// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Data access abstraction for mint transactions stored in the ledger.
//!
//! This store maintains two LMDB databases:
//! 1) A mapping of block index -> list of mint transactions included in the
//! block.    This is used to provide the mint_txs inside BlockContents.
//! 2) A mapping of hash -> MintTx. This is used to prevent replay attacks.

use crate::{key_bytes_to_u64, u64_to_key_bytes, Error, MintConfigStore};
use lmdb::{Database, DatabaseFlags, Environment, RwTransaction, Transaction, WriteFlags};
use mc_blockchain_types::BlockIndex;
use mc_transaction_core::mint::MintTx;
use mc_util_serial::{decode, encode, Message};

// LMDB Database names.
pub const MINT_TXS_BY_BLOCK_DB_NAME: &str = "mint_tx_store:set_txs_by_block";
pub const BLOCK_INDEX_BY_MINT_TX_NONCE_AND_TOKEN_ID_DB_NAME: &str =
    "mint_tx_store:block_index_by_mint_tx_nonce_and_token_id";

/// A list of mint-txs that can be prost-encoded. This is needed since that's
/// the only way to encode a Vec<MintTx>.
#[derive(Clone, Message)]
pub struct MintTxList {
    #[prost(message, repeated, tag = "1")]
    pub mint_txs: Vec<MintTx>,
}

#[derive(Clone)]
pub struct MintTxStore {
    /// MintTxs by block.
    mint_txs_by_block: Database,

    /// block index by MintTx nonce.
    block_index_by_mint_tx_nonce_and_token_id: Database,
}

impl MintTxStore {
    /// Opens an existing MintTxStore.
    pub fn new(env: &Environment) -> Result<Self, Error> {
        Ok(MintTxStore {
            mint_txs_by_block: env.open_db(Some(MINT_TXS_BY_BLOCK_DB_NAME))?,
            block_index_by_mint_tx_nonce_and_token_id: env
                .open_db(Some(BLOCK_INDEX_BY_MINT_TX_NONCE_AND_TOKEN_ID_DB_NAME))?,
        })
    }

    /// Creates a fresh MintTxStore.
    pub fn create(env: &Environment) -> Result<(), Error> {
        env.create_db(Some(MINT_TXS_BY_BLOCK_DB_NAME), DatabaseFlags::empty())?;
        env.create_db(
            Some(BLOCK_INDEX_BY_MINT_TX_NONCE_AND_TOKEN_ID_DB_NAME),
            DatabaseFlags::empty(),
        )?;
        Ok(())
    }

    /// Get mint txs in a given block.
    pub fn get_mint_txs_by_block_index(
        &self,
        block_index: u64,
        db_transaction: &impl Transaction,
    ) -> Result<Vec<MintTx>, Error> {
        let mint_txs: MintTxList =
            decode(db_transaction.get(self.mint_txs_by_block, &u64_to_key_bytes(block_index))?)?;
        Ok(mint_txs.mint_txs)
    }

    /// Write mint txs in a given block.
    pub fn write_mint_txs(
        &self,
        block_index: u64,
        mint_txs: &[MintTx],
        mint_config_store: &MintConfigStore,
        db_transaction: &mut RwTransaction,
    ) -> Result<(), Error> {
        let block_index_bytes = u64_to_key_bytes(block_index);

        // Store the list of MintTxs.
        let mint_tx_list = MintTxList {
            mint_txs: mint_txs.to_vec(),
        };

        db_transaction.put(
            self.mint_txs_by_block,
            &block_index_bytes,
            &encode(&mint_tx_list),
            WriteFlags::NO_OVERWRITE, // We should not be updating existing blocks
        )?;

        // For each mint transaction, we need to locate the matching mint configuration
        // and update the total minted count. We also need to ensure the nonce is
        // unique.
        for mint_tx in mint_txs {
            // Update total minted.
            let active_mint_config =
                mint_config_store.get_active_mint_config_for_mint_tx(mint_tx, db_transaction)?;

            let new_total_minted = active_mint_config
                .total_minted
                .checked_add(mint_tx.prefix.amount)
                .ok_or(Error::NotFound)?;

            mint_config_store.update_total_minted(
                &active_mint_config.mint_config,
                new_total_minted,
                db_transaction,
            )?;
            let mut combined_nonce_and_token_id = mint_tx.prefix.nonce.clone();
            combined_nonce_and_token_id
                .extend_from_slice(&u64_to_key_bytes(mint_tx.prefix.token_id));

            // Ensure nonce uniqueness
            db_transaction.put(
                self.block_index_by_mint_tx_nonce_and_token_id,
                &combined_nonce_and_token_id,
                &block_index_bytes,
                // do not overwrite a nonce that was already used
                WriteFlags::NO_OVERWRITE,
            )?;
        }

        Ok(())
    }

    pub fn check_mint_tx_nonce(
        &self,
        token_id: u64,
        nonce: &[u8],
        db_transaction: &impl Transaction,
    ) -> Result<Option<BlockIndex>, Error> {
        let combined_nonce_and_token_id = [nonce, &u64_to_key_bytes(token_id)].concat();
        match db_transaction.get(
            self.block_index_by_mint_tx_nonce_and_token_id,
            &combined_nonce_and_token_id,
        ) {
            Ok(db_bytes) => Ok(Some(key_bytes_to_u64(db_bytes))),
            Err(lmdb::Error::NotFound) => Ok(None),
            Err(e) => Err(Error::Lmdb(e)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{mint_config_store::ActiveMintConfig, tx_out_store::tx_out_store_tests::get_env};
    use mc_crypto_keys::Ed25519Pair;
    use mc_transaction_core::TokenId;
    use mc_transaction_core_test_utils::{
        create_mint_config_tx_and_signers, create_mint_tx,
        mint_config_tx_to_validated as to_validated,
    };
    use mc_util_from_random::FromRandom;
    use rand::{rngs::StdRng, SeedableRng};
    use std::cmp::max;

    pub fn init_test_stores() -> (MintConfigStore, MintTxStore, Environment) {
        let env = get_env();
        MintConfigStore::create(&env).unwrap();
        MintTxStore::create(&env).unwrap();
        let mint_config_store = MintConfigStore::new(&env).unwrap();
        let mint_tx_store = MintTxStore::new(&env).unwrap();
        (mint_config_store, mint_tx_store, env)
    }

    #[test]
    fn write_mint_txs_updates_total_minted() {
        let (mint_config_store, mint_tx_store, env) = init_test_stores();
        let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);
        let token_id1 = TokenId::from(1);
        let token_id2 = TokenId::from(2);

        // Generate and store a mint configurations.
        let (mint_config_tx1, signers1) = create_mint_config_tx_and_signers(token_id1, &mut rng);

        let (mint_config_tx2, signers2) = create_mint_config_tx_and_signers(token_id2, &mut rng);
        let mut db_txn = env.begin_rw_txn().unwrap();
        mint_config_store
            .write_validated_mint_config_txs(
                0,
                &[
                    to_validated(&mint_config_tx1),
                    to_validated(&mint_config_tx2),
                ],
                &mut db_txn,
            )
            .unwrap();
        db_txn.commit().unwrap();

        // Generate a mint tx that mints 1 token.
        let mint_tx1 = create_mint_tx(token_id1, &signers1, 1, &mut rng);
        let mut db_txn = env.begin_rw_txn().unwrap();
        mint_tx_store
            .write_mint_txs(0, &[mint_tx1], &mint_config_store, &mut db_txn)
            .unwrap();
        db_txn.commit().unwrap();

        // Get the configurations and ensure the total minted is updated.
        let db_txn = env.begin_ro_txn().unwrap();
        let active_mint_configs = mint_config_store
            .get_active_mint_configs(token_id1, &db_txn)
            .unwrap()
            .unwrap();
        assert_eq!(
            active_mint_configs.configs,
            vec![
                ActiveMintConfig {
                    mint_config: mint_config_tx1.prefix.configs[0].clone(),
                    total_minted: 1,
                },
                ActiveMintConfig {
                    mint_config: mint_config_tx1.prefix.configs[1].clone(),
                    total_minted: 0,
                },
                ActiveMintConfig {
                    mint_config: mint_config_tx1.prefix.configs[2].clone(),
                    total_minted: 0,
                },
            ]
        );
        drop(db_txn);

        // Generate a mint tx that mints 2 tokens.
        let mint_tx2 = create_mint_tx(token_id1, &signers1, 2, &mut rng);
        let mut db_txn = env.begin_rw_txn().unwrap();
        mint_tx_store
            .write_mint_txs(1, &[mint_tx2], &mint_config_store, &mut db_txn)
            .unwrap();
        db_txn.commit().unwrap();

        // Get the configurations and ensure the total minted is updated.
        let db_txn = env.begin_ro_txn().unwrap();
        let active_mint_configs = mint_config_store
            .get_active_mint_configs(token_id1, &db_txn)
            .unwrap()
            .unwrap();
        assert_eq!(
            active_mint_configs.configs,
            vec![
                ActiveMintConfig {
                    mint_config: mint_config_tx1.prefix.configs[0].clone(),
                    total_minted: 3,
                },
                ActiveMintConfig {
                    mint_config: mint_config_tx1.prefix.configs[1].clone(),
                    total_minted: 0,
                },
                ActiveMintConfig {
                    mint_config: mint_config_tx1.prefix.configs[2].clone(),
                    total_minted: 0,
                },
            ]
        );
        drop(db_txn);

        // Mint using the 2nd configuration of the 1st token
        let mint_tx3 = create_mint_tx(
            token_id1,
            &[Ed25519Pair::from(signers1[1].private_key())],
            5,
            &mut rng,
        );
        let mut db_txn = env.begin_rw_txn().unwrap();
        mint_tx_store
            .write_mint_txs(2, &[mint_tx3], &mint_config_store, &mut db_txn)
            .unwrap();
        db_txn.commit().unwrap();

        // Get the configurations and ensure the total minted is updated.
        let db_txn = env.begin_ro_txn().unwrap();
        let active_mint_configs = mint_config_store
            .get_active_mint_configs(token_id1, &db_txn)
            .unwrap()
            .unwrap();
        assert_eq!(
            active_mint_configs.configs,
            vec![
                ActiveMintConfig {
                    mint_config: mint_config_tx1.prefix.configs[0].clone(),
                    total_minted: 3,
                },
                ActiveMintConfig {
                    mint_config: mint_config_tx1.prefix.configs[1].clone(),
                    total_minted: 5,
                },
                ActiveMintConfig {
                    mint_config: mint_config_tx1.prefix.configs[2].clone(),
                    total_minted: 0,
                },
            ]
        );

        // Try with the 2nd token - initially nothing has been minted.
        let active_mint_configs = mint_config_store
            .get_active_mint_configs(token_id2, &db_txn)
            .unwrap()
            .unwrap();
        assert_eq!(
            active_mint_configs.configs,
            vec![
                ActiveMintConfig {
                    mint_config: mint_config_tx2.prefix.configs[0].clone(),
                    total_minted: 0,
                },
                ActiveMintConfig {
                    mint_config: mint_config_tx2.prefix.configs[1].clone(),
                    total_minted: 0,
                },
                ActiveMintConfig {
                    mint_config: mint_config_tx2.prefix.configs[2].clone(),
                    total_minted: 0,
                },
            ]
        );
        drop(db_txn);

        // Mint using the 2nd configuration of the 2nd token
        let mint_tx4 = create_mint_tx(
            token_id2,
            &[Ed25519Pair::from(signers2[1].private_key())],
            15,
            &mut rng,
        );
        let mut db_txn = env.begin_rw_txn().unwrap();
        mint_tx_store
            .write_mint_txs(3, &[mint_tx4], &mint_config_store, &mut db_txn)
            .unwrap();
        db_txn.commit().unwrap();

        // Get the configurations and ensure the total minted is updated.
        let db_txn = env.begin_ro_txn().unwrap();
        let active_mint_configs = mint_config_store
            .get_active_mint_configs(token_id1, &db_txn)
            .unwrap()
            .unwrap();
        assert_eq!(
            active_mint_configs.configs,
            vec![
                ActiveMintConfig {
                    mint_config: mint_config_tx1.prefix.configs[0].clone(),
                    total_minted: 3,
                },
                ActiveMintConfig {
                    mint_config: mint_config_tx1.prefix.configs[1].clone(),
                    total_minted: 5,
                },
                ActiveMintConfig {
                    mint_config: mint_config_tx1.prefix.configs[2].clone(),
                    total_minted: 0,
                },
            ]
        );

        let active_mint_configs = mint_config_store
            .get_active_mint_configs(token_id2, &db_txn)
            .unwrap()
            .unwrap();
        assert_eq!(
            active_mint_configs.configs,
            vec![
                ActiveMintConfig {
                    mint_config: mint_config_tx2.prefix.configs[0].clone(),
                    total_minted: 0,
                },
                ActiveMintConfig {
                    mint_config: mint_config_tx2.prefix.configs[1].clone(),
                    total_minted: 15,
                },
                ActiveMintConfig {
                    mint_config: mint_config_tx2.prefix.configs[2].clone(),
                    total_minted: 0,
                },
            ]
        );
    }

    #[test]
    fn write_mint_txs_cannot_overwrite_block() {
        let (mint_config_store, mint_tx_store, env) = init_test_stores();
        let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);
        let token_id1 = TokenId::from(1);

        // Generate and store a mint configurations.
        let (mint_config_tx1, signers1) = create_mint_config_tx_and_signers(token_id1, &mut rng);

        let mut db_txn = env.begin_rw_txn().unwrap();
        mint_config_store
            .write_validated_mint_config_txs(0, &[to_validated(&mint_config_tx1)], &mut db_txn)
            .unwrap();
        db_txn.commit().unwrap();

        // Generate a mint tx that mints 1 token on block 0
        let mint_tx1 = create_mint_tx(token_id1, &signers1, 1, &mut rng);
        let mut db_txn = env.begin_rw_txn().unwrap();
        mint_tx_store
            .write_mint_txs(0, &[mint_tx1], &mint_config_store, &mut db_txn)
            .unwrap();
        db_txn.commit().unwrap();

        // Trying again on block 0 should fail.
        let mint_tx2 = create_mint_tx(token_id1, &signers1, 1, &mut rng);
        let mut db_txn = env.begin_rw_txn().unwrap();
        assert_eq!(
            mint_tx_store.write_mint_txs(0, &[mint_tx2.clone()], &mint_config_store, &mut db_txn),
            Err(Error::Lmdb(lmdb::Error::KeyExist))
        );
        drop(db_txn);

        // But will succeed on block 1.
        let mut db_txn = env.begin_rw_txn().unwrap();
        mint_tx_store
            .write_mint_txs(1, &[mint_tx2], &mint_config_store, &mut db_txn)
            .unwrap();
        db_txn.commit().unwrap();
    }

    #[test]
    fn write_mint_txs_duplicate_nonce() {
        let (mint_config_store, mint_tx_store, env) = init_test_stores();
        let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);
        let token_id1 = TokenId::from(1);
        let token_id2 = TokenId::from(2);

        // Generate and store a mint configurations.
        let (mint_config_tx1, signers1) = create_mint_config_tx_and_signers(token_id1, &mut rng);
        let (mint_config_tx2, signers2) = create_mint_config_tx_and_signers(token_id2, &mut rng);

        let mut db_txn = env.begin_rw_txn().unwrap();
        mint_config_store
            .write_validated_mint_config_txs(
                0,
                &[
                    to_validated(&mint_config_tx1),
                    to_validated(&mint_config_tx2),
                ],
                &mut db_txn,
            )
            .unwrap();
        db_txn.commit().unwrap();

        // Generate a mint tx that mints 1 token on block 0
        rng = SeedableRng::from_seed([1u8; 32]);
        let mint_tx1 = create_mint_tx(token_id1, &signers1, 1, &mut rng);

        let mut db_txn = env.begin_rw_txn().unwrap();
        mint_tx_store
            .write_mint_txs(0, &[mint_tx1.clone()], &mint_config_store, &mut db_txn)
            .unwrap();
        db_txn.commit().unwrap();

        // Trying again on block 0 should fail.
        let mint_tx2 = create_mint_tx(token_id1, &signers1, 1, &mut rng);
        let mut db_txn = env.begin_rw_txn().unwrap();
        assert_eq!(
            mint_tx_store.write_mint_txs(0, &[mint_tx2.clone()], &mint_config_store, &mut db_txn),
            Err(Error::Lmdb(lmdb::Error::KeyExist))
        );
        drop(db_txn);

        // But will succeed on block 1.
        let mut db_txn = env.begin_rw_txn().unwrap();
        mint_tx_store
            .write_mint_txs(1, &[mint_tx2], &mint_config_store, &mut db_txn)
            .unwrap();
        db_txn.commit().unwrap();

        // Trying with the same nonce on the same token should fail.
        let mut db_txn = env.begin_rw_txn().unwrap();
        assert_eq!(
            mint_tx_store.write_mint_txs(2, &[mint_tx1], &mint_config_store, &mut db_txn),
            Err(Error::Lmdb(lmdb::Error::KeyExist))
        );
        drop(db_txn);

        // Generate similar tx as tx1 that have the same nonces for token2.
        rng = SeedableRng::from_seed([1u8; 32]);
        let mint_tx1_tkn2 = create_mint_tx(token_id2, &signers2, 1, &mut rng);

        //Trying with the same nonce on a different token should succeed.
        let mut db_txn = env.begin_rw_txn().unwrap();
        mint_tx_store
            .write_mint_txs(2, &[mint_tx1_tkn2], &mint_config_store, &mut db_txn)
            .unwrap();
        db_txn.commit().unwrap();
    }
    #[test]
    fn write_mint_txs_works_when_some_signers_are_unknown() {
        let (mint_config_store, mint_tx_store, env) = init_test_stores();
        let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);
        let token_id1 = TokenId::from(1);

        // Generate and store a mint configurations.
        let (mint_config_tx1, signers1) = create_mint_config_tx_and_signers(token_id1, &mut rng);

        let mut db_txn = env.begin_rw_txn().unwrap();
        mint_config_store
            .write_validated_mint_config_txs(0, &[to_validated(&mint_config_tx1)], &mut db_txn)
            .unwrap();
        db_txn.commit().unwrap();

        // Generate a mint tx that mints 1 token on block 0 with unknown signers.
        let mint_tx1 = create_mint_tx(
            token_id1,
            &[
                Ed25519Pair::from_random(&mut rng),
                Ed25519Pair::from_random(&mut rng),
                Ed25519Pair::from(signers1[1].private_key()),
            ],
            12,
            &mut rng,
        );
        let mut db_txn = env.begin_rw_txn().unwrap();
        mint_tx_store
            .write_mint_txs(0, &[mint_tx1], &mint_config_store, &mut db_txn)
            .unwrap();
        db_txn.commit().unwrap();

        let db_txn = env.begin_ro_txn().unwrap();
        let active_mint_configs = mint_config_store
            .get_active_mint_configs(token_id1, &db_txn)
            .unwrap()
            .unwrap();
        assert_eq!(
            active_mint_configs.configs,
            vec![
                ActiveMintConfig {
                    mint_config: mint_config_tx1.prefix.configs[0].clone(),
                    total_minted: 0,
                },
                ActiveMintConfig {
                    mint_config: mint_config_tx1.prefix.configs[1].clone(),
                    total_minted: 12,
                },
                ActiveMintConfig {
                    mint_config: mint_config_tx1.prefix.configs[2].clone(),
                    total_minted: 0,
                },
            ]
        );
    }

    #[test]
    fn write_mint_txs_fail_when_signer_is_unknown() {
        let (mint_config_store, mint_tx_store, env) = init_test_stores();
        let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);
        let token_id1 = TokenId::from(1);

        // Generate and store a mint configurations.
        let (mint_config_tx1, _signers1) = create_mint_config_tx_and_signers(token_id1, &mut rng);

        let mut db_txn = env.begin_rw_txn().unwrap();
        mint_config_store
            .write_validated_mint_config_txs(0, &[to_validated(&mint_config_tx1)], &mut db_txn)
            .unwrap();
        db_txn.commit().unwrap();

        // Generate a mint tx that mints 1 token on block 0 with unknown signers.
        let mint_tx1 = create_mint_tx(
            token_id1,
            &[
                Ed25519Pair::from_random(&mut rng),
                Ed25519Pair::from_random(&mut rng),
            ],
            1,
            &mut rng,
        );
        let mut db_txn = env.begin_rw_txn().unwrap();
        assert_eq!(
            mint_tx_store.write_mint_txs(0, &[mint_tx1], &mint_config_store, &mut db_txn),
            Err(Error::NotFound)
        );
    }

    #[test]
    fn write_mint_txs_fail_when_signature_is_invalid() {
        let (mint_config_store, mint_tx_store, env) = init_test_stores();
        let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);
        let token_id1 = TokenId::from(1);

        // Generate and store a mint configurations.
        let (mint_config_tx1, signers1) = create_mint_config_tx_and_signers(token_id1, &mut rng);

        let mut db_txn = env.begin_rw_txn().unwrap();
        mint_config_store
            .write_validated_mint_config_txs(0, &[to_validated(&mint_config_tx1)], &mut db_txn)
            .unwrap();
        db_txn.commit().unwrap();

        // Generate a mint tx that mints 1 token on block 0 but corrupt the signature by
        // altering the amount.
        let mut mint_tx1 = create_mint_tx(token_id1, &signers1, 1, &mut rng);
        mint_tx1.prefix.amount += 1;
        let mut db_txn = env.begin_rw_txn().unwrap();
        assert_eq!(
            mint_tx_store.write_mint_txs(0, &[mint_tx1], &mint_config_store, &mut db_txn),
            Err(Error::NotFound)
        );
    }

    #[test]
    fn write_mint_txs_fail_when_mint_limit_exceeded() {
        let (mint_config_store, mint_tx_store, env) = init_test_stores();
        let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);
        let token_id1 = TokenId::from(1);

        // Generate and store a mint configurations.
        let (mint_config_tx1, signers1) = create_mint_config_tx_and_signers(token_id1, &mut rng);

        let mut db_txn = env.begin_rw_txn().unwrap();
        mint_config_store
            .write_validated_mint_config_txs(0, &[to_validated(&mint_config_tx1)], &mut db_txn)
            .unwrap();
        db_txn.commit().unwrap();

        // Generate a mint tx that immediately exceeds the mint limit of both
        // configurations.
        let mint_tx1 = create_mint_tx(
            token_id1,
            &signers1[..2],
            max(
                mint_config_tx1.prefix.configs[0].mint_limit,
                mint_config_tx1.prefix.configs[1].mint_limit,
            ) + 1,
            &mut rng,
        );
        let mut db_txn = env.begin_rw_txn().unwrap();

        // The mint limit we get in the error will be dependent on the order of the mint
        // configurations, so we should accept both possibitilies.
        match mint_tx_store.write_mint_txs(0, &[mint_tx1.clone()], &mint_config_store, &mut db_txn)
        {
            Ok(()) => panic!("Unexpected success"),
            Err(Error::MintLimitExceeded(mint_amount, minted_so_far, mint_limit)) => {
                assert_eq!(mint_amount, mint_tx1.prefix.amount);
                assert_eq!(minted_so_far, 0);
                assert!(&[
                    mint_config_tx1.prefix.configs[0].mint_limit,
                    mint_config_tx1.prefix.configs[1].mint_limit,
                ]
                .contains(&mint_limit));
            }
            Err(err) => panic!("Unexpected error {}", err),
        }
    }

    #[test]
    fn check_mint_tx_nonce_works() {
        let (mint_config_store, mint_tx_store, env) = init_test_stores();
        let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);
        let token_id1 = TokenId::from(1);

        // Generate and store a mint configurations.
        let (mint_config_tx1, signers1) = create_mint_config_tx_and_signers(token_id1, &mut rng);

        let mut db_txn = env.begin_rw_txn().unwrap();
        mint_config_store
            .write_validated_mint_config_txs(0, &[to_validated(&mint_config_tx1)], &mut db_txn)
            .unwrap();
        db_txn.commit().unwrap();

        // Generate some test transactions
        let mint_tx1 = create_mint_tx(token_id1, &signers1, 1, &mut rng);
        let mint_tx2 = create_mint_tx(token_id1, &signers1, 1, &mut rng);
        let mint_tx3 = create_mint_tx(token_id1, &signers1, 1, &mut rng);

        let mut db_txn = env.begin_rw_txn().unwrap();
        mint_tx_store
            .write_mint_txs(
                0,
                &[mint_tx1.clone(), mint_tx2.clone()],
                &mint_config_store,
                &mut db_txn,
            )
            .unwrap();
        db_txn.commit().unwrap();

        let db_txn = env.begin_ro_txn().unwrap();
        assert_eq!(
            mint_tx_store.check_mint_tx_nonce(*token_id1, &mint_tx1.prefix.nonce, &db_txn),
            Ok(Some(0))
        );
        assert_eq!(
            mint_tx_store.check_mint_tx_nonce(*token_id1, &mint_tx2.prefix.nonce, &db_txn),
            Ok(Some(0))
        );
        assert_eq!(
            mint_tx_store.check_mint_tx_nonce(*token_id1, &mint_tx3.prefix.nonce, &db_txn),
            Ok(None)
        );
        assert_eq!(
            mint_tx_store.check_mint_tx_nonce(
                *token_id1,
                &mint_tx1.prefix.nonce[..mint_tx1.prefix.nonce.len() - 2],
                &db_txn
            ),
            Ok(None)
        );
        assert_eq!(
            mint_tx_store.check_mint_tx_nonce(*token_id1, &[1, 2, 3], &db_txn),
            Ok(None)
        );
        drop(db_txn);

        let mut db_txn = env.begin_rw_txn().unwrap();
        mint_tx_store
            .write_mint_txs(1, &[mint_tx3.clone()], &mint_config_store, &mut db_txn)
            .unwrap();
        db_txn.commit().unwrap();

        let db_txn = env.begin_ro_txn().unwrap();
        assert_eq!(
            mint_tx_store.check_mint_tx_nonce(*token_id1, &mint_tx1.prefix.nonce, &db_txn),
            Ok(Some(0))
        );
        assert_eq!(
            mint_tx_store.check_mint_tx_nonce(*token_id1, &mint_tx2.prefix.nonce, &db_txn),
            Ok(Some(0))
        );
        assert_eq!(
            mint_tx_store.check_mint_tx_nonce(*token_id1, &mint_tx3.prefix.nonce, &db_txn),
            Ok(Some(1))
        );
    }
}
