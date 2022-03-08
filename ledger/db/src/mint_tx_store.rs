// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Data access abstraction for mint transactions stored in the ledger.
//!
//! This store maintains two LMDB databases:
//! 1) A mapping of block index -> list of mint transactions included in the
//! block.    This is used to provide the mint_txs inside BlockContents.
//! 2) A mapping of hash -> MintTx. This is used to prevent replay attacks.

use crate::{u64_to_key_bytes, Error, MintConfigStore};
use lmdb::{Database, DatabaseFlags, Environment, RwTransaction, Transaction, WriteFlags};
use mc_transaction_core::mint::MintTx;
use mc_util_serial::{decode, encode, Message};

// LMDB Database names.
pub const MINT_TXS_BY_BLOCK_DB_NAME: &str = "mint_tx_store:set_txs_by_block";
pub const MINT_TX_BY_NONCE_DB_NAME: &str = "mint_tx_store:mint_tx_by_nonce";

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

    /// MintTx by nonce.
    mint_tx_by_nonce: Database,
}

impl MintTxStore {
    /// Opens an existing MintTxStore.
    pub fn new(env: &Environment) -> Result<Self, Error> {
        Ok(MintTxStore {
            mint_txs_by_block: env.open_db(Some(MINT_TXS_BY_BLOCK_DB_NAME))?,
            mint_tx_by_nonce: env.open_db(Some(MINT_TX_BY_NONCE_DB_NAME))?,
        })
    }

    /// Creates a fresh MintTxStore.
    pub fn create(env: &Environment) -> Result<(), Error> {
        env.create_db(Some(MINT_TXS_BY_BLOCK_DB_NAME), DatabaseFlags::empty())?;
        env.create_db(Some(MINT_TX_BY_NONCE_DB_NAME), DatabaseFlags::empty())?;
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

    /// Returns true if the Ledger contains the given mint tx nonce
    pub fn contains_mint_tx_nonce(
        &self,
        nonce: &[u8],
        db_transaction: &impl Transaction,
    ) -> Result<bool, Error> {
        match db_transaction.get(self.mint_tx_by_nonce, &nonce) {
            Ok(_db_bytes) => Ok(true),
            Err(lmdb::Error::NotFound) => Ok(false),
            Err(e) => Err(Error::Lmdb(e)),
        }
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

            let new_total_minted = active_mint_config.total_minted.checked_add(mint_tx.prefix.amount).expect("shouldn't have failed because get_active_mint_config_for_mint_tx guards against this");

            mint_config_store.update_total_minted(
                &active_mint_config.mint_config,
                new_total_minted,
                db_transaction,
            )?;

            // Ensure nonce uniqueness
            db_transaction.put(
                self.mint_tx_by_nonce,
                &mint_tx.prefix.nonce,
                &encode(mint_tx),
                WriteFlags::NO_OVERWRITE, /* this ensures we do not overwrite a nonce that was
                                           * already used */
            )?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        mint_config_store::{
            tests::{generate_test_mint_config_tx_and_signers, generate_test_mint_tx},
            ActiveMintConfig,
        },
        tx_out_store::tx_out_store_tests::get_env,
    };
    use mc_crypto_keys::Ed25519Pair;
    use mc_transaction_core::TokenId;
    use rand::{rngs::StdRng, SeedableRng};

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
        let (set_mint_config_tx1, signers1) =
            generate_test_mint_config_tx_and_signers(token_id1, &mut rng);

        let (set_mint_config_tx2, signers2) =
            generate_test_mint_config_tx_and_signers(token_id2, &mut rng);
        let mut db_txn = env.begin_rw_txn().unwrap();
        mint_config_store
            .write_set_mint_config_txs(
                0,
                &[set_mint_config_tx1.clone(), set_mint_config_tx2.clone()],
                &mut db_txn,
            )
            .unwrap();
        db_txn.commit().unwrap();

        // Generate a mint tx that mints 1 token.
        let mint_tx1 = generate_test_mint_tx(token_id1, &signers1, 1, &mut rng);
        let mut db_txn = env.begin_rw_txn().unwrap();
        mint_tx_store
            .write_mint_txs(0, &[mint_tx1], &mint_config_store, &mut db_txn)
            .unwrap();
        db_txn.commit().unwrap();

        // Get the configurations and ensure the total minted is updated.
        let db_txn = env.begin_ro_txn().unwrap();
        let active_mint_configs = mint_config_store
            .get_active_mint_configs(token_id1, &db_txn)
            .unwrap();
        assert_eq!(
            active_mint_configs,
            vec![
                ActiveMintConfig {
                    mint_config: set_mint_config_tx1.prefix.configs[0].clone(),
                    total_minted: 1,
                },
                ActiveMintConfig {
                    mint_config: set_mint_config_tx1.prefix.configs[1].clone(),
                    total_minted: 0,
                }
            ]
        );
        drop(db_txn);

        // Generate a mint tx that mints 2 tokens.
        let mint_tx2 = generate_test_mint_tx(token_id1, &signers1, 2, &mut rng);
        let mut db_txn = env.begin_rw_txn().unwrap();
        mint_tx_store
            .write_mint_txs(1, &[mint_tx2], &mint_config_store, &mut db_txn)
            .unwrap();
        db_txn.commit().unwrap();

        // Get the configurations and ensure the total minted is updated.
        let db_txn = env.begin_ro_txn().unwrap();
        let active_mint_configs = mint_config_store
            .get_active_mint_configs(token_id1, &db_txn)
            .unwrap();
        assert_eq!(
            active_mint_configs,
            vec![
                ActiveMintConfig {
                    mint_config: set_mint_config_tx1.prefix.configs[0].clone(),
                    total_minted: 3,
                },
                ActiveMintConfig {
                    mint_config: set_mint_config_tx1.prefix.configs[1].clone(),
                    total_minted: 0,
                }
            ]
        );
        drop(db_txn);

        // Mint using the 2nd configuration of the 1st token
        let mint_tx3 = generate_test_mint_tx(
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
            .unwrap();
        assert_eq!(
            active_mint_configs,
            vec![
                ActiveMintConfig {
                    mint_config: set_mint_config_tx1.prefix.configs[0].clone(),
                    total_minted: 3,
                },
                ActiveMintConfig {
                    mint_config: set_mint_config_tx1.prefix.configs[1].clone(),
                    total_minted: 5,
                }
            ]
        );

        // Try with the 2nd token - initially nothing has been minted.
        let active_mint_configs = mint_config_store
            .get_active_mint_configs(token_id2, &db_txn)
            .unwrap();
        assert_eq!(
            active_mint_configs,
            vec![
                ActiveMintConfig {
                    mint_config: set_mint_config_tx2.prefix.configs[0].clone(),
                    total_minted: 0,
                },
                ActiveMintConfig {
                    mint_config: set_mint_config_tx2.prefix.configs[1].clone(),
                    total_minted: 0,
                }
            ]
        );
        drop(db_txn);

        // Mint using the 2nd configuration of the 2nd token
        let mint_tx4 = generate_test_mint_tx(
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
            .unwrap();
        assert_eq!(
            active_mint_configs,
            vec![
                ActiveMintConfig {
                    mint_config: set_mint_config_tx1.prefix.configs[0].clone(),
                    total_minted: 3,
                },
                ActiveMintConfig {
                    mint_config: set_mint_config_tx1.prefix.configs[1].clone(),
                    total_minted: 5,
                }
            ]
        );

        let active_mint_configs = mint_config_store
            .get_active_mint_configs(token_id2, &db_txn)
            .unwrap();
        assert_eq!(
            active_mint_configs,
            vec![
                ActiveMintConfig {
                    mint_config: set_mint_config_tx2.prefix.configs[0].clone(),
                    total_minted: 0,
                },
                ActiveMintConfig {
                    mint_config: set_mint_config_tx2.prefix.configs[1].clone(),
                    total_minted: 15,
                }
            ]
        );
    }

    // TODO: test writing same block index twice, unknown signer, exceeding mint
    // capacity.
}
