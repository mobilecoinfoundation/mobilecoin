// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Data access abstraction for minting configuration stored in the ledger.
//!
//! This store maintains two LMDB databases:
//! 1) A mapping of token id -> currently active mint configurations.
//!    This database is used for two things:
//!      1) It allows transaction validation code to figure out if a mint
//! transaction is allowed to mint.
//!      2) It enables keeping track of how much was minted using a given
//! configuration. This is used to enforce the per-configuration mint limit.
//! 2) A mapping of nonce -> SetMintConfigTx object containing the nonce. This
//!    is mainly used to prevent replay attacks.

use crate::{u32_to_key_bytes, Error};
use lmdb::{Database, DatabaseFlags, Environment, RwTransaction, Transaction, WriteFlags};
use mc_transaction_core::{
    mint::{MintConfig, MintTx, SetMintConfigTx},
    TokenId,
};
use mc_util_serial::{decode, encode, Message};

// LMDB Database names.
pub const ACTIVE_MINT_CONFIGS_BY_TOKEN_ID_DB_NAME: &str =
    "mint_config_store:active_mint_configs_by_token_id";
pub const SET_MINT_CONFIG_TX_BY_NONCE_DB_NAME: &str =
    "mint_config_store:set_mint_config_tx_by_nonce_db_name";

/// An active mint configuration for a single token.
#[derive(Clone, Eq, Message, PartialEq)]
pub struct ActiveMintConfig {
    /// The actual mint configuration.
    #[prost(message, required, tag = "1")]
    pub mint_config: MintConfig,

    /// How many tokens have been minted using this configuration.
    #[prost(uint64, tag = "2")]
    pub total_minted: u64,
}

/// A collection of active mint configurations.
/// This is needed for serializing/deserializing a Vec<ActiveMintConfig>.
#[derive(Clone, Eq, Message, PartialEq)]
struct ActiveMintConfigs {
    #[prost(message, repeated, tag = "1")]
    pub configs: Vec<ActiveMintConfig>,
}

impl From<&SetMintConfigTx> for ActiveMintConfigs {
    fn from(set_mint_config_tx: &SetMintConfigTx) -> Self {
        ActiveMintConfigs {
            configs: set_mint_config_tx
                .prefix
                .configs
                .iter()
                .map(|mint_config| ActiveMintConfig {
                    mint_config: mint_config.clone(),
                    total_minted: 0,
                })
                .collect(),
        }
    }
}

#[derive(Clone)]
pub struct MintConfigStore {
    /// token id -> Vec<ActiveMintConfig>
    active_mint_configs_by_token_id: Database,

    /// nonce -> SetMintConfigTx
    set_mint_config_tx_by_nonce: Database,
}

impl MintConfigStore {
    /// Opens an existing MintConfigStore.
    pub fn new(env: &Environment) -> Result<Self, Error> {
        Ok(MintConfigStore {
            active_mint_configs_by_token_id: env
                .open_db(Some(ACTIVE_MINT_CONFIGS_BY_TOKEN_ID_DB_NAME))?,
            set_mint_config_tx_by_nonce: env.open_db(Some(SET_MINT_CONFIG_TX_BY_NONCE_DB_NAME))?,
        })
    }

    /// Creates a fresh MintConfigStore.
    pub fn create(env: &Environment) -> Result<(), Error> {
        env.create_db(
            Some(ACTIVE_MINT_CONFIGS_BY_TOKEN_ID_DB_NAME),
            DatabaseFlags::empty(),
        )?;
        env.create_db(
            Some(SET_MINT_CONFIG_TX_BY_NONCE_DB_NAME),
            DatabaseFlags::empty(),
        )?;
        Ok(())
    }

    /// Set mint configurations for a given token.
    pub fn set_active_mint_configs(
        &self,
        set_mint_config_tx: &SetMintConfigTx,
        db_transaction: &mut RwTransaction,
    ) -> Result<(), Error> {
        // All mint configurations must have the same token id.
        if set_mint_config_tx
            .prefix
            .configs
            .iter()
            .any(|mint_config| mint_config.token_id != set_mint_config_tx.prefix.token_id)
        {
            return Err(Error::InvalidMintConfig(
                "All mint configurations must have the same token id".to_string(),
            ));
        }

        // MintConfigs -> ActiveMintConfigs
        let active_mint_configs = ActiveMintConfigs::from(set_mint_config_tx);

        // Store in database
        db_transaction.put(
            self.set_mint_config_tx_by_nonce,
            &set_mint_config_tx.prefix.nonce,
            &encode(set_mint_config_tx),
            WriteFlags::NO_OVERWRITE, /* this ensures we do not overwrite a nonce that was
                                       * already used */
        )?;

        db_transaction.put(
            self.active_mint_configs_by_token_id,
            &u32_to_key_bytes(set_mint_config_tx.prefix.token_id),
            &encode(&active_mint_configs),
            WriteFlags::empty(),
        )?;

        Ok(())
    }

    /// Get mint configurations for a given token.
    pub fn get_active_mint_configs(
        &self,
        token_id: TokenId,
        db_transaction: &impl Transaction,
    ) -> Result<Vec<ActiveMintConfig>, Error> {
        let token_id_bytes = u32_to_key_bytes(*token_id);
        match db_transaction.get(self.active_mint_configs_by_token_id, &token_id_bytes) {
            Ok(bytes) => {
                let active_mint_configs: ActiveMintConfigs = decode(bytes)?;
                Ok(active_mint_configs.configs)
            }
            Err(lmdb::Error::NotFound) => Ok(Vec::new()),
            Err(err) => Err(err.into()),
        }
    }

    // Attempt to get a MintConfig that is active and is capable of minting the
    // given amount of tokens.
    pub fn get_active_mint_config_for_mint_tx(
        &self,
        mint_tx: &MintTx,
        db_transaction: &impl Transaction,
    ) -> Result<ActiveMintConfig, Error> {
        let active_mint_configs =
            self.get_active_mint_configs(TokenId::from(mint_tx.prefix.token_id), db_transaction)?;
        let message = mint_tx.prefix.hash();

        // Our default error is NotFound, in case we are unable to find a mint config
        // that matches the mint tx. We might override it if we find one but the
        // amount will exceed the mint limit.
        let mut error = Error::NotFound;

        for active_mint_config in active_mint_configs {
            // See if this mint config has signed the mint tx.
            if !active_mint_config
                .mint_config
                .signer_set
                .verify(&message, &mint_tx.signature)
                .is_ok()
            {
                continue;
            }

            // This mint config has signed the mint tx. Is it allowed to mint the given
            // amount of tokens?
            if let Some(new_total_minted) = active_mint_config
                .total_minted
                .checked_add(mint_tx.prefix.amount)
            {
                if new_total_minted <= active_mint_config.mint_config.mint_limit {
                    return Ok(active_mint_config);
                } else {
                    error = Error::MintLimitExceeded(
                        new_total_minted,
                        active_mint_config.mint_config.mint_limit,
                    );
                }
            }
        }

        Err(error)
    }

    /// Update the total minted amount for a given MintConfig.
    pub fn update_total_minted(
        &self,
        mint_config: &MintConfig,
        amount: u64,
        db_transaction: &mut RwTransaction,
    ) -> Result<(), Error> {
        if amount > mint_config.mint_limit {
            return Err(Error::MintLimitExceeded(amount, mint_config.mint_limit));
        }

        // Get the active mint configs for the given token.
        let mut active_mint_configs =
            self.get_active_mint_configs(TokenId::from(mint_config.token_id), db_transaction)?;

        // Find the active mint config that matches the mint config we were given.
        let active_mint_config = active_mint_configs
            .iter_mut()
            .find(|active_mint_config| active_mint_config.mint_config == *mint_config)
            .ok_or_else(|| Error::InvalidMintConfig("Mint config not found".to_string()))?;

        // Total minted amount should never decrease.
        if amount < active_mint_config.total_minted {
            return Err(Error::TotalMintedAmountCannotDecrease(
                amount,
                active_mint_config.total_minted,
            ));
        }

        // Update the total minted amount.
        active_mint_config.total_minted = amount;

        // Write to db.
        db_transaction.put(
            self.active_mint_configs_by_token_id,
            &u32_to_key_bytes(mint_config.token_id),
            &encode(&ActiveMintConfigs {
                configs: active_mint_configs,
            }),
            WriteFlags::empty(),
        )?;

        Ok(())
    }

    /// Returns true of the Ledger contains the given set-mint-config-tx nonce.
    pub fn contains_set_mint_config_tx_nonce(
        &self,
        nonce: &[u8],
        db_transaction: &impl Transaction,
    ) -> Result<bool, Error> {
        match db_transaction.get(self.set_mint_config_tx_by_nonce, &nonce) {
            Ok(_db_bytes) => Ok(true),
            Err(lmdb::Error::NotFound) => Ok(false),
            Err(e) => Err(Error::Lmdb(e)),
        }
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::tx_out_store::tx_out_store_tests::get_env;
    use mc_crypto_keys::{Ed25519Pair, RistrettoPublic, Signer};
    use mc_crypto_multisig::{MultiSig, SignerSet};
    use mc_transaction_core::mint::{
        MintConfig, MintTxPrefix, SetMintConfigTx, SetMintConfigTxPrefix,
    };
    use mc_util_from_random::FromRandom;
    use rand::{rngs::StdRng, SeedableRng};
    use rand_core::{CryptoRng, RngCore};

    pub fn init_mint_config_store() -> (MintConfigStore, Environment) {
        let env = get_env();
        MintConfigStore::create(&env).unwrap();
        let mint_config_store = MintConfigStore::new(&env).unwrap();
        (mint_config_store, env)
    }

    pub fn generate_test_mint_config_tx_and_signers(
        token_id: TokenId,
        rng: &mut (impl RngCore + CryptoRng),
    ) -> (SetMintConfigTx, Vec<Ed25519Pair>) {
        let signer_1 = Ed25519Pair::from_random(rng);
        let signer_2 = Ed25519Pair::from_random(rng);
        let signer_3 = Ed25519Pair::from_random(rng);

        let mut nonce: Vec<u8> = vec![0u8; 32];
        rng.fill_bytes(&mut nonce);

        let prefix = SetMintConfigTxPrefix {
            token_id: *token_id,
            configs: vec![
                MintConfig {
                    token_id: *token_id,
                    signer_set: SignerSet::new(vec![signer_1.public_key()], 1),
                    mint_limit: rng.next_u64(),
                },
                MintConfig {
                    token_id: *token_id,
                    signer_set: SignerSet::new(
                        vec![signer_2.public_key(), signer_3.public_key()],
                        1,
                    ),
                    mint_limit: rng.next_u64(),
                },
            ],
            nonce,
            tombstone_block: rng.next_u64(),
        };

        let message = prefix.hash();
        let signature = MultiSig::new(vec![signer_1.try_sign(message.as_ref()).unwrap()]);

        (
            SetMintConfigTx { prefix, signature },
            vec![signer_1, signer_2, signer_3],
        )
    }

    pub fn generate_test_mint_config_tx(
        token_id: TokenId,
        rng: &mut (impl RngCore + CryptoRng),
    ) -> SetMintConfigTx {
        let (set_mint_config_tx, _signers) =
            generate_test_mint_config_tx_and_signers(token_id, rng);
        set_mint_config_tx
    }

    // Generate a random mint tx
    pub fn generate_test_mint_tx(
        token_id: TokenId,
        signers: &[Ed25519Pair],
        amount: u64,
        rng: &mut (impl RngCore + CryptoRng),
    ) -> MintTx {
        let mut nonce: Vec<u8> = vec![0u8; 32];
        rng.fill_bytes(&mut nonce);

        let prefix = MintTxPrefix {
            token_id: *token_id,
            amount,
            view_public_key: RistrettoPublic::from_random(rng),
            spend_public_key: RistrettoPublic::from_random(rng),
            nonce,
            tombstone_block: rng.next_u64(),
        };

        let message = prefix.hash();

        let signatures = signers
            .iter()
            .map(|signer| signer.try_sign(message.as_ref()).unwrap())
            .collect();
        let signature = MultiSig::new(signatures);

        MintTx { prefix, signature }
    }

    #[test]
    fn set_get_behaves_correctly() {
        let (mint_config_store, env) = init_mint_config_store();
        let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);

        let test_tx_1 = generate_test_mint_config_tx(TokenId::from(1), &mut rng);
        let test_tx_2 = generate_test_mint_config_tx(TokenId::from(2), &mut rng);

        // Should be able to set a valid mint configuration and then get it back.
        {
            let mut db_transaction = env.begin_rw_txn().unwrap();
            mint_config_store
                .set_active_mint_configs(&test_tx_1, &mut db_transaction)
                .unwrap();
            db_transaction.commit().unwrap();
        }

        {
            let db_transaction = env.begin_ro_txn().unwrap();
            let active_mint_configs = mint_config_store
                .get_active_mint_configs(TokenId::from(1), &db_transaction)
                .unwrap();
            assert_eq!(
                active_mint_configs,
                ActiveMintConfigs::from(&test_tx_1).configs
            );

            // Getting configuration for a different token id should return an empty vec.
            let active_mint_configs = mint_config_store
                .get_active_mint_configs(TokenId::from(2), &db_transaction)
                .unwrap();
            assert_eq!(active_mint_configs, vec![]);
        }

        // Set a minting configuration for the 2nd token and try again.
        {
            let mut db_transaction = env.begin_rw_txn().unwrap();
            mint_config_store
                .set_active_mint_configs(&test_tx_2, &mut db_transaction)
                .unwrap();
            db_transaction.commit().unwrap();
        }

        {
            let db_transaction = env.begin_ro_txn().unwrap();

            let active_mint_configs = mint_config_store
                .get_active_mint_configs(TokenId::from(1), &db_transaction)
                .unwrap();
            assert_eq!(
                active_mint_configs,
                ActiveMintConfigs::from(&test_tx_1).configs
            );

            let active_mint_configs = mint_config_store
                .get_active_mint_configs(TokenId::from(2), &db_transaction)
                .unwrap();
            assert_eq!(
                active_mint_configs,
                ActiveMintConfigs::from(&test_tx_2).configs
            );
        }
    }

    #[test]
    fn duplicate_nonce_not_allowed() {
        let (mint_config_store, env) = init_mint_config_store();
        let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);

        let test_tx_1 = generate_test_mint_config_tx(TokenId::from(1), &mut rng);
        let mut test_tx_2 = generate_test_mint_config_tx(TokenId::from(2), &mut rng);

        {
            let mut db_transaction = env.begin_rw_txn().unwrap();
            mint_config_store
                .set_active_mint_configs(&test_tx_1, &mut db_transaction)
                .unwrap();
            db_transaction.commit().unwrap();
        }

        {
            let mut db_transaction = env.begin_rw_txn().unwrap();
            assert_eq!(
                mint_config_store.set_active_mint_configs(&test_tx_1, &mut db_transaction),
                Err(Error::Lmdb(lmdb::Error::KeyExist))
            );
            db_transaction.commit().unwrap();
        }

        test_tx_2.prefix.nonce = test_tx_1.prefix.nonce.clone();
        {
            let mut db_transaction = env.begin_rw_txn().unwrap();
            assert_eq!(
                mint_config_store.set_active_mint_configs(&test_tx_1, &mut db_transaction),
                Err(Error::Lmdb(lmdb::Error::KeyExist))
            );
            db_transaction.commit().unwrap();
        }

        // Sanity - change the nonce, we should then succeed.
        test_tx_2.prefix.nonce[0] = !test_tx_2.prefix.nonce[0];
        {
            let mut db_transaction = env.begin_rw_txn().unwrap();
            mint_config_store
                .set_active_mint_configs(&test_tx_2, &mut db_transaction)
                .unwrap();
            db_transaction.commit().unwrap();
        }
    }

    #[test]
    fn set_replaces_configuration() {
        let (mint_config_store, env) = init_mint_config_store();
        let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);

        let test_tx_1 = generate_test_mint_config_tx(TokenId::from(1), &mut rng);
        let test_tx_2 = generate_test_mint_config_tx(TokenId::from(1), &mut rng);

        assert_ne!(test_tx_1, test_tx_2);

        {
            let mut db_transaction = env.begin_rw_txn().unwrap();
            mint_config_store
                .set_active_mint_configs(&test_tx_1, &mut db_transaction)
                .unwrap();
            db_transaction.commit().unwrap();
        }

        {
            let db_transaction = env.begin_ro_txn().unwrap();
            let active_mint_configs = mint_config_store
                .get_active_mint_configs(TokenId::from(1), &db_transaction)
                .unwrap();
            assert_eq!(
                active_mint_configs,
                ActiveMintConfigs::from(&test_tx_1).configs
            );
        }

        // Replace the previous configuration with a different one
        {
            let mut db_transaction = env.begin_rw_txn().unwrap();
            mint_config_store
                .set_active_mint_configs(&test_tx_2, &mut db_transaction)
                .unwrap();
            db_transaction.commit().unwrap();
        }

        {
            let db_transaction = env.begin_ro_txn().unwrap();
            let active_mint_configs = mint_config_store
                .get_active_mint_configs(TokenId::from(1), &db_transaction)
                .unwrap();
            assert_eq!(
                active_mint_configs,
                ActiveMintConfigs::from(&test_tx_2).configs
            );
        }
    }

    #[test]
    fn empty_configuration_accepted() {
        let (mint_config_store, env) = init_mint_config_store();
        let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);

        let test_tx_1 = generate_test_mint_config_tx(TokenId::from(1), &mut rng);
        let test_tx_2 = SetMintConfigTx {
            prefix: SetMintConfigTxPrefix {
                token_id: test_tx_1.prefix.token_id,
                configs: vec![],
                nonce: vec![5u8; 32],
                tombstone_block: 1234,
            },
            signature: Default::default(),
        };

        assert_ne!(test_tx_1, test_tx_2);

        {
            let mut db_transaction = env.begin_rw_txn().unwrap();
            mint_config_store
                .set_active_mint_configs(&test_tx_1, &mut db_transaction)
                .unwrap();
            db_transaction.commit().unwrap();
        }

        {
            let db_transaction = env.begin_ro_txn().unwrap();
            let active_mint_configs = mint_config_store
                .get_active_mint_configs(TokenId::from(1), &db_transaction)
                .unwrap();
            assert_eq!(
                active_mint_configs,
                ActiveMintConfigs::from(&test_tx_1).configs
            );
        }

        // Replace the previous configuration with an empty one
        {
            let mut db_transaction = env.begin_rw_txn().unwrap();
            mint_config_store
                .set_active_mint_configs(&test_tx_2, &mut db_transaction)
                .unwrap();
            db_transaction.commit().unwrap();
        }

        {
            let db_transaction = env.begin_ro_txn().unwrap();
            let active_mint_configs = mint_config_store
                .get_active_mint_configs(TokenId::from(1), &db_transaction)
                .unwrap();
            assert_eq!(
                active_mint_configs,
                ActiveMintConfigs::from(&test_tx_2).configs
            );
        }
    }

    #[test]
    fn update_total_minted_works() {
        let (mint_config_store, env) = init_mint_config_store();
        let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);

        let test_tx_1 = generate_test_mint_config_tx(TokenId::from(1), &mut rng);

        {
            let mut db_transaction = env.begin_rw_txn().unwrap();
            mint_config_store
                .set_active_mint_configs(&test_tx_1, &mut db_transaction)
                .unwrap();
            db_transaction.commit().unwrap();
        }

        // Initially, both mint configs are not minted anything
        {
            let db_transaction = env.begin_ro_txn().unwrap();
            let active_mint_configs = mint_config_store
                .get_active_mint_configs(TokenId::from(1), &db_transaction)
                .unwrap();
            assert_eq!(active_mint_configs[0].total_minted, 0);
            assert_eq!(active_mint_configs[1].total_minted, 0);
        }

        // Update the total minted amount of the second configuration
        {
            let mut db_transaction = env.begin_rw_txn().unwrap();
            mint_config_store
                .update_total_minted(&test_tx_1.prefix.configs[1], 123456, &mut db_transaction)
                .unwrap();
            db_transaction.commit().unwrap();
        }

        // The amount should've updated correctly.
        {
            let db_transaction = env.begin_ro_txn().unwrap();
            let active_mint_configs = mint_config_store
                .get_active_mint_configs(TokenId::from(1), &db_transaction)
                .unwrap();
            assert_eq!(active_mint_configs[0].total_minted, 0);
            assert_eq!(active_mint_configs[1].total_minted, 123456);
        }

        // Update both configurations in one transaction
        {
            let mut db_transaction = env.begin_rw_txn().unwrap();
            mint_config_store
                .update_total_minted(
                    &test_tx_1.prefix.configs[0],
                    1020304050,
                    &mut db_transaction,
                )
                .unwrap();
            mint_config_store
                .update_total_minted(
                    &test_tx_1.prefix.configs[1],
                    2020202020,
                    &mut db_transaction,
                )
                .unwrap();
            db_transaction.commit().unwrap();
        }

        // The amount should've updated correctly.
        {
            let db_transaction = env.begin_ro_txn().unwrap();
            let active_mint_configs = mint_config_store
                .get_active_mint_configs(TokenId::from(1), &db_transaction)
                .unwrap();
            assert_eq!(active_mint_configs[0].total_minted, 1020304050);
            assert_eq!(active_mint_configs[1].total_minted, 2020202020);
        }
    }

    #[test]
    fn cannot_update_minting_above_limit() {
        let (mint_config_store, env) = init_mint_config_store();
        let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);

        let test_tx_1 = generate_test_mint_config_tx(TokenId::from(1), &mut rng);

        {
            let mut db_transaction = env.begin_rw_txn().unwrap();
            mint_config_store
                .set_active_mint_configs(&test_tx_1, &mut db_transaction)
                .unwrap();
            db_transaction.commit().unwrap();
        }

        {
            let mut db_transaction = env.begin_rw_txn().unwrap();
            assert_eq!(
                mint_config_store.update_total_minted(
                    &test_tx_1.prefix.configs[1],
                    test_tx_1.prefix.configs[1].mint_limit + 1,
                    &mut db_transaction,
                ),
                Err(Error::MintLimitExceeded(
                    test_tx_1.prefix.configs[1].mint_limit + 1,
                    test_tx_1.prefix.configs[1].mint_limit
                ))
            );
        }
    }

    #[test]
    fn cannot_decrease_total_minted_amount() {
        let (mint_config_store, env) = init_mint_config_store();
        let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);

        let test_tx_1 = generate_test_mint_config_tx(TokenId::from(1), &mut rng);

        {
            let mut db_transaction = env.begin_rw_txn().unwrap();
            mint_config_store
                .set_active_mint_configs(&test_tx_1, &mut db_transaction)
                .unwrap();
            db_transaction.commit().unwrap();
        }

        {
            let mut db_transaction = env.begin_rw_txn().unwrap();
            mint_config_store
                .update_total_minted(&test_tx_1.prefix.configs[1], 10, &mut db_transaction)
                .unwrap();
            db_transaction.commit().unwrap();
        }

        {
            let mut db_transaction = env.begin_rw_txn().unwrap();
            assert_eq!(
                mint_config_store.update_total_minted(
                    &test_tx_1.prefix.configs[1],
                    9,
                    &mut db_transaction,
                ),
                Err(Error::TotalMintedAmountCannotDecrease(9, 10,))
            );
        }
    }

    #[test]
    fn cannot_update_total_minted_amount_for_unknown_config() {
        let (mint_config_store, env) = init_mint_config_store();
        let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);

        let mut test_tx_1 = generate_test_mint_config_tx(TokenId::from(1), &mut rng);
        let test_tx_2 = generate_test_mint_config_tx(TokenId::from(2), &mut rng);

        // Try to update when nothing has been written yet.
        {
            let mut db_transaction = env.begin_rw_txn().unwrap();
            assert_eq!(
                mint_config_store.update_total_minted(
                    &test_tx_1.prefix.configs[1],
                    123456,
                    &mut db_transaction
                ),
                Err(Error::InvalidMintConfig(
                    "Mint config not found".to_string(),
                ))
            );
        }

        // Write a minting configuration to the database
        {
            let mut db_transaction = env.begin_rw_txn().unwrap();
            mint_config_store
                .set_active_mint_configs(&test_tx_1, &mut db_transaction)
                .unwrap();
            db_transaction.commit().unwrap();
        }

        // Try to update another one that has not been written.
        {
            let mut db_transaction = env.begin_rw_txn().unwrap();
            assert_eq!(
                mint_config_store.update_total_minted(
                    &test_tx_2.prefix.configs[1],
                    123456,
                    &mut db_transaction
                ),
                Err(Error::InvalidMintConfig(
                    "Mint config not found".to_string(),
                ))
            );
        }

        // Mess with the mint limit - we should fail to write as well.
        {
            test_tx_1.prefix.configs[1].mint_limit += 123;

            let mut db_transaction = env.begin_rw_txn().unwrap();
            assert_eq!(
                mint_config_store.update_total_minted(
                    &test_tx_1.prefix.configs[1],
                    123456,
                    &mut db_transaction
                ),
                Err(Error::InvalidMintConfig(
                    "Mint config not found".to_string(),
                ))
            );
        }
    }
    #[test]
    fn get_active_mint_config_for_mint_tx_works() {
        let (mint_config_store, env) = init_mint_config_store();
        let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);
        let token_id1 = TokenId::from(1);
        let token_id2 = TokenId::from(2);

        let (test_tx_1, signers1) = generate_test_mint_config_tx_and_signers(token_id1, &mut rng);

        // Store mint config
        {
            let mut db_transaction = env.begin_rw_txn().unwrap();
            mint_config_store
                .set_active_mint_configs(&test_tx_1, &mut db_transaction)
                .unwrap();
            db_transaction.commit().unwrap();
        }

        // Generate a test mint tx that matches the first mint config and see that we
        // can get it back.
        let db_transaction = env.begin_ro_txn().unwrap();
        let mint_tx1 = generate_test_mint_tx(
            token_id1,
            &[Ed25519Pair::from(signers1[0].private_key())],
            10,
            &mut rng,
        );
        assert_eq!(
            mint_config_store.get_active_mint_config_for_mint_tx(&mint_tx1, &db_transaction),
            Ok(ActiveMintConfig {
                mint_config: test_tx_1.prefix.configs[0].clone(),
                total_minted: 0,
            })
        );

        // Generate a test mint tx that matches the second mint config and see that we
        // can get it back.
        let mint_tx2 = generate_test_mint_tx(
            token_id1,
            &[Ed25519Pair::from(signers1[1].private_key())],
            10,
            &mut rng,
        );
        assert_eq!(
            mint_config_store.get_active_mint_config_for_mint_tx(&mint_tx2, &db_transaction),
            Ok(ActiveMintConfig {
                mint_config: test_tx_1.prefix.configs[1].clone(),
                total_minted: 0,
            })
        );

        // Generate a test mint tx that is signed by an unknown signer, we shouldn't get
        // anything back.
        let mint_tx3 = generate_test_mint_tx(
            token_id1,
            &[Ed25519Pair::from_random(&mut rng)],
            10,
            &mut rng,
        );
        assert_eq!(
            mint_config_store.get_active_mint_config_for_mint_tx(&mint_tx3, &db_transaction),
            Err(Error::NotFound)
        );

        // Generate a test mint tx that is signed by all known signers but a different
        // token id.
        let mint_tx4 = generate_test_mint_tx(token_id2, &signers1, 10, &mut rng);
        assert_eq!(
            mint_config_store.get_active_mint_config_for_mint_tx(&mint_tx4, &db_transaction),
            Err(Error::NotFound)
        );
    }

    #[test]
    fn get_active_mint_config_for_mint_tx_refuses_to_exceed_mint_limit() {
        let (mint_config_store, env) = init_mint_config_store();
        let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);
        let token_id1 = TokenId::from(1);

        let (test_tx_1, signers1) = generate_test_mint_config_tx_and_signers(token_id1, &mut rng);

        // Store mint config
        {
            let mut db_transaction = env.begin_rw_txn().unwrap();
            mint_config_store
                .set_active_mint_configs(&test_tx_1, &mut db_transaction)
                .unwrap();
            db_transaction.commit().unwrap();
        }

        // Generate a test mint tx that will immediately exceed the mint limit.
        {
            let db_transaction = env.begin_ro_txn().unwrap();
            let mint_tx = generate_test_mint_tx(
                token_id1,
                &[Ed25519Pair::from(signers1[0].private_key())],
                test_tx_1.prefix.configs[0].mint_limit + 1,
                &mut rng,
            );
            assert_eq!(
                mint_config_store.get_active_mint_config_for_mint_tx(&mint_tx, &db_transaction),
                Err(Error::MintLimitExceeded(
                    mint_tx.prefix.amount,
                    test_tx_1.prefix.configs[0].mint_limit
                ))
            );
        }

        // Mint limit should be enforced correctly if some amount was already minted.
        {
            let mut db_transaction = env.begin_rw_txn().unwrap();
            mint_config_store
                .update_total_minted(&test_tx_1.prefix.configs[0], 10, &mut db_transaction)
                .unwrap();
            db_transaction.commit().unwrap();
        }

        {
            let db_transaction = env.begin_ro_txn().unwrap();
            let mint_tx = generate_test_mint_tx(
                token_id1,
                &[Ed25519Pair::from(signers1[0].private_key())],
                test_tx_1.prefix.configs[0].mint_limit - 9,
                &mut rng,
            );
            assert_eq!(
                mint_config_store.get_active_mint_config_for_mint_tx(&mint_tx, &db_transaction),
                Err(Error::MintLimitExceeded(
                    mint_tx.prefix.amount + 10, // 10 is the amount that was previously minted
                    test_tx_1.prefix.configs[0].mint_limit
                ))
            );
        }

        // Sanity - getting the active mint configuration should succeed when not
        // over-minting.
        {
            let db_transaction = env.begin_ro_txn().unwrap();
            let mint_tx = generate_test_mint_tx(
                token_id1,
                &[Ed25519Pair::from(signers1[0].private_key())],
                20,
                &mut rng,
            );
            assert_eq!(
                mint_config_store.get_active_mint_config_for_mint_tx(&mint_tx, &db_transaction),
                Ok(ActiveMintConfig {
                    mint_config: test_tx_1.prefix.configs[0].clone(),
                    total_minted: 10,
                })
            );
        }
    }

    #[test]
    fn get_active_mint_config_for_mint_tx_selects_correct_config_when_exceeding_mint_limit() {
        let (mint_config_store, env) = init_mint_config_store();
        let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);
        let token_id1 = TokenId::from(1);

        let (mut test_tx_1, signers1) =
            generate_test_mint_config_tx_and_signers(token_id1, &mut rng);

        // This test requires that the 2nd minting configuration is >= the first one.
        test_tx_1.prefix.configs[1].mint_limit = test_tx_1.prefix.configs[0].mint_limit;

        // Store mint config
        {
            let mut db_transaction = env.begin_rw_txn().unwrap();
            mint_config_store
                .set_active_mint_configs(&test_tx_1, &mut db_transaction)
                .unwrap();
            db_transaction.commit().unwrap();
        }

        // Mint limit should result in the second configuration being selected.
        {
            let mut db_transaction = env.begin_rw_txn().unwrap();
            mint_config_store
                .update_total_minted(&test_tx_1.prefix.configs[0], 10, &mut db_transaction)
                .unwrap();
            mint_config_store
                .update_total_minted(&test_tx_1.prefix.configs[1], 9, &mut db_transaction)
                .unwrap();
            db_transaction.commit().unwrap();
        }

        {
            let db_transaction = env.begin_ro_txn().unwrap();
            let mint_tx = generate_test_mint_tx(
                token_id1,
                &signers1,
                test_tx_1.prefix.configs[0].mint_limit - 9,
                &mut rng,
            );
            assert_eq!(
                mint_config_store.get_active_mint_config_for_mint_tx(&mint_tx, &db_transaction),
                Ok(ActiveMintConfig {
                    mint_config: test_tx_1.prefix.configs[1].clone(),
                    total_minted: 9,
                })
            );
        }
    }
}
