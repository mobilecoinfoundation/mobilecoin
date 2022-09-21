// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Data access abstraction for minting configuration stored in the ledger.
//!
//! This store maintains three LMDB databases:
//! 1) A mapping of token id -> currently active mint configurations.
//!    This database is used for two things:
//!      1) It allows transaction validation code to figure out if a mint
//! transaction is allowed to mint.
//!      2) It enables keeping track of how much was minted using a given
//! configuration. This is used to enforce the per-configuration mint limit.
//! 2) A mapping of nonce -> block index of the block containing the
//! MintConfigTx with that nonce. This is mainly used to prevent replay
//! attacks.
//! 3) A mapping of block index -> list of ValidatedMintConfigTx objects
//! included in the block.

use crate::{key_bytes_to_u64, u64_to_key_bytes, Error};
use lmdb::{Cursor, Database, DatabaseFlags, Environment, RwTransaction, Transaction, WriteFlags};
use mc_blockchain_types::BlockIndex;
use mc_common::HashMap;
use mc_transaction_core::{
    mint::{MintConfig, MintConfigTx, MintTx, ValidatedMintConfigTx},
    TokenId,
};
use mc_util_serial::{decode, encode, Message};

// LMDB Database names.
pub const ACTIVE_MINT_CONFIGS_BY_TOKEN_ID_DB_NAME: &str =
    "mint_config_store:active_mint_configs_by_token_id";
pub const BLOCK_INDEX_BY_MINT_CONFIG_TX_NONCE_AND_TOKEN_ID_DB_NAME: &str =
    "mint_config_store:block_index_by_mint_config_tx_nonce_and_token_id";
pub const VALIDATED_MINT_CONFIG_TXS_BY_BLOCK_DB_NAME: &str =
    "mint_config_store:validated_mint_config_txs_by_block";

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

/// A collection of active mint configurations for a specific token id.
/// This also contains the global mint limit that is shared amongst all the
/// configurations.
#[derive(Clone, Eq, Message, PartialEq)]
pub struct ActiveMintConfigs {
    #[prost(message, repeated, tag = "1")]
    pub configs: Vec<ActiveMintConfig>,

    /// The original MintConfigTx that this object was created from.
    #[prost(message, required, tag = "2")]
    pub mint_config_tx: MintConfigTx,
}

impl ActiveMintConfigs {
    /// The total amount that can be minted by all configurations tgether, once
    /// this set has been made active.
    pub fn total_mint_limit(&self) -> u64 {
        self.mint_config_tx.prefix.total_mint_limit
    }

    /// Get the total amount that was minted across all configurations.
    pub fn total_minted(&self) -> u64 {
        self.configs.iter().map(|c| c.total_minted).sum()
    }

    /// Check if we can mint a certain amount without exceeding the global
    /// limit.
    pub fn can_mint(&self, amount: u64) -> bool {
        if let Some(new_total_minted) = self.total_minted().checked_add(amount) {
            new_total_minted <= self.total_mint_limit()
        } else {
            false
        }
    }

    /// Attempt to get an ActiveMintConfig that that is capable of minting the
    /// given amount of tokens.
    pub fn get_active_mint_config_for_mint_tx(
        &self,
        mint_tx: &MintTx,
    ) -> Result<ActiveMintConfig, Error> {
        // Check if the amount minted is going to tip us over the limit.
        if !self.can_mint(mint_tx.prefix.amount) {
            // should be changed to address that.
            return Err(Error::MintLimitExceeded(
                mint_tx.prefix.amount,
                self.total_minted(),
                self.total_mint_limit(),
            ));
        }

        // Sanity check that the MintConfigs match what was inside the original
        // transaction.
        let mint_configs = self
            .configs
            .iter()
            .map(|c| &c.mint_config)
            .collect::<Vec<_>>();
        if mint_configs
            != self
                .mint_config_tx
                .prefix
                .configs
                .iter()
                .collect::<Vec<&MintConfig>>()
        {
            return Err(Error::InvalidMintConfig(
                "MintConfigs do not match origianl transaction".to_string(),
            ));
        }

        // Our default error is NotFound, in case we are unable to find a mint config
        // that matches the mint tx. We might override it if we find one but the
        // amount will exceed the mint limit.
        let mut error = Error::NotFound;

        let message = mint_tx.prefix.hash();
        for active_mint_config in &self.configs {
            // See if this mint config has signed the mint tx.
            if active_mint_config
                .mint_config
                .signer_set
                .verify(&message, &mint_tx.signature)
                .is_err()
            {
                continue;
            }

            // This mint config has signed the mint tx. Is it allowed to mint the given
            // amount of tokens?
            // If we overflow (checked_add returns None) then we will keep looking for an
            // active mint configuration that is able to accommodate the MintTx.
            if let Some(new_total_minted) = active_mint_config
                .total_minted
                .checked_add(mint_tx.prefix.amount)
            {
                if new_total_minted <= active_mint_config.mint_config.mint_limit {
                    return Ok(active_mint_config.clone());
                }
            }

            // We found a mint config with a matching signature, but it cannot accommodate
            // the amount this transaction is trying to mint.
            error = Error::MintLimitExceeded(
                mint_tx.prefix.amount,
                active_mint_config.total_minted,
                active_mint_config.mint_config.mint_limit,
            );
        }

        Err(error)
    }
}

impl From<&MintConfigTx> for ActiveMintConfigs {
    fn from(mint_config_tx: &MintConfigTx) -> Self {
        ActiveMintConfigs {
            configs: mint_config_tx
                .prefix
                .configs
                .iter()
                .map(|mint_config| ActiveMintConfig {
                    mint_config: mint_config.clone(),
                    total_minted: 0,
                })
                .collect(),
            mint_config_tx: mint_config_tx.clone(),
        }
    }
}

/// A list of validated mint-config-txs that can be prost-encoded. This is
/// needed since that's the only way to encode a Vec<ValidatedMintConfigTx>.
#[derive(Clone, Message)]
pub struct ValidatedMintConfigTxList {
    #[prost(message, repeated, tag = "1")]
    pub validated_mint_config_txs: Vec<ValidatedMintConfigTx>,
}

#[derive(Clone)]
pub struct MintConfigStore {
    /// token id -> Vec<ActiveMintConfig>
    active_mint_configs_by_token_id: Database,

    /// nonce -> block index
    block_index_by_mint_config_tx_nonce_and_token_id: Database,

    /// block_index -> ValidatedMintConfigTxList
    validated_mint_config_txs_by_block: Database,
}

impl MintConfigStore {
    /// Opens an existing MintConfigStore.
    pub fn new(env: &Environment) -> Result<Self, Error> {
        Ok(MintConfigStore {
            active_mint_configs_by_token_id: env
                .open_db(Some(ACTIVE_MINT_CONFIGS_BY_TOKEN_ID_DB_NAME))?,
            block_index_by_mint_config_tx_nonce_and_token_id: env.open_db(Some(
                BLOCK_INDEX_BY_MINT_CONFIG_TX_NONCE_AND_TOKEN_ID_DB_NAME,
            ))?,
            validated_mint_config_txs_by_block: env
                .open_db(Some(VALIDATED_MINT_CONFIG_TXS_BY_BLOCK_DB_NAME))?,
        })
    }

    /// Creates a fresh MintConfigStore.
    pub fn create(env: &Environment) -> Result<(), Error> {
        env.create_db(
            Some(ACTIVE_MINT_CONFIGS_BY_TOKEN_ID_DB_NAME),
            DatabaseFlags::empty(),
        )?;
        env.create_db(
            Some(BLOCK_INDEX_BY_MINT_CONFIG_TX_NONCE_AND_TOKEN_ID_DB_NAME),
            DatabaseFlags::empty(),
        )?;
        env.create_db(
            Some(VALIDATED_MINT_CONFIG_TXS_BY_BLOCK_DB_NAME),
            DatabaseFlags::empty(),
        )?;

        Ok(())
    }

    /// Write validated mint-config-txs in a given block.
    pub fn write_validated_mint_config_txs(
        &self,
        block_index: u64,
        validated_mint_config_txs: &[ValidatedMintConfigTx],
        db_transaction: &mut RwTransaction,
    ) -> Result<(), Error> {
        let block_index_bytes = u64_to_key_bytes(block_index);

        // Store the list of ValidatedMintConfigTxs.
        let validated_mint_config_tx_list = ValidatedMintConfigTxList {
            validated_mint_config_txs: validated_mint_config_txs.to_vec(),
        };

        db_transaction.put(
            self.validated_mint_config_txs_by_block,
            &block_index_bytes,
            &encode(&validated_mint_config_tx_list),
            WriteFlags::NO_OVERWRITE, // We should not be updating existing blocks
        )?;

        // Update active mint configurations.
        for validated_mint_config_tx in validated_mint_config_txs {
            let mint_config_tx = &validated_mint_config_tx.mint_config_tx;

            // All mint configurations must have the same token id.
            if mint_config_tx
                .prefix
                .configs
                .iter()
                .any(|mint_config| mint_config.token_id != mint_config_tx.prefix.token_id)
            {
                return Err(Error::InvalidMintConfig(
                    "All mint configurations must have the same token id".to_string(),
                ));
            }

            // MintConfigs -> ActiveMintConfigs
            let active_mint_configs = ActiveMintConfigs::from(mint_config_tx);
            let mut combined_nonce_and_token_id = mint_config_tx.prefix.nonce.clone();
            combined_nonce_and_token_id
                .extend_from_slice(&u64_to_key_bytes(mint_config_tx.prefix.token_id));

            // Store in database
            db_transaction.put(
                self.block_index_by_mint_config_tx_nonce_and_token_id,
                &combined_nonce_and_token_id,
                &block_index_bytes,
                //  ensures we do not overwrite a nonce that was already used
                WriteFlags::NO_OVERWRITE,
            )?;

            db_transaction.put(
                self.active_mint_configs_by_token_id,
                &u64_to_key_bytes(mint_config_tx.prefix.token_id),
                &encode(&active_mint_configs),
                WriteFlags::empty(),
            )?;
        }

        Ok(())
    }

    /// Get ValidatedMintConfigTxs in a given block.
    pub fn get_validated_mint_config_txs_by_block_index(
        &self,
        block_index: u64,
        db_transaction: &impl Transaction,
    ) -> Result<Vec<ValidatedMintConfigTx>, Error> {
        let validated_mint_config_tx_list: ValidatedMintConfigTxList =
            decode(db_transaction.get(
                self.validated_mint_config_txs_by_block,
                &u64_to_key_bytes(block_index),
            )?)?;
        Ok(validated_mint_config_tx_list.validated_mint_config_txs)
    }

    /// Get mint configurations for a given token.
    pub fn get_active_mint_configs(
        &self,
        token_id: TokenId,
        db_transaction: &impl Transaction,
    ) -> Result<Option<ActiveMintConfigs>, Error> {
        let token_id_bytes = u64_to_key_bytes(*token_id);
        match db_transaction.get(self.active_mint_configs_by_token_id, &token_id_bytes) {
            Ok(bytes) => Ok(Some(decode(bytes)?)),
            Err(lmdb::Error::NotFound) => Ok(None),
            Err(err) => Err(err.into()),
        }
    }

    /// Return the full map of TokenId -> ActiveMintConfigs.
    pub fn get_active_mint_configs_map(
        &self,
        db_transaction: &impl Transaction,
    ) -> Result<HashMap<TokenId, ActiveMintConfigs>, Error> {
        let mut cursor = db_transaction.open_ro_cursor(self.active_mint_configs_by_token_id)?;
        cursor
            .iter()
            .map(|result| {
                result.map_err(Error::from).and_then(
                    |(token_id_bytes, active_mint_configs_bytes)| {
                        Ok((
                            TokenId::from(key_bytes_to_u64(token_id_bytes)),
                            decode(active_mint_configs_bytes)?,
                        ))
                    },
                )
            })
            .collect::<Result<HashMap<TokenId, ActiveMintConfigs>, Error>>()
    }

    // Attempt to get a MintConfig that is active and is capable of minting the
    // given amount of tokens.
    pub fn get_active_mint_config_for_mint_tx(
        &self,
        mint_tx: &MintTx,
        db_transaction: &impl Transaction,
    ) -> Result<ActiveMintConfig, Error> {
        let active_mint_configs = self
            .get_active_mint_configs(TokenId::from(mint_tx.prefix.token_id), db_transaction)?
            .ok_or(Error::NotFound)?;

        active_mint_configs.get_active_mint_config_for_mint_tx(mint_tx)
    }

    /// Update the total minted amount for a given MintConfig.
    pub fn update_total_minted(
        &self,
        mint_config: &MintConfig,
        amount: u64,
        db_transaction: &mut RwTransaction,
    ) -> Result<(), Error> {
        // Get the active mint configs for the given token.
        let mut active_mint_configs = self
            .get_active_mint_configs(TokenId::from(mint_config.token_id), db_transaction)?
            .ok_or(Error::NotFound)?;

        // Find the active mint config that matches the mint config we were given.
        let active_mint_config = active_mint_configs
            .configs
            .iter_mut()
            .find(|active_mint_config| active_mint_config.mint_config == *mint_config)
            .ok_or(Error::NotFound)?;

        // Total minted amount should never decrease.
        if amount < active_mint_config.total_minted {
            return Err(Error::TotalMintedAmountCannotDecrease(
                amount,
                active_mint_config.total_minted,
            ));
        }

        // Amount should never go above the mint limit of the specific configuration.
        let mint_increase_amount = amount - active_mint_config.total_minted;
        if amount > active_mint_config.mint_config.mint_limit {
            return Err(Error::MintLimitExceeded(
                mint_increase_amount,
                active_mint_config.total_minted,
                active_mint_config.mint_config.mint_limit,
            ));
        }

        // Update the total minted amount.
        active_mint_config.total_minted = amount;

        // Sanity check that we didn't go over the total mint limit.
        if active_mint_configs.total_minted() > active_mint_configs.total_mint_limit() {
            return Err(Error::MintLimitExceeded(
                mint_increase_amount,
                active_mint_configs.total_minted(),
                active_mint_configs.total_mint_limit(),
            ));
        }

        // Write to db.
        db_transaction.put(
            self.active_mint_configs_by_token_id,
            &u64_to_key_bytes(mint_config.token_id),
            &encode(&active_mint_configs),
            WriteFlags::empty(),
        )?;

        Ok(())
    }

    pub fn check_mint_config_tx_nonce(
        &self,
        nonce: &[u8],
        db_transaction: &impl Transaction,
    ) -> Result<Option<BlockIndex>, Error> {
        match db_transaction.get(
            self.block_index_by_mint_config_tx_nonce_and_token_id,
            &nonce,
        ) {
            Ok(db_bytes) => Ok(Some(key_bytes_to_u64(db_bytes))),
            Err(lmdb::Error::NotFound) => Ok(None),
            Err(e) => Err(Error::Lmdb(e)),
        }
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::tx_out_store::tx_out_store_tests::get_env;
    use mc_crypto_keys::{Ed25519Pair, Signer};
    use mc_crypto_multisig::MultiSig;
    use mc_transaction_core::mint::{MintConfigTx, MintConfigTxPrefix};
    use mc_transaction_core_test_utils::{
        create_mint_config_tx, create_mint_config_tx_and_signers, create_mint_tx,
        mint_config_tx_to_validated as to_validated,
    };
    use mc_util_from_random::FromRandom;
    use rand::{rngs::StdRng, RngCore, SeedableRng};

    pub fn init_mint_config_store() -> (MintConfigStore, Environment) {
        let env = get_env();
        MintConfigStore::create(&env).unwrap();
        let mint_config_store = MintConfigStore::new(&env).unwrap();
        (mint_config_store, env)
    }

    #[test]
    fn set_get_behaves_correctly() {
        let (mint_config_store, env) = init_mint_config_store();
        let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);

        let test_tx_1 = create_mint_config_tx(TokenId::from(1), &mut rng);
        let test_tx_2 = create_mint_config_tx(TokenId::from(2), &mut rng);

        // Should be able to set a valid mint configuration and then get it back.
        {
            let mut db_transaction = env.begin_rw_txn().unwrap();
            mint_config_store
                .write_validated_mint_config_txs(
                    0,
                    &[to_validated(&test_tx_1)],
                    &mut db_transaction,
                )
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
                Some(ActiveMintConfigs::from(&test_tx_1))
            );

            // Getting configuration for a different token id should reutrn None.
            let active_mint_configs = mint_config_store
                .get_active_mint_configs(TokenId::from(2), &db_transaction)
                .unwrap();
            assert_eq!(active_mint_configs, None);
        }

        // Set a minting configuration for the 2nd token and try again.
        {
            let mut db_transaction = env.begin_rw_txn().unwrap();
            mint_config_store
                .write_validated_mint_config_txs(
                    1,
                    &[to_validated(&test_tx_2)],
                    &mut db_transaction,
                )
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
                Some(ActiveMintConfigs::from(&test_tx_1))
            );

            let active_mint_configs = mint_config_store
                .get_active_mint_configs(TokenId::from(2), &db_transaction)
                .unwrap();
            assert_eq!(
                active_mint_configs,
                Some(ActiveMintConfigs::from(&test_tx_2))
            );
        }
    }

    #[test]
    fn duplicate_nonce_not_allowed() {
        let (mint_config_store, env) = init_mint_config_store();
        let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);

        let test_tx_1 = create_mint_config_tx(TokenId::from(1), &mut rng);
        let mut test_tx_2 = create_mint_config_tx(TokenId::from(1), &mut rng);
        let mut test_tx_tkn_2 = create_mint_config_tx(TokenId::from(2), &mut rng);

        {
            let mut db_transaction = env.begin_rw_txn().unwrap();
            mint_config_store
                .write_validated_mint_config_txs(
                    0,
                    &[to_validated(&test_tx_1)],
                    &mut db_transaction,
                )
                .unwrap();
            db_transaction.commit().unwrap();
        }

        //Retrying the same transaction should fail
        {
            let mut db_transaction = env.begin_rw_txn().unwrap();
            assert_eq!(
                mint_config_store.write_validated_mint_config_txs(
                    1,
                    &[to_validated(&test_tx_1)],
                    &mut db_transaction
                ),
                Err(Error::Lmdb(lmdb::Error::KeyExist))
            );
            db_transaction.commit().unwrap();
        }
        //Retrying with the same nonce for the same token_id should fail.
        test_tx_2.prefix.nonce = test_tx_1.prefix.nonce.clone();
        {
            let mut db_transaction = env.begin_rw_txn().unwrap();
            assert_eq!(
                mint_config_store.write_validated_mint_config_txs(
                    2,
                    &[to_validated(&test_tx_2)],
                    &mut db_transaction
                ),
                Err(Error::Lmdb(lmdb::Error::KeyExist))
            );
            db_transaction.commit().unwrap();
        }

        //Using the same nonce with different token_id should succeed.
        test_tx_tkn_2.prefix.nonce = test_tx_1.prefix.nonce;
        {
            let mut db_transaction = env.begin_rw_txn().unwrap();
            mint_config_store
                .write_validated_mint_config_txs(
                    3,
                    &[to_validated(&test_tx_tkn_2)],
                    &mut db_transaction,
                )
                .unwrap();
            db_transaction.commit().unwrap();
        }

        // Sanity - change the nonce, we should then succeed.
        test_tx_2.prefix.nonce[0] = !test_tx_2.prefix.nonce[0];
        {
            let mut db_transaction = env.begin_rw_txn().unwrap();
            mint_config_store
                .write_validated_mint_config_txs(
                    4,
                    &[to_validated(&test_tx_2)],
                    &mut db_transaction,
                )
                .unwrap();
            db_transaction.commit().unwrap();
        }
    }

    #[test]
    fn set_replaces_configuration() {
        let (mint_config_store, env) = init_mint_config_store();
        let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);

        let test_tx_1 = create_mint_config_tx(TokenId::from(1), &mut rng);
        let test_tx_2 = create_mint_config_tx(TokenId::from(1), &mut rng);

        assert_ne!(test_tx_1, test_tx_2);

        {
            let mut db_transaction = env.begin_rw_txn().unwrap();
            mint_config_store
                .write_validated_mint_config_txs(
                    0,
                    &[to_validated(&test_tx_1)],
                    &mut db_transaction,
                )
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
                Some(ActiveMintConfigs::from(&test_tx_1))
            );
        }

        // Replace the previous configuration with a different one
        {
            let mut db_transaction = env.begin_rw_txn().unwrap();
            mint_config_store
                .write_validated_mint_config_txs(
                    1,
                    &[to_validated(&test_tx_2)],
                    &mut db_transaction,
                )
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
                Some(ActiveMintConfigs::from(&test_tx_2))
            );
        }
    }

    #[test]
    fn empty_configuration_accepted() {
        let (mint_config_store, env) = init_mint_config_store();
        let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);

        let test_tx_1 = create_mint_config_tx(TokenId::from(1), &mut rng);
        let test_tx_2 = MintConfigTx {
            prefix: MintConfigTxPrefix {
                token_id: test_tx_1.prefix.token_id,
                configs: vec![],
                nonce: vec![5u8; 32],
                tombstone_block: 1234,
                total_mint_limit: 0,
            },
            signature: Default::default(),
        };

        assert_ne!(test_tx_1, test_tx_2);

        {
            let mut db_transaction = env.begin_rw_txn().unwrap();
            mint_config_store
                .write_validated_mint_config_txs(
                    0,
                    &[to_validated(&test_tx_1)],
                    &mut db_transaction,
                )
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
                Some(ActiveMintConfigs::from(&test_tx_1))
            );
        }

        // Replace the previous configuration with an empty one
        {
            let mut db_transaction = env.begin_rw_txn().unwrap();
            mint_config_store
                .write_validated_mint_config_txs(
                    1,
                    &[to_validated(&test_tx_2)],
                    &mut db_transaction,
                )
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
                Some(ActiveMintConfigs::from(&test_tx_2))
            );
        }
    }

    #[test]
    fn update_total_minted_works() {
        let (mint_config_store, env) = init_mint_config_store();
        let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);

        let test_tx_1 = create_mint_config_tx(TokenId::from(1), &mut rng);

        {
            let mut db_transaction = env.begin_rw_txn().unwrap();
            mint_config_store
                .write_validated_mint_config_txs(
                    0,
                    &[to_validated(&test_tx_1)],
                    &mut db_transaction,
                )
                .unwrap();
            db_transaction.commit().unwrap();
        }

        // Initially, both mint configs are not minted anything
        {
            let db_transaction = env.begin_ro_txn().unwrap();
            let active_mint_configs = mint_config_store
                .get_active_mint_configs(TokenId::from(1), &db_transaction)
                .unwrap()
                .unwrap();
            assert_eq!(active_mint_configs.configs[0].total_minted, 0);
            assert_eq!(active_mint_configs.configs[1].total_minted, 0);
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
                .unwrap()
                .unwrap();
            assert_eq!(active_mint_configs.configs[0].total_minted, 0);
            assert_eq!(active_mint_configs.configs[1].total_minted, 123456);
        }

        // Update both configurations in one transaction
        {
            let mut db_transaction = env.begin_rw_txn().unwrap();
            mint_config_store
                .update_total_minted(&test_tx_1.prefix.configs[0], 102030, &mut db_transaction)
                .unwrap();
            mint_config_store
                .update_total_minted(&test_tx_1.prefix.configs[1], 123500, &mut db_transaction)
                .unwrap();
            db_transaction.commit().unwrap();
        }

        // The amount should've updated correctly.
        {
            let db_transaction = env.begin_ro_txn().unwrap();
            let active_mint_configs = mint_config_store
                .get_active_mint_configs(TokenId::from(1), &db_transaction)
                .unwrap()
                .unwrap();
            assert_eq!(active_mint_configs.configs[0].total_minted, 102030);
            assert_eq!(active_mint_configs.configs[1].total_minted, 123500);
        }
    }

    #[test]
    fn cannot_update_minting_above_limit() {
        let (mint_config_store, env) = init_mint_config_store();
        let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);

        let test_tx_1 = create_mint_config_tx(TokenId::from(1), &mut rng);

        {
            let mut db_transaction = env.begin_rw_txn().unwrap();
            mint_config_store
                .write_validated_mint_config_txs(
                    0,
                    &[to_validated(&test_tx_1)],
                    &mut db_transaction,
                )
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
                    0,
                    test_tx_1.prefix.configs[1].mint_limit
                ))
            );
        }
    }

    #[test]
    fn cannot_decrease_total_minted_amount() {
        let (mint_config_store, env) = init_mint_config_store();
        let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);

        let test_tx_1 = create_mint_config_tx(TokenId::from(1), &mut rng);

        {
            let mut db_transaction = env.begin_rw_txn().unwrap();
            mint_config_store
                .write_validated_mint_config_txs(
                    0,
                    &[to_validated(&test_tx_1)],
                    &mut db_transaction,
                )
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

        let mut test_tx_1 = create_mint_config_tx(TokenId::from(1), &mut rng);
        let test_tx_2 = create_mint_config_tx(TokenId::from(2), &mut rng);

        // Try to update when nothing has been written yet.
        {
            let mut db_transaction = env.begin_rw_txn().unwrap();
            assert_eq!(
                mint_config_store.update_total_minted(
                    &test_tx_1.prefix.configs[1],
                    123456,
                    &mut db_transaction
                ),
                Err(Error::NotFound)
            );
        }

        // Write a minting configuration to the database
        {
            let mut db_transaction = env.begin_rw_txn().unwrap();
            mint_config_store
                .write_validated_mint_config_txs(
                    0,
                    &[to_validated(&test_tx_1)],
                    &mut db_transaction,
                )
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
                Err(Error::NotFound)
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
                Err(Error::NotFound)
            );
        }
    }
    #[test]
    fn get_active_mint_config_for_mint_tx_works() {
        let (mint_config_store, env) = init_mint_config_store();
        let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);
        let token_id1 = TokenId::from(1);
        let token_id2 = TokenId::from(2);

        let (test_tx_1, signers1) = create_mint_config_tx_and_signers(token_id1, &mut rng);

        // Store mint config
        {
            let mut db_transaction = env.begin_rw_txn().unwrap();
            mint_config_store
                .write_validated_mint_config_txs(
                    0,
                    &[to_validated(&test_tx_1)],
                    &mut db_transaction,
                )
                .unwrap();
            db_transaction.commit().unwrap();
        }

        // Generate a test mint tx that matches the first mint config and see that we
        // can get it back.
        let db_transaction = env.begin_ro_txn().unwrap();
        let mint_tx1 = create_mint_tx(
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
        let mint_tx2 = create_mint_tx(
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
        let mint_tx3 = create_mint_tx(
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
        let mint_tx4 = create_mint_tx(token_id2, &signers1, 10, &mut rng);
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

        let (test_tx_1, signers1) = create_mint_config_tx_and_signers(token_id1, &mut rng);

        // Store mint config
        {
            let mut db_transaction = env.begin_rw_txn().unwrap();
            mint_config_store
                .write_validated_mint_config_txs(
                    0,
                    &[to_validated(&test_tx_1)],
                    &mut db_transaction,
                )
                .unwrap();
            db_transaction.commit().unwrap();
        }

        // Generate a test mint tx that will immediately exceed the mint limit.
        {
            let db_transaction = env.begin_ro_txn().unwrap();
            let mint_tx = create_mint_tx(
                token_id1,
                &[Ed25519Pair::from(signers1[0].private_key())],
                test_tx_1.prefix.configs[0].mint_limit + 1,
                &mut rng,
            );
            assert_eq!(
                mint_config_store.get_active_mint_config_for_mint_tx(&mint_tx, &db_transaction),
                Err(Error::MintLimitExceeded(
                    mint_tx.prefix.amount,
                    0,
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
            let mint_tx = create_mint_tx(
                token_id1,
                &[Ed25519Pair::from(signers1[0].private_key())],
                test_tx_1.prefix.configs[0].mint_limit - 9,
                &mut rng,
            );
            assert_eq!(
                mint_config_store.get_active_mint_config_for_mint_tx(&mint_tx, &db_transaction),
                Err(Error::MintLimitExceeded(
                    mint_tx.prefix.amount,
                    10, // 10 is the amount that was previously minted
                    test_tx_1.prefix.configs[0].mint_limit
                ))
            );
        }

        // Sanity - getting the active mint configuration should succeed when not
        // over-minting.
        {
            let db_transaction = env.begin_ro_txn().unwrap();
            let mint_tx = create_mint_tx(
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

        let (mut test_tx_1, signers1) = create_mint_config_tx_and_signers(token_id1, &mut rng);

        // This test requires that the 2nd minting configuration is >= the first one.
        test_tx_1.prefix.configs[1].mint_limit = test_tx_1.prefix.configs[0].mint_limit;

        // Store mint config
        {
            let mut db_transaction = env.begin_rw_txn().unwrap();
            mint_config_store
                .write_validated_mint_config_txs(
                    0,
                    &[to_validated(&test_tx_1)],
                    &mut db_transaction,
                )
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
            let mint_tx = create_mint_tx(
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

    #[test]
    fn get_active_mint_config_for_mint_tx_refuses_exceeding_total_mint_limit() {
        let (mint_config_store, env) = init_mint_config_store();
        let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);
        let token_id1 = TokenId::from(1);

        let (mut test_tx_1, signers1) = create_mint_config_tx_and_signers(token_id1, &mut rng);

        test_tx_1.prefix.total_mint_limit = test_tx_1.prefix.configs[0].mint_limit - 1;

        // Store mint config
        {
            let mut db_transaction = env.begin_rw_txn().unwrap();
            mint_config_store
                .write_validated_mint_config_txs(
                    0,
                    &[to_validated(&test_tx_1)],
                    &mut db_transaction,
                )
                .unwrap();
            db_transaction.commit().unwrap();
        }

        // Generate a test mint tx that will immediately exceed the total mint limit.
        {
            let db_transaction = env.begin_ro_txn().unwrap();
            let mint_tx = create_mint_tx(
                token_id1,
                &[Ed25519Pair::from(signers1[0].private_key())],
                test_tx_1.prefix.configs[0].mint_limit,
                &mut rng,
            );
            assert_eq!(
                mint_config_store.get_active_mint_config_for_mint_tx(&mint_tx, &db_transaction),
                Err(Error::MintLimitExceeded(
                    mint_tx.prefix.amount,
                    0,
                    test_tx_1.prefix.total_mint_limit,
                ))
            );
        }

        // Total mint limit should be enforced correctly if some amount was already
        // minted.
        {
            let mut db_transaction = env.begin_rw_txn().unwrap();
            mint_config_store
                .update_total_minted(&test_tx_1.prefix.configs[0], 10, &mut db_transaction)
                .unwrap();
            db_transaction.commit().unwrap();
        }

        {
            let db_transaction = env.begin_ro_txn().unwrap();
            let mint_tx = create_mint_tx(
                token_id1,
                &[Ed25519Pair::from(signers1[0].private_key())],
                // We minted 10 tokens above, so the configuration will allow us to mint 10 so the
                // configuration does allow for 10 more but the global limit only allows 9 more so
                // this is expected to fail.
                test_tx_1.prefix.configs[0].mint_limit - 10,
                &mut rng,
            );
            assert_eq!(
                mint_config_store.get_active_mint_config_for_mint_tx(&mint_tx, &db_transaction),
                Err(Error::MintLimitExceeded(
                    mint_tx.prefix.amount,
                    10,
                    test_tx_1.prefix.total_mint_limit,
                ))
            );
        }

        // Sanity check
        {
            let db_transaction = env.begin_ro_txn().unwrap();
            let mint_tx = create_mint_tx(
                token_id1,
                &[Ed25519Pair::from(signers1[0].private_key())],
                test_tx_1.prefix.configs[0].mint_limit - 11,
                &mut rng,
            );
            assert_eq!(
                mint_config_store
                    .get_active_mint_config_for_mint_tx(&mint_tx, &db_transaction)
                    .unwrap()
                    .mint_config,
                test_tx_1.prefix.configs[0],
            );
        }
    }

    #[test]
    fn can_set_empty_configs_array() {
        let (mint_config_store, env) = init_mint_config_store();
        let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);
        let token_id1 = TokenId::from(1);
        let token_id2 = TokenId::from(2);

        let test_tx_1 = create_mint_config_tx(token_id1, &mut rng);
        let test_tx_2 = create_mint_config_tx(token_id2, &mut rng);

        {
            let mut db_transaction = env.begin_rw_txn().unwrap();
            mint_config_store
                .write_validated_mint_config_txs(
                    0,
                    &[to_validated(&test_tx_1), to_validated(&test_tx_2)],
                    &mut db_transaction,
                )
                .unwrap();
            db_transaction.commit().unwrap();
        }

        {
            let db_transaction = env.begin_ro_txn().unwrap();

            let active_mint_configs = mint_config_store
                .get_active_mint_configs(token_id1, &db_transaction)
                .unwrap();
            assert_eq!(
                active_mint_configs,
                Some(ActiveMintConfigs::from(&test_tx_1))
            );

            let active_mint_configs = mint_config_store
                .get_active_mint_configs(token_id2, &db_transaction)
                .unwrap();
            assert_eq!(
                active_mint_configs,
                Some(ActiveMintConfigs::from(&test_tx_2))
            );
        }

        // Replace the previous configuration with an empty one - this is how we could
        // disable minting for a given token id
        {
            let test_tx_3 = {
                let signer_1 = Ed25519Pair::from_random(&mut rng);

                let mut nonce: Vec<u8> = vec![0u8; 32];
                rng.fill_bytes(&mut nonce);

                let prefix = MintConfigTxPrefix {
                    token_id: *token_id1,
                    configs: vec![],
                    nonce,
                    tombstone_block: rng.next_u64(),
                    total_mint_limit: 0,
                };

                let message = prefix.hash();
                let signature = MultiSig::new(vec![signer_1.try_sign(message.as_ref()).unwrap()]);

                MintConfigTx { prefix, signature }
            };
            let mut db_transaction = env.begin_rw_txn().unwrap();
            mint_config_store
                .write_validated_mint_config_txs(
                    1,
                    &[to_validated(&test_tx_3)],
                    &mut db_transaction,
                )
                .unwrap();
            db_transaction.commit().unwrap();
        }

        {
            let db_transaction = env.begin_ro_txn().unwrap();
            let active_mint_configs = mint_config_store
                .get_active_mint_configs(token_id1, &db_transaction)
                .unwrap()
                .unwrap();
            assert_eq!(active_mint_configs.configs, vec![]);

            let active_mint_configs = mint_config_store
                .get_active_mint_configs(token_id2, &db_transaction)
                .unwrap();
            assert_eq!(
                active_mint_configs,
                Some(ActiveMintConfigs::from(&test_tx_2))
            );
        }
    }

    #[test]
    fn check_mint_config_tx_nonce_works() {
        let (mint_config_store, env) = init_mint_config_store();
        let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);
        let token_id1 = TokenId::from(1);
        let token_id2 = TokenId::from(2);

        let test_tx_1 = create_mint_config_tx(token_id1, &mut rng);
        let test_tx_2 = create_mint_config_tx(token_id2, &mut rng);
        let test_tx_3 = create_mint_config_tx(token_id2, &mut rng);

        {
            let mut db_transaction = env.begin_rw_txn().unwrap();
            mint_config_store
                .write_validated_mint_config_txs(
                    0,
                    &[to_validated(&test_tx_1), to_validated(&test_tx_2)],
                    &mut db_transaction,
                )
                .unwrap();
            db_transaction.commit().unwrap();
        }

        {
            let db_transaction = env.begin_ro_txn().unwrap();

            assert_eq!(
                mint_config_store
                    .check_mint_config_tx_nonce(&test_tx_1.prefix.nonce, &db_transaction),
                Ok(Some(0)),
            );

            assert_eq!(
                mint_config_store
                    .check_mint_config_tx_nonce(&test_tx_2.prefix.nonce, &db_transaction),
                Ok(Some(0)),
            );

            assert_eq!(
                mint_config_store.check_mint_config_tx_nonce(
                    &test_tx_2.prefix.nonce[0..test_tx_2.prefix.nonce.len() - 1],
                    &db_transaction
                ),
                Ok(None),
            );

            assert_eq!(
                mint_config_store
                    .check_mint_config_tx_nonce(&test_tx_3.prefix.nonce, &db_transaction),
                Ok(None),
            );

            assert_eq!(
                mint_config_store.check_mint_config_tx_nonce(&[1, 2, 3], &db_transaction),
                Ok(None),
            );
        }

        {
            let mut db_transaction = env.begin_rw_txn().unwrap();
            mint_config_store
                .write_validated_mint_config_txs(
                    1,
                    &[to_validated(&test_tx_3)],
                    &mut db_transaction,
                )
                .unwrap();
            db_transaction.commit().unwrap();
        }

        {
            let db_transaction = env.begin_ro_txn().unwrap();

            assert_eq!(
                mint_config_store
                    .check_mint_config_tx_nonce(&test_tx_1.prefix.nonce, &db_transaction),
                Ok(Some(0)),
            );

            assert_eq!(
                mint_config_store
                    .check_mint_config_tx_nonce(&test_tx_2.prefix.nonce, &db_transaction),
                Ok(Some(0)),
            );

            assert_eq!(
                mint_config_store
                    .check_mint_config_tx_nonce(&test_tx_3.prefix.nonce, &db_transaction),
                Ok(Some(1)),
            );
        }
    }

    #[test]
    fn get_active_mint_configs_map_works() {
        let (mint_config_store, env) = init_mint_config_store();
        let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);
        let token_id1 = TokenId::from(1);
        let token_id2 = TokenId::from(2);

        let test_tx_1 = create_mint_config_tx(token_id1, &mut rng);
        let test_tx_2 = create_mint_config_tx(token_id2, &mut rng);
        let test_tx_3 = create_mint_config_tx(token_id2, &mut rng);

        {
            let mut db_transaction = env.begin_rw_txn().unwrap();
            mint_config_store
                .write_validated_mint_config_txs(
                    0,
                    &[to_validated(&test_tx_1), to_validated(&test_tx_2)],
                    &mut db_transaction,
                )
                .unwrap();
            db_transaction.commit().unwrap();
        }

        {
            let db_transaction = env.begin_ro_txn().unwrap();
            let active_mint_configs = mint_config_store
                .get_active_mint_configs_map(&db_transaction)
                .unwrap();

            assert_eq!(
                active_mint_configs,
                HashMap::from_iter([
                    (token_id1, ActiveMintConfigs::from(&test_tx_1)),
                    (token_id2, ActiveMintConfigs::from(&test_tx_2)),
                ])
            );
        }

        // Update token id 2 and try again
        {
            let mut db_transaction = env.begin_rw_txn().unwrap();
            mint_config_store
                .write_validated_mint_config_txs(
                    1,
                    &[to_validated(&test_tx_3)],
                    &mut db_transaction,
                )
                .unwrap();
            db_transaction.commit().unwrap();
        }

        {
            let db_transaction = env.begin_ro_txn().unwrap();
            let active_mint_configs = mint_config_store
                .get_active_mint_configs_map(&db_transaction)
                .unwrap();

            assert_eq!(
                active_mint_configs,
                HashMap::from_iter([
                    (token_id1, ActiveMintConfigs::from(&test_tx_1)),
                    (token_id2, ActiveMintConfigs::from(&test_tx_3)),
                ])
            );
        }
    }
}
