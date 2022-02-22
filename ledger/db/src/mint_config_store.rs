// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Data access abstraction for minting configuration stored in the ledger.
//!
//! This store maintains two LMDB databases:
//! 1) A mapping of token id -> currently active mint configurations.
//!    This database is used for two things:
//!        1) It allows transaction validation code to figure out if a mint
//! transaction is allowed to mint.        2) It enables keeping track of how
//! much was minted using a given configuration. This is used to enforce the
//! per-configuration mint limit. 2) A mapping of nonce -> SetMintConfigTx
//! object containing the nonce. This is mainly used to prevent replay attacks.

use crate::{u32_to_key_bytes, Error};
use lmdb::{Database, DatabaseFlags, Environment, RwTransaction, Transaction, WriteFlags};
use mc_transaction_core::{
    mint::{MintConfig, SetMintConfigTx},
    TokenId,
};
use mc_util_serial::{decode, encode, Message};

// LMDB Database names.
pub const ACTIVE_MINT_CONFIGS_BY_TOKEN_ID_DB_NAME: &str =
    "mint_config_store:active_mint_configs_by_token_id";
pub const SET_MINT_CONFIG_TX_BY_NONCE_DB_NAME: &str =
    "mint_config_store:set_mint_config_tx_by_nonce_db_name";

/// An active mint configuration for a single token.
#[derive(Clone, Message)]
pub struct ActiveMintConfig {
    /// The actual mint configuration.
    #[prost(message, required, tag = "1")]
    pub mint_config: MintConfig,

    /// How many tokens have been minted using this configuration.
    #[prost(uint64, tag = "2")]
    pub total_minted: u64,
}

/// A collection of active mint configurations.
#[derive(Clone, Message)]
pub struct ActiveMintConfigs {
    #[prost(message, repeated, tag = "1")]
    pub configs: Vec<ActiveMintConfig>,
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
        let active_mint_configs = ActiveMintConfigs {
            configs: set_mint_config_tx
                .prefix
                .configs
                .iter()
                .map(|mint_config| ActiveMintConfig {
                    mint_config: mint_config.clone(),
                    total_minted: 0,
                })
                .collect(),
        };

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
                let active_mint_configs: ActiveMintConfigs = decode(&bytes)?;
                Ok(active_mint_configs.configs)
            }
            Err(lmdb::Error::NotFound) => Ok(Vec::new()),
            Err(err) => Err(err.into()),
        }
    }
}
