// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Model file for the mint_configs table.

//use crate::{db::schema::*, Error};
use crate::{
    db::{
        schema::{mint_configs, mint_txs},
        Conn,
    },
    Error,
};
use diesel::prelude::*;
use mc_blockchain_types::BlockIndex;
use mc_util_serial::{decode, encode};
use serde::{Deserialize, Serialize};

/// Diesel model for the `mint_configs` table.
/// This stores audit data for a specific block index.
#[derive(Debug, Deserialize, Eq, Insertable, PartialEq, Queryable, Serialize)]
pub struct MintConfig {
    /// Auto incrementing primary key.
    pub id: Option<i32>,

    /// id linking to the mint_config_txs table.
    pub mint_config_tx_id: i32,

    /// The maximal amount this configuration can mint from the moment it has
    /// been applied.
    pub mint_limit: i64,

    /// The protobuf-serialized MintConfig.
    pub protobuf: Vec<u8>,
}

impl MintConfig {
    /// Get mint limit.
    pub fn mint_limit(&self) -> u64 {
        self.mint_limit as u64
    }

    /// Get the original MintConfig
    pub fn decode(&self) -> Result<mc_transaction_core::mint::MintConfig, Error> {
        Ok(decode(&self.protobuf)?)
    }

    /// Insert a new MintConfig into the database.
    pub fn insert(
        mint_config_tx_id: i32,
        config: &mc_transaction_core::mint::MintConfig,
        conn: &Conn,
    ) -> Result<(), Error> {
        let obj = Self {
            id: None,
            mint_config_tx_id,
            mint_limit: config.mint_limit as i64,
            protobuf: encode(config),
        };

        diesel::insert_into(mint_configs::table)
            .values(&obj)
            .execute(conn)?;

        Ok(())
    }

    /// Get all mint configs associated with a given mint config tx id.
    pub fn get_by_mint_config_tx_id(
        mint_config_tx_id: i32,
        conn: &Conn,
    ) -> Result<Vec<Self>, Error> {
        Ok(mint_configs::table
            .filter(mint_configs::mint_config_tx_id.eq(mint_config_tx_id))
            .load::<Self>(conn)?)
    }

    /// Get the total amount minted by this configuration.
    pub fn get_total_minted_before_block(
        &self,
        block_index: BlockIndex,
        conn: &Conn,
    ) -> Result<u64, Error> {
        // Note: We sum in Rust and not Sqlite due to Sqlite not properly supporting
        // unsigned ints.
        let mint_amounts: Vec<i64> = mint_txs::table
            .filter(mint_txs::mint_config_id.eq(self.id))
            .filter(mint_txs::block_index.lt(block_index as i64))
            .select(mint_txs::amount)
            .load::<i64>(conn)?;
        Ok(mint_amounts.into_iter().map(|val| val as u64).sum())
    }
}
