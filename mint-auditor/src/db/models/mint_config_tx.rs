// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Model file for the mint_config_txs table.

use crate::{
    db::{
        last_insert_rowid,
        models::MintConfig,
        schema::{self, mint_config_txs, mint_configs, mint_txs},
        transaction, Conn,
    },
    Error,
};
use diesel::prelude::*;
use mc_blockchain_types::BlockIndex;
use mc_transaction_core::TokenId;
use mc_util_serial::{decode, encode};
use serde::{Deserialize, Serialize};

/// Diesel model for the `mint_config_txs` table.
/// This stores audit data for a specific block index.
#[derive(Debug, Deserialize, Eq, Insertable, PartialEq, Queryable, Serialize)]
pub struct MintConfigTx {
    /// Auto incrementing primary key.
    pub id: Option<i32>,

    /// The block index at which this mint config tx appreared.
    pub block_index: i64,

    /// The token id this mint config tx is for.
    pub token_id: i64,

    /// The nonce, as hex-encoded bytes.
    pub nonce: String,

    /// The maximal amount that can be minted by configurations specified in
    /// this tx. This amount is shared amongst all configs.
    pub total_mint_limit: i64,

    /// Tombstone block.
    pub tombstone_block: i64,

    /// The protobuf-serialized MintConfigTx.
    pub protobuf: Vec<u8>,
}

impl MintConfigTx {
    /// Get block index.
    pub fn block_index(&self) -> u64 {
        self.block_index as u64
    }

    /// Get token id.
    pub fn token_id(&self) -> TokenId {
        TokenId::from(self.token_id as u64)
    }

    /// Get mint limit.
    pub fn total_mint_limit(&self) -> u64 {
        self.total_mint_limit as u64
    }

    /// Get tombstone block.
    pub fn tombstone_block(&self) -> u64 {
        self.tombstone_block as u64
    }

    /// Get the original MintConfigTx
    pub fn decode(&self) -> Result<mc_transaction_core::mint::MintConfigTx, Error> {
        Ok(decode(&self.protobuf)?)
    }

    /// Insert a new MintConfigTx into the database.
    pub fn insert(
        block_index: BlockIndex,
        tx: &mc_transaction_core::mint::MintConfigTx,
        conn: &Conn,
    ) -> Result<(), Error> {
        transaction(conn, |conn| {
            let obj = Self {
                id: None,
                block_index: block_index as i64,
                token_id: tx.prefix.token_id as i64,
                nonce: hex::encode(&tx.prefix.nonce),
                total_mint_limit: tx.prefix.total_mint_limit as i64,
                tombstone_block: tx.prefix.tombstone_block as i64,
                protobuf: encode(tx),
            };

            diesel::insert_into(schema::mint_config_txs::table)
                .values(&obj)
                .execute(conn)?;

            let mint_config_tx_id = diesel::select(last_insert_rowid).get_result::<i32>(conn)?;

            for config in &tx.prefix.configs {
                MintConfig::insert(mint_config_tx_id, config, conn)?;
            }

            Ok(())
        })
    }

    /// Get the most recent MintConfigTx for a given token id that was active
    /// before a given block index.
    pub fn most_recent_for_token(
        block_index: BlockIndex,
        token_id: TokenId,
        conn: &Conn,
    ) -> Result<Option<MintConfigTx>, Error> {
        Ok(mint_config_txs::table
            .filter(schema::mint_config_txs::token_id.eq(*token_id as i64))
            .filter(schema::mint_config_txs::block_index.lt(block_index as i64))
            .order_by(schema::mint_config_txs::block_index.desc())
            .limit(1)
            .first::<MintConfigTx>(conn)
            .optional()?)
    }

    /// Get the total amount minted by all configurations in this MintConfigTx.
    pub fn get_total_minted_before_block(
        &self,
        block_index: BlockIndex,
        conn: &Conn,
    ) -> Result<u64, Error> {
        // Note: We sum in Rust and not Sqlite due to Sqlite not properly supporting
        // unsigned ints.
        // We default our id to 0 since SQLite auto-inc values start at 1.
        let mint_amounts: Vec<i64> = mint_txs::table
            .inner_join(mint_configs::table)
            .filter(mint_configs::mint_config_tx_id.eq(self.id.unwrap_or_default()))
            .filter(mint_txs::block_index.lt(block_index as i64))
            .select(mint_txs::amount)
            .load::<i64>(conn)?;
        Ok(mint_amounts.into_iter().map(|val| val as u64).sum())
    }
}
