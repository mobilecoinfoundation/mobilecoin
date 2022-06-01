// Copyright (c) 2018-2022 The MobileCoin Foundation

use super::schema::*;
use mc_transaction_core::TokenId;
use serde::{Deserialize, Serialize};

/// Diesel model for the `block_audit_data` table.
/// This stores audit data for a specific block index.
#[derive(Debug, Deserialize, Eq, PartialEq, Queryable, Insertable, Serialize)]
#[table_name = "block_audit_data"]
pub struct BlockAuditData {
    /// Block index.
    pub block_index: i64,
}

impl BlockAuditData {
    /// Get block index.
    pub fn block_index(&self) -> u64 {
        self.block_index as u64
    }
}

/// Diesel model for the `block_balance` table.
/// This stores the balance of each token for a specific block index.
#[derive(Debug, Deserialize, Queryable, Insertable, Serialize)]
#[table_name = "block_balance"]
pub struct BlockBalance {
    /// Block index.
    pub block_index: i64,

    /// Token id.
    pub token_id: i64,

    /// Balanace.
    pub balance: i64,
}

impl BlockBalance {
    /// Get block index.
    pub fn block_index(&self) -> u64 {
        self.block_index as u64
    }

    /// Get token id.
    pub fn token_id(&self) -> TokenId {
        TokenId::from(self.token_id as u64)
    }

    /// Get balance.
    pub fn balance(&self) -> u64 {
        self.balance as u64
    }
}

/// Diesel model for the `counters` table.
/// This stores a bunch of general purpose counters. There is only ever one row
/// in this table.
#[derive(Debug, Default, Deserialize, Eq, PartialEq, Queryable, Insertable, Serialize)]
#[table_name = "counters"]
pub struct Counters {
    /// Id (required to keep Diesel happy).
    pub id: i32,

    /// The number of blocks synced so far.
    pub num_blocks_synced: i64,

    /// The number of burn transactions that exceeded the minted amount.
    pub num_burns_exceeding_balance: i64,

    /// The number of mint transactions that did not match an active mint
    /// configuration.
    pub num_mint_txs_without_matching_mint_config: i64,
}

impl Counters {
    /// Get the number of blocks synced so far.
    pub fn num_blocks_synced(&self) -> u64 {
        self.num_blocks_synced as u64
    }

    /// Get the number of burn transactions that exceeded the minted amount.
    pub fn num_burns_exceeding_balance(&self) -> u64 {
        self.num_burns_exceeding_balance as u64
    }

    /// Get the number of mint transactions that did not match an active mint
    /// configuration.
    pub fn num_mint_txs_without_matching_mint_config(&self) -> u64 {
        self.num_mint_txs_without_matching_mint_config as u64
    }
}
