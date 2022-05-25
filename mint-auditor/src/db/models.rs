// Copyright (c) 2018-2022 The MobileCoin Foundation

use super::schema::*;
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, Eq, PartialEq, Queryable, Insertable, Serialize)]
#[table_name = "block_audit_data"]
pub struct BlockAuditData {
    pub block_index: i64,
}

#[derive(Debug, Deserialize, Queryable, Insertable, Serialize)]
#[table_name = "block_balance"]
pub struct BlockBalance {
    pub block_index: i64,
    pub token_id: i64,
    pub balance: i64,
}

#[derive(Debug, Default, Deserialize, Eq, PartialEq, Queryable, Insertable, Serialize)]
#[table_name = "counters"]
pub struct Counters {
    pub id: i32,
    pub num_blocks_synced: i64,
    pub num_burns_exceeding_balance: i64,
    pub num_mint_txs_without_matching_mint_config: i64,
}
