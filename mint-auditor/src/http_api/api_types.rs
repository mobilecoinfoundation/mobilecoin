// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Request and response types

use crate::db::{AuditedMint, BlockAuditData, GnosisSafeDeposit, MintTx};
use mc_common::HashMap;
use mc_transaction_core::TokenId;
use rocket::serde::Serialize;

/// Block audit data
#[derive(Serialize)]
#[allow(missing_docs)]
pub struct BlockAuditDataResponse {
    pub block_index: u64,
    pub balances: HashMap<u64, u64>,
}

impl BlockAuditDataResponse {
    /// Create a new BlockAuditDataResponse from block index and balance
    pub fn new(block_audit_data: BlockAuditData, balances: HashMap<TokenId, u64>) -> Self {
        Self {
            block_index: block_audit_data.block_index(),
            balances: balances
                .into_iter()
                .map(|(token_id, balance)| (*token_id, balance))
                .collect(),
        }
    }
}

/// Audited mint with corresponding mint tx and gnosis safe deposit
#[derive(Serialize, Debug, Eq, PartialEq)]
#[allow(missing_docs)]
pub struct AuditedMintResponse {
    pub audited: AuditedMint,
    pub mint: MintTx,
    pub deposit: GnosisSafeDeposit,
}
