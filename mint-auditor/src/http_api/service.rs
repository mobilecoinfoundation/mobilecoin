// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Mint auditor service for handling http requests

use crate::{
    db::{BlockAuditData, BlockBalance, Counters, MintAuditorDb},
    http_api::api_types::BlockAuditDataResponse,
    Error,
};
use ::std::collections::HashMap;

/// Service for handling auditor requests
pub struct MintAuditorHttpService {}

/// Service for handling auditor requests
impl MintAuditorHttpService {
    /// get counters
    pub fn get_counters(mint_auditor_db: &MintAuditorDb) -> Result<Counters, Error> {
        let conn = mint_auditor_db.get_conn()?;
        Counters::get(&conn)
    }

    /// Get the audit data for a target block
    pub fn get_block_audit_data(
        block_index: u64,
        mint_auditor_db: &MintAuditorDb,
    ) -> Result<BlockAuditDataResponse, Error> {
        let conn = mint_auditor_db.get_conn()?;

        let block_audit_data = BlockAuditData::get(&conn, block_index)?;

        let balances = BlockBalance::get_balances_for_block(&conn, block_audit_data.block_index())?;

        Ok(BlockAuditDataResponse {
            block_index: block_audit_data.block_index(),
            balances: HashMap::from_iter(
                balances
                    .into_iter()
                    .map(|(token_id, balance)| (*token_id, balance)),
            ),
        })
    }

    /// Get the audit data for the last synced block.
    pub fn get_last_block_audit_data(
        mint_auditor_db: &MintAuditorDb,
    ) -> Result<BlockAuditDataResponse, Error> {
        let conn = mint_auditor_db.get_conn()?;

        let block_audit_data_option = BlockAuditData::last_block_audit_data(&conn)?;

        if let Some(block_audit_data) = block_audit_data_option {
            let balances =
                BlockBalance::get_balances_for_block(&conn, block_audit_data.block_index())?;

            return Ok(BlockAuditDataResponse {
                block_index: block_audit_data.block_index(),
                balances: HashMap::from_iter(
                    balances
                        .into_iter()
                        .map(|(token_id, balance)| (*token_id, balance)),
                ),
            });
        }

        Err(Error::NotFound)
    }
}
