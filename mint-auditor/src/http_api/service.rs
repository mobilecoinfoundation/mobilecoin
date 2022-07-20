// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Mint auditor service for handling http requests

use crate::{
    db::{BlockAuditData, BlockBalance, Counters, MintAuditorDb, MintTx},
    http_api::routes::{CatResponse, TestResponse},
};
use ::std::collections::HashMap;
use displaydoc::Display;
use rocket::serde::Serialize;

/// temp
#[derive(Display, Debug, Serialize)]
pub enum AuditorServiceError {
    /// Error with auditor service
    AuditorServiceError(String),
}

/// temp
pub struct MintAuditorHttpService {}

/// temp
impl MintAuditorHttpService {
    /// temp
    pub fn get_cat(_mint_auditor_db: &MintAuditorDb) -> Result<CatResponse, AuditorServiceError> {
        Ok(CatResponse {
            cat: "meow".to_string(),
        })
    }

    /// temp
    pub fn get_db_test(
        mint_auditor_db: &MintAuditorDb,
    ) -> Result<TestResponse, AuditorServiceError> {
        let conn = mint_auditor_db.get_conn().unwrap();

        let txos = MintTx::find_unaudited_mint_txs(&conn).unwrap();

        Ok(TestResponse {
            num_mints: txos.len() as u64,
        })
    }

    /// get counters
    pub fn get_counters(mint_auditor_db: &MintAuditorDb) -> Result<Counters, AuditorServiceError> {
        let conn = mint_auditor_db.get_conn().unwrap();
        let counters = Counters::get(&conn).unwrap();
        Ok(counters)
    }

    /// blah blah
    pub fn get_block_audit_data(
        block_index: u64,
        mint_auditor_db: &MintAuditorDb,
    ) -> Result<BlockAuditDataResponse, AuditorServiceError> {
        let conn = mint_auditor_db.get_conn().unwrap();

        let block_audit_data = BlockAuditData::get(&conn, block_index).unwrap();
        let balances =
            BlockBalance::get_balances_for_block(&conn, block_audit_data.block_index()).unwrap();

        Ok(BlockAuditDataResponse {
            block_index: block_audit_data.block_index(),
            balances: HashMap::from_iter(
                balances
                    .into_iter()
                    .map(|(token_id, balance)| (*token_id, balance)),
            ),
        })
    }

    /// blah blah
    pub fn get_last_block_audit_data(
        mint_auditor_db: &MintAuditorDb,
    ) -> Result<BlockAuditDataResponse, AuditorServiceError> {
        let conn = mint_auditor_db.get_conn().unwrap();

        let block_audit_data = BlockAuditData::last_block_audit_data(&conn)
            .unwrap()
            .unwrap();
        let balances =
            BlockBalance::get_balances_for_block(&conn, block_audit_data.block_index()).unwrap();

        Ok(BlockAuditDataResponse {
            block_index: block_audit_data.block_index(),
            balances: HashMap::from_iter(
                balances
                    .into_iter()
                    .map(|(token_id, balance)| (*token_id, balance)),
            ),
        })
    }
}

/// block audit data
#[derive(Serialize)]
#[allow(missing_docs)]
pub struct BlockAuditDataResponse {
    // message fields
    pub block_index: u64,
    pub balances: HashMap<u64, u64>,
}

/// counters
#[derive(Serialize)]
#[allow(missing_docs)]
pub struct CountersResponse {
    // message fields
    pub num_blocks_synced: u64,
    pub num_burns_exceeding_balance: u64,
    pub num_mint_txs_without_matching_mint_config: u64,
    pub num_mismatching_mints_and_deposits: u64,
    pub num_mismatching_burns_and_withdrawals: u64,
    pub num_unknown_ethereum_token_deposits: u64,
    pub num_unknown_ethereum_token_withdrawals: u64,
    pub num_mints_to_unknown_safe: u64,
    pub num_burns_from_unknown_safe: u64,
    pub num_unexpected_errors_matching_deposits_to_mints: u64,
    pub num_unexpected_errors_matching_mints_to_deposits: u64,
    pub num_unexpected_errors_matching_withdrawals_to_burns: u64,
    pub num_unexpected_errors_matching_burns_to_withdrawals: u64,
}

impl From<&Counters> for CountersResponse {
    fn from(src: &Counters) -> CountersResponse {
        CountersResponse {
            num_blocks_synced: src.num_blocks_synced(),
            num_burns_exceeding_balance: src.num_burns_exceeding_balance(),
            num_mint_txs_without_matching_mint_config: src
                .num_mint_txs_without_matching_mint_config(),
            num_mismatching_mints_and_deposits: src.num_mismatching_mints_and_deposits(),
            num_mismatching_burns_and_withdrawals: src.num_mismatching_burns_and_withdrawals(),
            num_unknown_ethereum_token_deposits: src.num_unknown_ethereum_token_deposits(),
            num_unknown_ethereum_token_withdrawals: src
                .num_unexpected_errors_matching_burns_to_withdrawals(),
            num_mints_to_unknown_safe: src.num_mints_to_unknown_safe(),
            num_burns_from_unknown_safe: src.num_burns_from_unknown_safe(),
            num_unexpected_errors_matching_deposits_to_mints: src
                .num_unexpected_errors_matching_deposits_to_mints(),
            num_unexpected_errors_matching_mints_to_deposits: src
                .num_unexpected_errors_matching_mints_to_deposits(),
            num_unexpected_errors_matching_withdrawals_to_burns: src
                .num_unexpected_errors_matching_withdrawals_to_burns(),
            num_unexpected_errors_matching_burns_to_withdrawals: src
                .num_unexpected_errors_matching_burns_to_withdrawals(),
        }
    }
}
