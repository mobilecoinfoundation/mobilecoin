use crate::db::{BlockAuditData, Counters, MintAuditorDb};
use mc_common::HashMap;
use mc_transaction_core::TokenId;
use rocket::serde::Serialize;

/// type for auditor db in Rocket state
pub struct AuditorDb(pub MintAuditorDb);

/// block audit data
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

/// counters
#[derive(Serialize, Default, Eq, PartialEq, Debug)]
#[allow(missing_docs)]
pub struct CountersResponse {
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
