// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Convert to/from mc_mint_auditor_api::Counters.

use crate::db::Counters;

/// Convert Counters --> mc_mint_auditor_api::Counters
impl From<&Counters> for mc_mint_auditor_api::Counters {
    fn from(src: &Counters) -> Self {
        let mut dst = mc_mint_auditor_api::Counters::new();
        dst.set_num_blocks_synced(src.num_blocks_synced());
        dst.set_num_burns_exceeding_balance(src.num_burns_exceeding_balance());
        dst.set_num_mint_txs_without_matching_mint_config(
            src.num_mint_txs_without_matching_mint_config(),
        );
        dst.set_num_mismatching_mints_and_deposits(src.num_mismatching_mints_and_deposits());
        dst.set_num_mismatching_burns_and_withdrawals(src.num_mismatching_burns_and_withdrawals());
        dst.set_num_unknown_ethereum_token_deposits(src.num_unknown_ethereum_token_deposits());
        dst.set_num_unknown_ethereum_token_withdrawals(
            src.num_unknown_ethereum_token_withdrawals(),
        );
        dst.set_num_mints_to_unknown_safe(src.num_mints_to_unknown_safe());
        dst.set_num_burns_from_unknown_safe(src.num_burns_from_unknown_safe());
        dst.set_num_unexpected_errors_matching_deposits_to_mints(
            src.num_unexpected_errors_matching_deposits_to_mints(),
        );
        dst.set_num_unexpected_errors_matching_mints_to_deposits(
            src.num_unexpected_errors_matching_mints_to_deposits(),
        );
        dst.set_num_unexpected_errors_matching_withdrawals_to_burns(
            src.num_unexpected_errors_matching_withdrawals_to_burns(),
        );
        dst.set_num_unexpected_errors_matching_burns_to_withdrawals(
            src.num_unexpected_errors_matching_burns_to_withdrawals(),
        );
        dst
    }
}
