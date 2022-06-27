// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Convert to/from mc_mint_auditor_api::Counters.

use crate::db::Counters;

/// Convert Counters --> mc_mint_auditor_api::Counters
impl From<&Counters> for mc_mint_auditor_api::Counters {
    fn from(src: &Counters) -> Self {
        Self {
            num_blocks_synced: src.num_blocks_synced(),
            num_burns_exceeding_balance: src.num_burns_exceeding_balance(),
            num_mint_txs_without_matching_mint_config: src
                .num_mint_txs_without_matching_mint_config(),
            num_mismatching_mints_and_deposits: src.num_mismatching_mints_and_deposits(),
            num_unknown_ethereum_token_deposits: src.num_unknown_ethereum_token_deposits(),
            num_mints_to_unknown_safe: src.num_mints_to_unknown_safe(),
            num_unexpected_errors_matching_deposits_to_mints: src
                .num_unexpected_errors_matching_deposits_to_mints(),
            num_unexpected_errors_matching_mints_to_deposits: src
                .num_unexpected_errors_matching_mints_to_deposits(),
        }
    }
}

/// Convert mc_mint_auditor_api::Counters --> Counters
impl From<&mc_mint_auditor_api::Counters> for Counters {
    fn from(src: &mc_mint_auditor_api::Counters) -> Self {
        Self {
            id: 0,
            num_blocks_synced: src.num_blocks_synced as i64,
            num_burns_exceeding_balance: src.num_burns_exceeding_balance as i64,
            num_mint_txs_without_matching_mint_config: src.num_mint_txs_without_matching_mint_config
                as i64,
            num_mismatching_mints_and_deposits: src.num_mismatching_mints_and_deposits,
            num_unknown_ethereum_token_deposits: src.num_unknown_ethereum_token_deposits,
            num_mints_to_unknown_safe: src.num_mints_to_unknown_safe,
            num_unexpected_errors_matching_deposits_to_mints: src
                .num_unexpected_errors_matching_deposits_to_mints,
            num_unexpected_errors_matching_mints_to_deposits: src
                .num_unexpected_errors_matching_mints_to_deposits,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    // Counters --> mc_mint_auditor_api::Counters --> Counters
    // should be the identity function.
    fn test_convert_block_audit_data() {
        let source = Counters {
            id: 0,
            num_blocks_synced: 10,
            num_burns_exceeding_balance: 20,
            num_mint_txs_without_matching_mint_config: 30,
            num_mismatching_mints_and_deposits: 40,
            num_unknown_ethereum_token_deposits: 50,
            num_mints_to_unknown_safe: 60,
            num_unexpected_errors_matching_deposits_to_mints: 70,
            num_unexpected_errors_matching_mints_to_deposits: 80,
        };

        // Converting should be the identity function.
        {
            let external = mc_mint_auditor_api::Counters::from(&source);
            let recovered = Counters::from(&external);
            assert_eq!(source, recovered);
        }
    }
}
