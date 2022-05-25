// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Convert to/from mc_mint_auditor_api::Counters.

use crate::db::Counters;

/// Convert Counters --> mc_mint_auditor_api::Counters
impl From<&Counters> for mc_mint_auditor_api::Counters {
    fn from(src: &Counters) -> Self {
        let mut dst = mc_mint_auditor_api::Counters::new();
        dst.set_num_blocks_synced(src.num_blocks_synced as u64);
        dst.set_num_burns_exceeding_balance(src.num_burns_exceeding_balance as u64);
        dst.set_num_mint_txs_without_matching_mint_config(
            src.num_mint_txs_without_matching_mint_config as u64,
        );
        dst
    }
}

/// Convert mc_mint_auditor_api::Counters --> Counters
impl From<&mc_mint_auditor_api::Counters> for Counters {
    fn from(src: &mc_mint_auditor_api::Counters) -> Self {
        Self {
            id: 0,
            num_blocks_synced: src.get_num_blocks_synced() as i64,
            num_burns_exceeding_balance: src.get_num_burns_exceeding_balance() as i64,
            num_mint_txs_without_matching_mint_config: src
                .get_num_mint_txs_without_matching_mint_config()
                as i64,
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
        };

        // Converting should be the identity function.
        {
            let external = mc_mint_auditor_api::Counters::from(&source);
            let recovered = Counters::from(&external);
            assert_eq!(source, recovered);
        }
    }
}
