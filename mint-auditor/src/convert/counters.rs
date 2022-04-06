// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Convert to/from mc_mint_auditor_api::Counters.

use crate::Counters;

/// Convert Counters --> mc_mint_auditor_api::Counters
impl From<&Counters> for mc_mint_auditor_api::Counters {
    fn from(src: &Counters) -> Self {
        let mut dst = mc_mint_auditor_api::Counters::new();
        dst.set_num_blocks_synced(src.num_blocks_synced);
        dst.set_num_burns_exceeding_balance(src.num_burns_exceeding_balance);
        dst.set_num_mint_txs_without_matching_mint_config(
            src.num_mint_txs_without_matching_mint_config,
        );
        dst
    }
}

/// Convert mc_mint_auditor_api::Counters --> Counters
impl From<&mc_mint_auditor_api::Counters> for Counters {
    fn from(src: &mc_mint_auditor_api::Counters) -> Self {
        Self {
            num_blocks_synced: src.get_num_blocks_synced(),
            num_burns_exceeding_balance: src.get_num_burns_exceeding_balance(),
            num_mint_txs_without_matching_mint_config: src
                .get_num_mint_txs_without_matching_mint_config(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mc_util_serial::{decode, encode};
    use protobuf::Message;

    #[test]
    // Counters --> mc_mint_auditor_api::Counters --> Counters
    // should be the identity function.
    fn test_convert_block_audit_data() {
        let source = Counters {
            num_blocks_synced: 10,
            num_burns_exceeding_balance: 20,
            num_mint_txs_without_matching_mint_config: 30,
        };

        // decode(encode(source)) should be the identity function.
        {
            let bytes = encode(&source);
            let recovered = decode(&bytes).unwrap();
            assert_eq!(source, recovered);
        }

        // Converting should be the identity function.
        {
            let external = mc_mint_auditor_api::Counters::from(&source);
            let recovered = Counters::from(&external);
            assert_eq!(source, recovered);
        }

        // Encoding with prost, decoding with protobuf should be the identity
        // function.
        {
            let bytes = encode(&source);
            let recovered = mc_mint_auditor_api::Counters::parse_from_bytes(&bytes).unwrap();
            assert_eq!(recovered, mc_mint_auditor_api::Counters::from(&source));
        }

        // Encoding with protobuf, decoding with prost should be the identity function.
        {
            let external = mc_mint_auditor_api::Counters::from(&source);
            let bytes = external.write_to_bytes().unwrap();
            let recovered: Counters = decode(&bytes).unwrap();
            assert_eq!(source, recovered);
        }
    }
}
