// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Convert to/from mc_mint_auditor_api::BlockAuditData.

use crate::BlockAuditData;

/// Convert BlockAuditData --> mc_mint_auditor_api::BlockAuditData
impl From<&BlockAuditData> for mc_mint_auditor_api::BlockAuditData {
    fn from(src: &BlockAuditData) -> Self {
        let mut dst = mc_mint_auditor_api::BlockAuditData::new();
        dst.set_balance_map(src.balance_map.clone().into_iter().collect());
        dst
    }
}

/// Convert mc_mint_auditor_api::BlockAuditData --> BlockAuditData
impl From<&mc_mint_auditor_api::BlockAuditData> for BlockAuditData {
    fn from(src: &mc_mint_auditor_api::BlockAuditData) -> Self {
        Self {
            balance_map: src.get_balance_map().clone().into_iter().collect(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mc_util_serial::{decode, encode};
    use protobuf::Message;
    use std::{collections::BTreeMap, iter::FromIterator};

    #[test]
    // BlockAuditData --> mc_mint_auditor_api::BlockAuditData --> BlockAuditData
    // should be the identity function.
    fn test_convert_block_audit_data() {
        let source = BlockAuditData {
            balance_map: BTreeMap::from_iter([(1, 2), (3, 4)]),
        };

        // decode(encode(source)) should be the identity function.
        {
            let bytes = encode(&source);
            let recovered = decode(&bytes).unwrap();
            assert_eq!(source, recovered);
        }

        // Converting should be the identity function.
        {
            let external = mc_mint_auditor_api::BlockAuditData::from(&source);
            let recovered = BlockAuditData::from(&external);
            assert_eq!(source, recovered);
        }

        // Encoding with prost, decoding with protobuf should be the identity
        // function.
        {
            let bytes = encode(&source);
            let recovered = mc_mint_auditor_api::BlockAuditData::parse_from_bytes(&bytes).unwrap();
            assert_eq!(
                recovered,
                mc_mint_auditor_api::BlockAuditData::from(&source)
            );
        }

        // Encoding with protobuf, decoding with prost should be the identity function.
        {
            let external = mc_mint_auditor_api::BlockAuditData::from(&source);
            let bytes = external.write_to_bytes().unwrap();
            let recovered: BlockAuditData = decode(&bytes).unwrap();
            assert_eq!(source, recovered);
        }
    }
}
