// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Convert to/from mc_reserve_auditor_api::GnosisSafeTx.

use crate::db::GnosisSafeTx as DbGnosisSafeTx;
use mc_reserve_auditor_api::GnosisSafeTx as ProtoGnosisSafeTx;

/// Convert DbGnosisSafeTx --> ProtoGnosisSafeTx
impl From<&DbGnosisSafeTx> for ProtoGnosisSafeTx {
    fn from(src: &DbGnosisSafeTx) -> Self {
        let mut dst = Self::new();
        dst.set_raw_tx_json(src.raw_tx_json.clone());
        dst.set_eth_tx_hash(src.eth_tx_hash.clone());
        dst
    }
}

/// Convert ProtoGnosisSafeTx --> DbGnosisSafeTx
impl From<&ProtoGnosisSafeTx> for DbGnosisSafeTx {
    fn from(src: &ProtoGnosisSafeTx) -> Self {
        Self {
            eth_tx_hash: src.get_eth_tx_hash().to_string(),
            raw_tx_json: src.get_raw_tx_json().to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    // DbGnosisSafeTx --> ProtoGnosisSafeTx --> DbGnosisSafeTx should be the
    // identity function.
    fn test_convert_gnosis_safe_tx() {
        let source = DbGnosisSafeTx {
            eth_tx_hash: "0x0e781edb7739aa88ad2ffb6a69aab46ff9e32dbd0f0c87e4006a176838b075d2"
                .to_string(),
            raw_tx_json: "{\"test\": 10}".to_string(),
        };

        // Converting should be the identity function.
        {
            let external = ProtoGnosisSafeTx::from(&source);
            let recovered = DbGnosisSafeTx::from(&external);
            assert_eq!(source, recovered);
        }
    }
}
