// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Convert to/from mc_mint_auditor_api::BlockAuditData.

use crate::db::BlockAuditData;

/// Convert BlockAuditData --> mc_mint_auditor_api::BlockAuditData
impl From<&BlockAuditData> for mc_mint_auditor_api::BlockAuditData {
    fn from(src: &BlockAuditData) -> Self {
        let mut dst = mc_mint_auditor_api::BlockAuditData::new();
        dst.set_block_index(src.block_index());
        dst
    }
}

/// Convert mc_mint_auditor_api::BlockAuditData --> BlockAuditData
impl From<&mc_mint_auditor_api::BlockAuditData> for BlockAuditData {
    fn from(src: &mc_mint_auditor_api::BlockAuditData) -> Self {
        Self {
            block_index: src.get_block_index() as i64,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    // BlockAuditData --> mc_mint_auditor_api::BlockAuditData --> BlockAuditData
    // should be the identity function.
    fn test_convert_block_audit_data() {
        let source = BlockAuditData { block_index: 1234 };

        // Converting should be the identity function.
        {
            let external = mc_mint_auditor_api::BlockAuditData::from(&source);
            let recovered = BlockAuditData::from(&external);
            assert_eq!(source, recovered);
        }
    }
}
