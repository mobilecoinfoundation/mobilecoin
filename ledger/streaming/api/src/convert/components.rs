// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Convert between Rust and proto representations of BlockStreamComponents.

use crate::{streaming_blocks::BlockWithQuorumSet, BlockStreamComponents};
use mc_api::ConversionError;
use std::convert::{TryFrom, TryInto};

impl From<&BlockStreamComponents> for BlockWithQuorumSet {
    fn from(data: &BlockStreamComponents) -> Self {
        let mut proto = BlockWithQuorumSet::new();
        proto.set_block((&data.block_data).into());
        proto.set_quorum_set((&data.quorum_set).into());
        proto.set_report((&data.verification_report).into());
        proto
    }
}

impl TryFrom<&BlockWithQuorumSet> for BlockStreamComponents {
    type Error = ConversionError;

    fn try_from(proto: &BlockWithQuorumSet) -> Result<Self, Self::Error> {
        let block_data = proto.get_block().try_into()?;
        let quorum_set = proto.get_quorum_set().try_into()?;
        let verification_report = proto.get_report().try_into()?;
        Ok(BlockStreamComponents {
            block_data,
            quorum_set,
            verification_report,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::make_quorum_set;
    use mc_attest_core::VerificationReport;
    use mc_transaction_core::{Block, BlockContents, BlockData};

    #[test]
    fn test_roundtrip() {
        let contents = BlockContents::new(vec![], vec![]);
        let block = Block::new_origin_block(&[]);
        let block_data = BlockData::new(block, contents, None);
        let quorum_set = make_quorum_set();
        let verification_report = VerificationReport::default();
        let data = BlockStreamComponents {
            block_data,
            quorum_set,
            verification_report,
        };

        let proto = BlockWithQuorumSet::from(&data);
        let data2 = BlockStreamComponents::try_from(&proto).expect("Failed to parse proto");
        assert_eq!(data, data2);

        let proto2 = BlockWithQuorumSet::from(&data2);
        assert_eq!(proto, proto2);
    }
}
