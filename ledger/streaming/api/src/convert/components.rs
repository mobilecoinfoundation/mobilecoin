// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Convert between Rust and proto representations of BlockStreamComponents.

use crate::{streaming_blocks::BlockWithQuorumSet, BlockStreamComponents};
use mc_api::ConversionError;
use mc_attest_core::VerificationReport;
use mc_consensus_scp::QuorumSet;
use std::convert::{TryFrom, TryInto};

impl From<&BlockStreamComponents> for BlockWithQuorumSet {
    fn from(data: &BlockStreamComponents) -> Self {
        let mut proto = BlockWithQuorumSet::new();
        proto.set_block((&data.block_data).into());
        // TODO(#1682): Error when fields are missing.
        if let Some(ref quorum_set) = data.quorum_set {
            proto.set_quorum_set(quorum_set.into());
        }
        if let Some(ref report) = data.verification_report {
            proto.set_report(report.into());
        }
        proto
    }
}

impl TryFrom<&BlockWithQuorumSet> for BlockStreamComponents {
    type Error = ConversionError;

    fn try_from(proto: &BlockWithQuorumSet) -> Result<Self, Self::Error> {
        let block_data = proto.get_block().try_into()?;
        // TODO(#1682): Error when fields are missing.
        let quorum_set = proto
            .quorum_set
            .as_ref()
            .map(QuorumSet::try_from)
            .transpose()?;
        let verification_report = proto
            .report
            .as_ref()
            .map(VerificationReport::try_from)
            .transpose()?;
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
    use mc_transaction_core::{Block, BlockContents, BlockData};

    #[test]
    fn test_roundtrip() {
        let contents = BlockContents::default();
        let block = Block::new_origin_block(&[]);
        let block_data = BlockData::new(block, contents, None);
        let quorum_set = make_quorum_set();
        let data = BlockStreamComponents {
            block_data,
            quorum_set: Some(quorum_set),
            verification_report: None,
        };

        let proto = BlockWithQuorumSet::from(&data);
        let data2 = BlockStreamComponents::try_from(&proto).expect("Failed to parse proto");
        assert_eq!(data, data2);

        let proto2 = BlockWithQuorumSet::from(&data2);
        assert_eq!(proto, proto2);
    }
}
