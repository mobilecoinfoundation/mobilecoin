//! Convert between blockchain::ArchiveBlock and BlockStreamComponents

use crate::BlockStreamComponents;
use mc_api::{blockchain, ConversionError};
use mc_transaction_core::BlockData;
use std::convert::TryFrom;

/// Convert BlockStreamComponents --> blockchain::ArchiveBlock.
impl From<&BlockStreamComponents> for blockchain::ArchiveBlock {
    fn from(src: &BlockStreamComponents) -> Self {
        // TODO(#1682): Include QuorumSet, VerificationReport.
        blockchain::ArchiveBlock::from(&src.block_data)
    }
}

/// Convert from blockchain::ArchiveBlock --> BlockStreamComponents
impl TryFrom<&blockchain::ArchiveBlock> for BlockStreamComponents {
    type Error = ConversionError;

    fn try_from(src: &blockchain::ArchiveBlock) -> Result<Self, Self::Error> {
        let block_data = BlockData::try_from(src)?;
        // TODO(#1682): Include QuorumSet, VerificationReport.
        Ok(BlockStreamComponents {
            block_data,
            quorum_set: None,
            verification_report: None,
        })
    }
}

// Ideally this would be:
//     impl From<&[BlockStreamComponents]> for blockchain::ArchiveBlocks
// but that fails to compile with "error[E0117]: only traits defined in the
// current crate can be implemented for arbitrary types"
/// Convert &\[[BlockStreamComponents]] -> [blockchain::ArchiveBlocks]
#[allow(unused)]
pub fn components_to_archive_blocks(src: &[BlockStreamComponents]) -> blockchain::ArchiveBlocks {
    let mut archive_blocks = blockchain::ArchiveBlocks::new();
    // TODO(#1682): Include QuorumSet, VerificationReport.
    let blocks = src.iter().map(|c| (&c.block_data).into());
    archive_blocks.set_blocks(blocks.collect());
    archive_blocks
}

// Ideally this would be:
//    impl TryFrom<&blockchain::ArchiveBlocks> for Vec<BlockStreamComponents>
// but that fails to compile with "error[E0117]: only traits defined in the
// current crate can be implemented for arbitrary types"
/// Convert blockchain::ArchiveBlocks -> Vec<BlockStreamComponents>
#[allow(unused)]
pub fn archive_blocks_to_components(
    src: &blockchain::ArchiveBlocks,
) -> crate::Result<Vec<BlockStreamComponents>> {
    let blocks_data = Vec::<BlockData>::try_from(src)?;
    // TODO(#1682): Include QuorumSet, VerificationReport.
    let components = blocks_data
        .into_iter()
        .map(|block_data| BlockStreamComponents {
            block_data,
            quorum_set: None,
            verification_report: None,
        })
        .collect();
    Ok(components)
}
