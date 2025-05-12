// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Convert between BlockData and ArchiveBlock.

use crate::{
    blockchain::{archive_block, ArchiveBlock, ArchiveBlockV1, ArchiveBlocks},
    ConversionError,
};
use mc_blockchain_types::{BlockContents, BlockData, BlockMetadata, BlockSignature};

/// Convert BlockData --> ArchiveBlock.
impl From<&BlockData> for ArchiveBlock {
    fn from(src: &BlockData) -> Self {
        Self {
            block: archive_block::Block::V1(ArchiveBlockV1 {
                block: Some(src.block().into()),
                block_contents: Some(src.contents().into()),
                signature: src.signature().map(|s| s.into()),
                metadata: src.metadata().map(|m| m.into()),
            })
            .into(),
        }
    }
}

/// Convert from ArchiveBlock --> BlockData
impl TryFrom<&ArchiveBlock> for BlockData {
    type Error = ConversionError;

    fn try_from(src: &ArchiveBlock) -> Result<Self, Self::Error> {
        let Some(archive_block::Block::V1(archive_block_v1)) = src.block.as_ref() else {
            return Err(ConversionError::ObjectMissing);
        };

        let block = archive_block_v1
            .block
            .as_ref()
            .unwrap_or(&Default::default())
            .try_into()?;
        let block_contents = BlockContents::try_from(
            archive_block_v1
                .block_contents
                .as_ref()
                .unwrap_or(&Default::default()),
        )?;

        let signature = archive_block_v1
            .signature
            .as_ref()
            .map(BlockSignature::try_from)
            .transpose()?;
        if let Some(signature) = signature.as_ref() {
            signature.verify(&block)?;
        }

        let metadata = archive_block_v1
            .metadata
            .as_ref()
            .map(BlockMetadata::try_from) // also verifies its signature.
            .transpose()?;

        if block.contents_hash == block_contents.hash() && block.is_block_id_valid() {
            Ok(BlockData::new(block, block_contents, signature, metadata))
        } else {
            Err(ConversionError::InvalidContents)
        }
    }
}

/// Convert &[BlockData] -> ArchiveBlocks
impl From<&[BlockData]> for ArchiveBlocks {
    fn from(src: &[BlockData]) -> Self {
        Self {
            blocks: src.iter().map(|block| block.into()).collect(),
        }
    }
}

/// Convert ArchiveBlocks -> Vec<BlockData>
impl TryFrom<&ArchiveBlocks> for Vec<BlockData> {
    type Error = ConversionError;

    fn try_from(src: &ArchiveBlocks) -> Result<Self, Self::Error> {
        let blocks_data = src
            .blocks
            .iter()
            .map(BlockData::try_from)
            .collect::<Result<Vec<_>, ConversionError>>()?;

        // Ensure blocks_data form a legitimate chain of blocks.
        if blocks_data
            .iter()
            // Verify that the block ID is consistent with the cached parent ID.
            .all(|data| data.block().is_block_id_valid())
            && blocks_data
                .windows(2)
                // Verify that the cached parent ID matches the previous block's ID.
                .all(|window| window[1].block().parent_id == window[0].block().id)
        {
            Ok(blocks_data)
        } else {
            Err(ConversionError::InvalidContents)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mc_blockchain_test_utils::get_blocks;
    use mc_blockchain_types::{Block, BlockVersion};
    use mc_util_test_helper::get_seeded_rng;
    use mc_util_zip_exact::zip_exact;

    fn generate_test_blocks_data(num_blocks: usize) -> Vec<BlockData> {
        get_blocks(
            BlockVersion::MAX,
            num_blocks,
            5,
            1,
            2,
            42,
            None,
            &mut get_seeded_rng(),
        )
    }

    #[test]
    // BlockData <--> ArchiveBlock
    fn test_archive_block() {
        let block_data = generate_test_blocks_data(2).pop().unwrap();

        // BlockData -> ArchiveBlock
        let archive_block = ArchiveBlock::from(&block_data);
        let archive_block::Block::V1(archive_block_v1) = archive_block.block.as_ref().unwrap();
        assert_eq!(
            block_data.block(),
            &Block::try_from(archive_block_v1.block.as_ref().unwrap()).unwrap(),
        );
        assert_eq!(
            block_data.contents(),
            &BlockContents::try_from(archive_block_v1.block_contents.as_ref().unwrap()).unwrap()
        );
        assert_eq!(
            block_data.signature().cloned().unwrap(),
            BlockSignature::try_from(archive_block_v1.signature.as_ref().unwrap()).unwrap()
        );
        assert_eq!(
            block_data.metadata().cloned().unwrap(),
            BlockMetadata::try_from(archive_block_v1.metadata.as_ref().unwrap()).unwrap()
        );

        // ArchiveBlock -> BlockData
        let block_data2 = BlockData::try_from(&archive_block).unwrap();
        assert_eq!(block_data, block_data2);
    }

    #[test]
    // Attempting to convert an ArchiveBlock with invalid signature or contents
    // should fail.
    fn try_from_blockchain_archive_block_rejects_invalid() {
        let block_data = generate_test_blocks_data(2).pop().unwrap();

        // ArchiveBlock with invalid signature cannot be converted back to BlockData
        {
            let mut archive_block = ArchiveBlock::from(&block_data);
            let archive_block::Block::V1(ref mut archive_block_v1) =
                archive_block.block.as_mut().unwrap();
            archive_block_v1
                .signature
                .as_mut()
                .unwrap()
                .signature
                .as_mut()
                .unwrap()
                .data[0] += 1;
            assert_eq!(
                BlockData::try_from(&archive_block),
                Err(ConversionError::InvalidSignature)
            );
        }

        // ArchiveBlock with invalid metadata cannot be converted back to BlockData
        {
            let mut archive_block = ArchiveBlock::from(&block_data);
            let archive_block::Block::V1(ref mut archive_block_v1) =
                archive_block.block.as_mut().unwrap();
            archive_block_v1
                .metadata
                .as_mut()
                .unwrap()
                .contents
                .as_mut()
                .unwrap()
                .quorum_set
                .as_mut()
                .unwrap()
                .threshold += 1;
            assert_eq!(
                BlockData::try_from(&archive_block),
                Err(ConversionError::InvalidSignature)
            );
        }

        // ArchiveBlock with invalid contents cannot be converted back to BlockData
        {
            let mut archive_block = ArchiveBlock::from(&block_data);
            let archive_block::Block::V1(ref mut archive_block_v1) =
                archive_block.block.as_mut().unwrap();
            archive_block_v1.block_contents.as_mut().unwrap().key_images = vec![];
            assert_eq!(
                BlockData::try_from(&archive_block),
                Err(ConversionError::InvalidContents)
            );
        }
    }

    #[test]
    // Vec<BlockData> <--> ArchiveBlocks
    fn test_archive_blocks() {
        let blocks_data = generate_test_blocks_data(10);

        // Vec<BlockData> -> ArchiveBlocks
        let archive_blocks = ArchiveBlocks::from(blocks_data.as_slice());
        for (block_data, archive_block) in
            zip_exact(blocks_data.iter(), archive_blocks.blocks.iter()).unwrap()
        {
            let archive_block::Block::V1(archive_block_v1) = archive_block.block.as_ref().unwrap();
            assert_eq!(
                block_data.block(),
                &Block::try_from(archive_block_v1.block.as_ref().unwrap()).unwrap(),
            );
            assert_eq!(
                block_data.contents(),
                &BlockContents::try_from(archive_block_v1.block_contents.as_ref().unwrap())
                    .unwrap()
            );
            assert_eq!(
                block_data.signature().cloned().unwrap(),
                BlockSignature::try_from(archive_block_v1.signature.as_ref().unwrap()).unwrap()
            );
            assert_eq!(
                block_data.metadata().cloned().unwrap(),
                BlockMetadata::try_from(archive_block_v1.metadata.as_ref().unwrap()).unwrap()
            );
        }

        // ArchiveBlocks -> Vec<BlockData>
        let blocks_data2 = Vec::<BlockData>::try_from(&archive_blocks).unwrap();
        assert_eq!(blocks_data, blocks_data2);
    }

    #[test]
    // ArchiveBlocks -> Vec<BlockData> should fail if the blocks do not form a
    // proper chain.
    fn test_try_from_blockchain_archive_blocks_rejects_invalid() {
        let blocks_data = generate_test_blocks_data(10);
        let mut archive_blocks = ArchiveBlocks::from(blocks_data.as_slice());
        archive_blocks.blocks.remove(5);

        assert_eq!(
            Vec::<BlockData>::try_from(&archive_blocks),
            Err(ConversionError::InvalidContents),
        );
    }
}
