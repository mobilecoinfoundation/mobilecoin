// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Convert between BlockData and ArchiveBlock.

use crate::{
    blockchain::{ArchiveBlock, ArchiveBlocks},
    ConversionError,
};
use mc_blockchain_types::{BlockContents, BlockData, BlockMetadata, BlockSignature};

/// Convert BlockData --> ArchiveBlock.
impl From<&BlockData> for ArchiveBlock {
    fn from(src: &BlockData) -> Self {
        let mut archive_block = ArchiveBlock::new();
        let archive_block_v1 = archive_block.mut_v1();
        archive_block_v1.set_block(src.block().into());
        archive_block_v1.set_block_contents(src.contents().into());

        if let Some(signature) = src.signature() {
            archive_block_v1.set_signature(signature.into());
        }

        if let Some(metadata) = src.metadata() {
            archive_block_v1.set_metadata(metadata.into());
        }

        archive_block
    }
}

/// Convert from ArchiveBlock --> BlockData
impl TryFrom<&ArchiveBlock> for BlockData {
    type Error = ConversionError;

    fn try_from(src: &ArchiveBlock) -> Result<Self, Self::Error> {
        if !src.has_v1() {
            return Err(ConversionError::ObjectMissing);
        }
        let archive_block_v1 = src.get_v1();

        let block = archive_block_v1.get_block().try_into()?;
        let block_contents = BlockContents::try_from(archive_block_v1.get_block_contents())?;

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
        let mut archive_blocks = ArchiveBlocks::new();
        archive_blocks.set_blocks(src.iter().map(ArchiveBlock::from).collect());
        archive_blocks
    }
}

/// Convert ArchiveBlocks -> Vec<BlockData>
impl TryFrom<&ArchiveBlocks> for Vec<BlockData> {
    type Error = ConversionError;

    fn try_from(src: &ArchiveBlocks) -> Result<Self, Self::Error> {
        let blocks_data = src
            .get_blocks()
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
    use mc_blockchain_test_utils::make_block_metadata;
    use mc_blockchain_types::{
        Block, BlockContents, BlockData, BlockID, BlockSignature, BlockVersion,
    };
    use mc_crypto_keys::{Ed25519Private, RistrettoPublic};
    use mc_transaction_core::{
        encrypted_fog_hint::ENCRYPTED_FOG_HINT_LEN,
        membership_proofs::Range,
        ring_signature::KeyImage,
        tokens::Mob,
        tx::{TxOut, TxOutMembershipElement, TxOutMembershipHash},
        Amount, MaskedAmount, Token,
    };
    use mc_util_from_random::FromRandom;
    use mc_util_zip_exact::zip_exact;
    use rand::{rngs::StdRng, SeedableRng};

    fn generate_test_blocks_data(num_blocks: u64) -> Vec<BlockData> {
        let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);
        let mut blocks_data = Vec::new();
        let mut last_block: Option<Block> = None;

        for block_idx in 0..num_blocks {
            let amount = Amount {
                value: 1u64 << 13,
                token_id: Mob::ID,
            };
            let tx_out = TxOut {
                masked_amount: MaskedAmount::new(amount, &RistrettoPublic::from_random(&mut rng))
                    .unwrap(),
                target_key: RistrettoPublic::from_random(&mut rng).into(),
                public_key: RistrettoPublic::from_random(&mut rng).into(),
                e_fog_hint: (&[0u8; ENCRYPTED_FOG_HINT_LEN]).into(),
                e_memo: None,
            };
            let key_image = KeyImage::from(block_idx);

            let parent_block_id = last_block
                .map(|block| block.id)
                .unwrap_or_else(|| BlockID::try_from(&[1u8; 32][..]).unwrap());

            let block_contents = BlockContents {
                key_images: vec![key_image],
                outputs: vec![tx_out.clone()],
                ..Default::default()
            };
            let block = Block::new(
                BlockVersion::ZERO,
                &parent_block_id,
                99 + block_idx,
                400 + block_idx,
                &TxOutMembershipElement {
                    range: Range::new(10, 20).unwrap(),
                    hash: TxOutMembershipHash::from([12u8; 32]),
                },
                &block_contents,
            );

            last_block = Some(block.clone());

            let signer = Ed25519Private::from_random(&mut rng);
            let signature =
                BlockSignature::from_block_and_keypair(&block, &(signer.into())).unwrap();

            let metadata = make_block_metadata(block.id.clone(), &mut rng);
            let block_data = BlockData::new(block, block_contents, signature, metadata);
            blocks_data.push(block_data);
        }

        blocks_data
    }

    #[test]
    // BlockData <--> ArchiveBlock
    fn test_archive_block() {
        let block_data = generate_test_blocks_data(2).pop().unwrap();

        // BlockData -> ArchiveBlock
        let archive_block = ArchiveBlock::from(&block_data);
        assert_eq!(
            block_data.block(),
            &Block::try_from(archive_block.get_v1().get_block()).unwrap(),
        );
        assert_eq!(
            block_data.contents(),
            &BlockContents::try_from(archive_block.get_v1().get_block_contents()).unwrap()
        );
        assert_eq!(
            block_data.signature().cloned().unwrap(),
            BlockSignature::try_from(archive_block.get_v1().get_signature()).unwrap()
        );
        assert_eq!(
            block_data.metadata().cloned().unwrap(),
            BlockMetadata::try_from(archive_block.get_v1().get_metadata()).unwrap()
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
            archive_block
                .mut_v1()
                .mut_signature()
                .mut_signature()
                .mut_data()[0] += 1;
            assert_eq!(
                BlockData::try_from(&archive_block),
                Err(ConversionError::InvalidSignature)
            );
        }

        // ArchiveBlock with invalid metadata cannot be converted back to BlockData
        {
            let mut archive_block = ArchiveBlock::from(&block_data);
            archive_block
                .mut_v1()
                .mut_metadata()
                .mut_contents()
                .mut_quorum_set()
                .threshold += 1;
            assert_eq!(
                BlockData::try_from(&archive_block),
                Err(ConversionError::InvalidSignature)
            );
        }

        // ArchiveBlock with invalid contents cannot be converted back to BlockData
        {
            let mut archive_block = ArchiveBlock::from(&block_data);
            archive_block
                .mut_v1()
                .mut_block_contents()
                .clear_key_images();
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
            zip_exact(blocks_data.iter(), archive_blocks.get_blocks().iter()).unwrap()
        {
            assert_eq!(
                block_data.block(),
                &Block::try_from(archive_block.get_v1().get_block()).unwrap(),
            );
            assert_eq!(
                block_data.contents(),
                &BlockContents::try_from(archive_block.get_v1().get_block_contents()).unwrap()
            );
            assert_eq!(
                block_data.signature().cloned().unwrap(),
                BlockSignature::try_from(archive_block.get_v1().get_signature()).unwrap()
            );
            assert_eq!(
                block_data.metadata().cloned().unwrap(),
                BlockMetadata::try_from(archive_block.get_v1().get_metadata()).unwrap()
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
        archive_blocks.mut_blocks().remove(5);

        assert_eq!(
            Vec::<BlockData>::try_from(&archive_blocks),
            Err(ConversionError::InvalidContents),
        );
    }
}
