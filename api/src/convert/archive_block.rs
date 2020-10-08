//! Convert to/from blockchain::ArchiveBlock

use crate::{blockchain, convert::ConversionError};
use std::convert::TryFrom;

/// Convert mc_transaction_core::BlockData --> blockchain::ArchiveBlock.
impl From<&mc_transaction_core::BlockData> for blockchain::ArchiveBlock {
    fn from(src: &mc_transaction_core::BlockData) -> Self {
        let bc_block = blockchain::Block::from(src.block());
        let bc_block_contents = blockchain::BlockContents::from(src.contents());

        let mut archive_block_v1 = blockchain::ArchiveBlockV1::new();
        archive_block_v1.set_block(bc_block);
        archive_block_v1.set_block_contents(bc_block_contents);

        if let Some(signature) = src.signature() {
            let bc_signature = blockchain::BlockSignature::from(signature);
            archive_block_v1.set_signature(bc_signature);
        }

        let mut archive_block = blockchain::ArchiveBlock::new();
        archive_block.set_v1(archive_block_v1);

        archive_block
    }
}

/// Convert from blockchain::ArchiveBlock --> mc_transaction_core::BlockData
impl TryFrom<&blockchain::ArchiveBlock> for mc_transaction_core::BlockData {
    type Error = ConversionError;

    fn try_from(src: &blockchain::ArchiveBlock) -> Result<Self, Self::Error> {
        if !src.has_v1() {
            return Err(ConversionError::ObjectMissing);
        }

        let block = mc_transaction_core::Block::try_from(src.get_v1().get_block())?;

        let block_contents =
            mc_transaction_core::BlockContents::try_from(src.get_v1().get_block_contents())?;

        let signature = src
            .get_v1()
            .signature
            .as_ref()
            .map(mc_transaction_core::BlockSignature::try_from)
            .transpose()?;

        if let Some(signature) = signature.as_ref() {
            signature
                .verify(&block)
                .map_err(|_| ConversionError::InvalidSignature)?;
        }

        if block.contents_hash != block_contents.hash() {
            return Err(ConversionError::InvalidContents);
        }

        Ok(mc_transaction_core::BlockData::new(
            block,
            block_contents,
            signature,
        ))
    }
}
