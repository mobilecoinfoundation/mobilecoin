//! Convert to/from blockchain::ArchiveBlock

use crate::blockchain; // , convert::ConversionError

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
