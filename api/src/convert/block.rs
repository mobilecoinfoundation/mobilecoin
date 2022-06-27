//! Convert to/from blockchain::Block

use crate::{blockchain, ConversionError};
use mc_blockchain_types::Block;

/// Convert Block --> blockchain::Block.
impl From<&Block> for blockchain::Block {
    fn from(src: &Block) -> Self {
        Self {
            id: Some((&src.id).into()),
            version: src.version,
            parent_id: Some((&src.parent_id).into()),
            index: src.index,
            cumulative_txo_count: src.cumulative_txo_count,
            root_element: Some((&src.root_element).into()),
            contents_hash: Some((&src.contents_hash).into()),
        }
    }
}

/// Convert blockchain::Block --> Block.
impl TryFrom<&blockchain::Block> for Block {
    type Error = ConversionError;

    fn try_from(value: &blockchain::Block) -> Result<Self, Self::Error> {
        let block_id = value
            .id
            .as_ref()
            .ok_or(ConversionError::ObjectMissing)?
            .try_into()?;
        let parent_id = value
            .parent_id
            .as_ref()
            .ok_or(ConversionError::ObjectMissing)?
            .try_into()?;
        let root_element = value
            .root_element
            .as_ref()
            .ok_or(ConversionError::ObjectMissing)?
            .try_into()?;
        let contents_hash = value
            .contents_hash
            .as_ref()
            .ok_or(ConversionError::ObjectMissing)?
            .try_into()?;

        Ok(Block {
            id: block_id,
            version: value.version,
            parent_id,
            index: value.index,
            cumulative_txo_count: value.cumulative_txo_count,
            root_element,
            contents_hash,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mc_blockchain_types::{BlockContentsHash, BlockID};
    use mc_transaction_core::{
        membership_proofs::Range,
        tx::{TxOutMembershipElement, TxOutMembershipHash},
    };
    use mc_util_serial::round_trip_message;

    #[test]
    fn test_block_round_trip() {
        let source_block = Block {
            id: BlockID::try_from(&[2u8; 32][..]).unwrap(),
            version: 1,
            parent_id: BlockID::try_from(&[1u8; 32][..]).unwrap(),
            index: 99,
            cumulative_txo_count: 400,
            root_element: TxOutMembershipElement {
                range: Range::new(10, 20).unwrap(),
                hash: TxOutMembershipHash::from([12u8; 32]),
            },
            contents_hash: BlockContentsHash::try_from(&[66u8; 32][..]).unwrap(),
        };

        round_trip_message::<Block, blockchain::Block>(&source_block);
    }
}
