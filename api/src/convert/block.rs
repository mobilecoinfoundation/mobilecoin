// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Convert to/from blockchain::Block

use crate::{blockchain, ConversionError};
use mc_blockchain_types::{Block, BlockContentsHash, BlockID};
use mc_transaction_core::tx::TxOutMembershipElement;

/// Convert Block --> blockchain::Block.
impl From<&Block> for blockchain::Block {
    fn from(other: &Block) -> Self {
        Self {
            id: Some((&other.id).into()),
            version: other.version,
            parent_id: Some((&other.parent_id).into()),
            index: other.index,
            cumulative_txo_count: other.cumulative_txo_count,
            root_element: Some((&other.root_element).into()),
            contents_hash: Some((&other.contents_hash).into()),
        }
    }
}

/// Convert blockchain::Block --> Block.
impl TryFrom<&blockchain::Block> for Block {
    type Error = ConversionError;

    fn try_from(value: &blockchain::Block) -> Result<Self, Self::Error> {
        let block_id = BlockID::try_from(value.id.as_ref().unwrap_or(&Default::default()))?;
        let parent_id = BlockID::try_from(value.parent_id.as_ref().unwrap_or(&Default::default()))?;
        let root_element = TxOutMembershipElement::try_from(
            value.root_element.as_ref().unwrap_or(&Default::default()),
        )?;
        let contents_hash = BlockContentsHash::try_from(
            value.contents_hash.as_ref().unwrap_or(&Default::default()),
        )?;

        let block = Block {
            id: block_id,
            version: value.version,
            parent_id,
            index: value.index,
            cumulative_txo_count: value.cumulative_txo_count,
            root_element,
            contents_hash,
        };
        Ok(block)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::external;
    use mc_transaction_core::{membership_proofs::Range, tx::TxOutMembershipHash};
    use prost::Message;

    #[test]
    // Block --> blockchain::Block
    fn test_block_from() {
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

        let block = blockchain::Block::from(&source_block);
        assert_eq!(block.id.unwrap().data, [2u8; 32]);
        assert_eq!(block.version, 1);
        assert_eq!(block.parent_id.unwrap().data, [1u8; 32]);
        assert_eq!(block.index, 99);
        assert_eq!(block.cumulative_txo_count, 400);
        assert_eq!(
            block
                .root_element
                .as_ref()
                .unwrap()
                .range
                .as_ref()
                .unwrap()
                .from,
            10
        );
        assert_eq!(
            block
                .root_element
                .as_ref()
                .unwrap()
                .range
                .as_ref()
                .unwrap()
                .to,
            20
        );
        assert_eq!(
            block
                .root_element
                .as_ref()
                .unwrap()
                .hash
                .as_ref()
                .unwrap()
                .data,
            &[12u8; 32]
        );
        assert_eq!(block.contents_hash.unwrap().data, [66u8; 32]);
    }

    #[test]
    // blockchain::Block -> Block
    fn test_block_try_from() {
        let root_element = external::TxOutMembershipElement {
            range: Some(external::Range { from: 10, to: 20 }),
            hash: Some(external::TxOutMembershipHash {
                data: vec![13u8; 32],
            }),
        };

        let block_id = blockchain::BlockId {
            data: vec![10u8; 32],
        };
        let parent_block_id = blockchain::BlockId {
            data: vec![9u8; 32],
        };
        let contents_hash = blockchain::BlockContentsHash {
            data: vec![66u8; 32],
        };

        let source_block = blockchain::Block {
            id: Some(block_id),
            version: 1,
            parent_id: Some(parent_block_id),
            index: 2,
            root_element: Some(root_element),
            contents_hash: Some(contents_hash),
            cumulative_txo_count: 0,
        };

        let block = Block::try_from(&source_block).unwrap();
        assert_eq!(block.id.as_ref(), [10u8; 32]);
        assert_eq!(block.version, 1);
        assert_eq!(block.parent_id.as_ref(), [9u8; 32]);
        assert_eq!(block.index, 2);
        assert_eq!(block.root_element.range.from, 10);
        assert_eq!(block.root_element.range.to, 20);
        assert_eq!(block.root_element.hash.as_ref(), &[13u8; 32]);
        assert_eq!(block.contents_hash.as_ref(), [66u8; 32]);
    }

    #[test]
    // the blockchain::Block definition matches the Block prost attributes.
    // This ensures the definition in the .proto files matches the prost attributes
    // inside the Block struct.
    fn test_blockchain_block_matches_prost() {
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

        // Encode using `protobuf`, decode using `prost`.
        {
            let blockchain_block = blockchain::Block::from(&source_block);
            let blockchain_block_bytes = blockchain_block.encode_to_vec();

            let block_from_prost: Block =
                mc_util_serial::decode(&blockchain_block_bytes).expect("failed decoding");
            assert_eq!(source_block, block_from_prost);
        }

        // Encode using `prost`, decode using `protobuf`.
        {
            let prost_block_bytes = mc_util_serial::encode(&source_block);
            let blockchain_block =
                blockchain::Block::decode(prost_block_bytes.as_slice()).expect("failed decoding");

            assert_eq!(blockchain_block, blockchain::Block::from(&source_block));
        }
    }
}
