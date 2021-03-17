//! Convert to/from blockchain::Block

use crate::{blockchain, convert::ConversionError};
use mc_transaction_core::tx::TxOutMembershipElement;
use std::convert::TryFrom;

/// Convert mc_transaction_core::Block --> blockchain::Block.
impl From<&mc_transaction_core::Block> for blockchain::Block {
    fn from(other: &mc_transaction_core::Block) -> Self {
        let mut block = blockchain::Block::new();
        block.set_id(blockchain::BlockID::from(&other.id));
        block.set_version(other.version);
        block.set_parent_id(blockchain::BlockID::from(&other.parent_id));
        block.set_index(other.index);
        block.set_cumulative_txo_count(other.cumulative_txo_count);
        block.set_root_element((&other.root_element).into());
        block.set_contents_hash(blockchain::BlockContentsHash::from(&other.contents_hash));
        block
    }
}

/// Convert blockchain::Block --> mc_transaction_core::Block.
impl TryFrom<&blockchain::Block> for mc_transaction_core::Block {
    type Error = ConversionError;

    fn try_from(value: &blockchain::Block) -> Result<Self, Self::Error> {
        let block_id = mc_transaction_core::BlockID::try_from(value.get_id())?;
        let parent_id = mc_transaction_core::BlockID::try_from(value.get_parent_id())?;
        let root_element = TxOutMembershipElement::try_from(value.get_root_element())?;
        let contents_hash =
            mc_transaction_core::BlockContentsHash::try_from(value.get_contents_hash())?;

        let block = mc_transaction_core::Block {
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
    use mc_transaction_core::{
        membership_proofs::Range,
        tx::{TxOutMembershipElement, TxOutMembershipHash},
    };
    use protobuf::Message;

    #[test]
    // mc_transaction_core::Block --> blockchain::Block
    fn test_block_from() {
        let source_block = mc_transaction_core::Block {
            id: mc_transaction_core::BlockID::try_from(&[2u8; 32][..]).unwrap(),
            version: 1,
            parent_id: mc_transaction_core::BlockID::try_from(&[1u8; 32][..]).unwrap(),
            index: 99,
            cumulative_txo_count: 400,
            root_element: TxOutMembershipElement {
                range: Range::new(10, 20).unwrap(),
                hash: TxOutMembershipHash::from([12u8; 32]),
            },
            contents_hash: mc_transaction_core::BlockContentsHash::try_from(&[66u8; 32][..])
                .unwrap(),
        };

        let block = blockchain::Block::from(&source_block);
        assert_eq!(block.get_id().get_data(), [2u8; 32]);
        assert_eq!(block.get_version(), 1);
        assert_eq!(block.get_parent_id().get_data(), [1u8; 32]);
        assert_eq!(block.get_index(), 99);
        assert_eq!(block.get_cumulative_txo_count(), 400);
        assert_eq!(block.get_root_element().get_range().get_from(), 10);
        assert_eq!(block.get_root_element().get_range().get_to(), 20);
        assert_eq!(block.get_root_element().get_hash().get_data(), &[12u8; 32]);
        assert_eq!(block.get_contents_hash().get_data(), [66u8; 32]);
    }

    #[test]
    // blockchain::Block -> mc_transaction_core::Block
    fn test_block_try_from() {
        let mut root_element = external::TxOutMembershipElement::new();
        root_element.mut_range().set_from(10);
        root_element.mut_range().set_to(20);
        root_element.mut_hash().set_data(vec![13u8; 32]);

        let mut block_id = blockchain::BlockID::new();
        block_id.set_data(vec![10u8; 32]);

        let mut parent_block_id = blockchain::BlockID::new();
        parent_block_id.set_data(vec![9u8; 32]);

        let mut contents_hash = blockchain::BlockContentsHash::new();
        contents_hash.set_data(vec![66u8; 32]);

        let mut source_block = blockchain::Block::new();
        source_block.set_id(block_id);
        source_block.set_version(1u32);
        source_block.set_parent_id(parent_block_id);
        source_block.set_index(2);
        source_block.set_root_element(root_element);
        source_block.set_contents_hash(contents_hash);

        let block = mc_transaction_core::Block::try_from(&source_block).unwrap();
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
        let source_block = mc_transaction_core::Block {
            id: mc_transaction_core::BlockID::try_from(&[2u8; 32][..]).unwrap(),
            version: 1,
            parent_id: mc_transaction_core::BlockID::try_from(&[1u8; 32][..]).unwrap(),
            index: 99,
            cumulative_txo_count: 400,
            root_element: TxOutMembershipElement {
                range: Range::new(10, 20).unwrap(),
                hash: TxOutMembershipHash::from([12u8; 32]),
            },
            contents_hash: mc_transaction_core::BlockContentsHash::try_from(&[66u8; 32][..])
                .unwrap(),
        };

        // Encode using `protobuf`, decode using `prost`.
        {
            let blockchain_block = blockchain::Block::from(&source_block);
            let blockchain_block_bytes = blockchain_block.write_to_bytes().unwrap();

            let block_from_prost: mc_transaction_core::Block =
                mc_util_serial::decode(&blockchain_block_bytes).expect("failed decoding");
            assert_eq!(source_block, block_from_prost);
        }

        // Encode using `prost`, decode using `protobuf`.
        {
            let prost_block_bytes = mc_util_serial::encode(&source_block);
            let blockchain_block =
                blockchain::Block::parse_from_bytes(&prost_block_bytes).expect("failed decoding");

            assert_eq!(blockchain_block, blockchain::Block::from(&source_block));
        }
    }
}
