// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Test helpers for creating [BlockData].

use mc_consensus_scp::test_utils::test_node_id_and_signer;
use mc_transaction_core::{
    tx::TxOutMembershipElement, Block, BlockContents, BlockData, BlockMetadata, BlockVersion,
    SignedBlockMetadata,
};

/// Generate the specified number of [BlockData]
pub fn make_blocks(count: usize) -> Vec<BlockData> {
    let (_node_id, signer) = test_node_id_and_signer(0);
    (0..count)
        .scan(None, |parent, i| {
            let contents = BlockContents::default();
            let block = if i == 0 {
                Block::new_origin_block(&[])
            } else {
                let root_element = TxOutMembershipElement::default();
                Block::new_with_parent(
                    BlockVersion::MAX,
                    parent.as_ref().unwrap(),
                    &root_element,
                    &contents,
                )
            };
            *parent = Some(block.clone());

            let quorum_set = None;
            let verification_report = None;
            let metadata_contents =
                BlockMetadata::new(block.id.clone(), quorum_set, verification_report);
            let metadata =
                SignedBlockMetadata::from_contents_and_keypair(metadata_contents, &signer)
                    .expect("SignedBlockMetadata");
            let block_data = BlockData::new_with_metadata(block, contents, None, metadata);
            Some(block_data)
        })
        .collect()
}
