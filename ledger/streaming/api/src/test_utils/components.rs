// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Test helpers for creating [BlockStreamComponents].

use super::make_quorum_set;
use crate::BlockStreamComponents;
use mc_transaction_core::{
    tx::TxOutMembershipElement, Block, BlockContents, BlockData, BlockVersion,
};

/// Generate the specified number of [BlockStreamComponents]
pub fn make_components(count: usize) -> Vec<BlockStreamComponents> {
    let mut parent: Option<Block> = None;
    (0..count)
        .map(|i| {
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
            parent = Some(block.clone());
            let block_data = BlockData::new(block, contents, None);
            let quorum_set = Some(make_quorum_set());
            let verification_report = None;
            BlockStreamComponents {
                block_data,
                quorum_set,
                verification_report,
            }
        })
        .collect()
}
