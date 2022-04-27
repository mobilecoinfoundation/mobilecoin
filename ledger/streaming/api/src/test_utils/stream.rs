// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Mock BlockStream

use crate::{BlockData, BlockStream, Result};
use futures::Stream;
use mc_ledger_db::test_utils::mock_ledger::get_custom_test_ledger_blocks;

/// Mock implementation of BlockStream, backed by pre-defined data.
#[derive(Clone, Debug)]
pub struct MockStream {
    items: Vec<Result<BlockData>>,
}

impl MockStream {
    /// Instantiate a MockStream with the given items.
    /// A subset of the items will be cloned for each `get_block_stream` call.
    pub fn new(items: Vec<Result<BlockData>>) -> Self {
        Self { items }
    }

    /// Instantiate a MockStream with the given blocks.
    pub fn from_blocks(src: Vec<BlockData>) -> Self {
        let items: Vec<Result<BlockData>> = src.into_iter().map(Ok).collect();
        Self::new(items)
    }
}

impl BlockStream for MockStream {
    type Stream<'s> = impl Stream<Item = Result<BlockData>> + 's;

    fn get_block_stream(&self, starting_height: u64) -> Result<Self::Stream<'_>> {
        let start_index = starting_height as usize;
        let items = self.items.iter().cloned().skip(start_index);
        Ok(futures::stream::iter(items))
    }
}

/// Create a mock stream with blocks that resemble those seen in productoin
///
/// * `outputs_per_recipient_per_block` - transaction outputs per account per
///   block
/// * `num_accounts` - number of accounts in the simulated blocks
/// * `num_blocks` - number of simulated blocks to create
/// * `key_images_per_block` - number of simulated key images per block
///
/// Returns a MockStream that when driven will produce blocks with the contents
/// specified in the above parameters
pub fn mock_stream_with_custom_block_contents(
    outputs_per_recipient_per_block: usize,
    num_accounts: usize,
    num_blocks: usize,
    key_images_per_block: usize,
    max_token_id: u64,
) -> MockStream {
    let blocks = get_custom_test_ledger_blocks(
        outputs_per_recipient_per_block,
        num_accounts,
        num_blocks,
        key_images_per_block,
        max_token_id,
    );

    let block_data: Vec<BlockData> = blocks
        .into_iter()
        .map(move |(block, block_contents)| BlockData::new(block, block_contents, None))
        .collect();
    MockStream::from_blocks(block_data)
}
