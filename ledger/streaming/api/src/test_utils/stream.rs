// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Mock BlockStream

use crate::{BlockData, BlockStream, Result};
use futures::Stream;

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
