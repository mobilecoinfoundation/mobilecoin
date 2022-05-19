// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Mock implementation of [Streamer<Result<BlockData>>], backed by pre-defined
//! data.

use crate::{BlockData, BlockIndex, Result, Streamer};
use futures::Stream;

/// Mock implementation of [Streamer<Result<BlockData>>], backed by pre-defined
/// data.
#[derive(Clone, Debug)]
pub struct MockStream {
    items: Vec<Result<BlockData>>,
}

impl MockStream {
    /// Instantiate a MockStream with the given items.
    /// A subset of the items will be cloned for each `get_stream` call.
    pub fn new(items: Vec<Result<BlockData>>) -> Self {
        Self { items }
    }

    /// Instantiate a MockStream with the given blocks.
    pub fn from_blocks(src: Vec<BlockData>) -> Self {
        let items: Vec<Result<BlockData>> = src.into_iter().map(Ok).collect();
        Self::new(items)
    }
}

impl Streamer<Result<BlockData>, BlockIndex> for MockStream {
    type Stream<'s> = impl Stream<Item = Result<BlockData>> + 's;

    fn get_stream(&self, starting_height: BlockIndex) -> Result<Self::Stream<'_>> {
        let start_index = starting_height as usize;
        let items = self.items.iter().skip(start_index).cloned();
        Ok(futures::stream::iter(items))
    }
}
