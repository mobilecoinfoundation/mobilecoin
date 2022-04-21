// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Mock BlockStream

use crate::{BlockStream, BlockStreamComponents, Result};
use futures::Stream;
use std::iter::FromIterator;

/// Mock implementation of BlockStream, backed by a pre-defined Stream.
#[derive(Clone, Debug)]
pub struct MockStream {
    items: Vec<Result<BlockStreamComponents>>,
}

impl MockStream {
    /// Instantiate a MockStream with the given stream.
    /// It will be cloned for each `get_block_stream` call.
    pub fn new(items: Vec<Result<BlockStreamComponents>>) -> Self {
        Self { items }
    }

    /// Instantiate a MockStream with the given items.
    pub fn from_components(src: Vec<BlockStreamComponents>) -> Self {
        let items: Vec<Result<BlockStreamComponents>> = src.into_iter().map(Ok).collect();
        Self::from_items(items)
    }

    /// Instantiate a MockStream with the given items.
    pub fn from_items(items: Vec<Result<BlockStreamComponents>>) -> Self {
        Self::new(items)
    }
}

impl BlockStream for MockStream {
    type Stream<'s> = impl Stream<Item = Result<BlockStreamComponents>> + 's;

    fn get_block_stream(&self, starting_height: u64) -> Result<Self::Stream<'_>> {
        let items = if starting_height > 0 {
            Vec::from_iter(
                self.items[starting_height as usize..self.items.len()]
                    .iter()
                    .cloned(),
            )
        } else {
            self.items.clone()
        };
        Ok(futures::stream::iter(items))
    }
}

/// Create a MockStream with the given BlockStreamComponents.
pub fn mock_stream_from_components(src: Vec<BlockStreamComponents>) -> MockStream {
    let items: Vec<Result<BlockStreamComponents>> = src.into_iter().map(Ok).collect();
    MockStream::new(items)
}
