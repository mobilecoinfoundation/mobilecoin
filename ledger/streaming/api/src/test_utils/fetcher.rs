// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Mock [BlockFetcher]

use crate::{test_utils::make_blocks, BlockData, BlockFetcher, Result};
use futures::{Future, Stream, StreamExt};
use mc_transaction_core::BlockIndex;
use std::ops::Range;

/// Mock implementation of [BlockFetcher].
pub struct MockFetcher {
    /// Fetch results.
    pub results: Vec<Result<BlockData>>,
}

impl MockFetcher {
    /// Instantiate a [MockFetcher] with the given number of blocks.
    pub fn new(num: usize) -> Self {
        Self::from_blocks(make_blocks(num))
    }

    /// Instantiate a [MockFetcher] with the given blocks.
    pub fn from_blocks(blocks: Vec<BlockData>) -> Self {
        let results = blocks.into_iter().map(Ok).collect();
        Self { results }
    }

    /// Instantiate a [MockFetcher] with the given results.
    pub fn from_results(results: Vec<Result<BlockData>>) -> Self {
        Self { results }
    }
}

impl BlockFetcher for MockFetcher {
    type Single<'s> = impl Future<Output = Result<BlockData>> + 's;
    type Multiple<'s> = impl Stream<Item = Result<BlockData>> + 's;

    fn fetch_single(&self, index: BlockIndex) -> Self::Single<'_> {
        let result = self.results[index as usize].clone();
        async { result }
    }

    fn fetch_range(&self, indexes: Range<BlockIndex>) -> Self::Multiple<'_> {
        futures::stream::iter(indexes).then(move |idx| self.fetch_single(idx))
    }
}
