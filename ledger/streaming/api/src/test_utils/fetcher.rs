// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Mock [BlockFetcher]

use crate::{test_utils::make_components, BlockFetcher, BlockStreamComponents, Result};
use futures::{Future, Stream, StreamExt};
use mc_transaction_core::BlockIndex;
use std::ops::Range;

/// Mock implementation of [BlockFetcher].
pub struct MockFetcher {
    /// Fetch results.
    pub results: Vec<Result<BlockStreamComponents>>,
}

impl MockFetcher {
    /// Instantiate a [MockFetcher] with the given number of components.
    pub fn new(num: usize) -> Self {
        Self::from_components(make_components(num))
    }

    /// Instantiate a [MockFetcher] with the given components.
    pub fn from_components(components: Vec<BlockStreamComponents>) -> Self {
        let results = components.into_iter().map(Ok).collect();
        Self { results }
    }

    /// Instantiate a [MockFetcher] with the given results.
    pub fn from_results(results: Vec<Result<BlockStreamComponents>>) -> Self {
        Self { results }
    }
}

impl BlockFetcher for MockFetcher {
    type Single<'s> = impl Future<Output = Result<BlockStreamComponents>> + 's;
    type Multiple<'s> = impl Stream<Item = Result<BlockStreamComponents>> + 's;

    fn fetch_single(&self, index: BlockIndex) -> Self::Single<'_> {
        let result = self.results[index as usize].clone();
        async { result }
    }

    fn fetch_range(&self, indexes: Range<BlockIndex>) -> Self::Multiple<'_> {
        futures::stream::iter(indexes).then(move |idx| self.fetch_single(idx))
    }
}
