// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Mock [BlockFetcher]

use crate::{test_utils::make_components, BlockFetcher, BlockStreamComponents, Result};
use futures::{Future, FutureExt, Stream, StreamExt};
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
    type Single = impl Future<Output = Result<BlockStreamComponents>>;
    type Multiple = impl Stream<Item = Result<BlockStreamComponents>>;

    fn fetch_single(&self, index: BlockIndex) -> Result<Self::Single> {
        let result = self.results[index as usize].clone();
        Ok(async { result })
    }

    fn fetch_range(&self, range: Range<BlockIndex>) -> Result<Self::Multiple> {
        let streams = range
            .map(|idx| self.fetch_single(idx).map(FutureExt::into_stream))
            // Aggregate the results and propagate errors.
            .collect::<Result<Vec<_>>>()?;
        let result = futures::stream::iter(streams).flatten();
        Ok(result)
    }
}
