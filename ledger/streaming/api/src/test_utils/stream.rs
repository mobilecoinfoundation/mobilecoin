// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Mock BlockStream

use crate::{BlockStream, BlockStreamComponents, Result};
use futures::Stream;

/// Mock implementation of BlockStream, backed by a pre-defined Stream.
#[derive(Clone, Debug)]
pub struct MockStream<S>
where
    S: Stream<Item = Result<BlockStreamComponents>> + Clone,
{
    source: S,
}

impl<S> MockStream<S>
where
    S: Stream<Item = Result<BlockStreamComponents>> + Clone,
{
    /// Instantiate a MockStream with the given stream.
    /// It will be cloned for each `get_block_stream` call.
    pub fn new(source: S) -> Self {
        Self { source }
    }
}

type VecIter = <Vec<Result<BlockStreamComponents>> as IntoIterator>::IntoIter;

impl MockStream<futures::stream::Iter<VecIter>> {
    /// Instantiate a MockStream with the given items.
    pub fn from_components(src: Vec<BlockStreamComponents>) -> Self {
        let items: Vec<Result<BlockStreamComponents>> = src.into_iter().map(Ok).collect();
        Self::from_items(items)
    }

    /// Instantiate a MockStream with the given items.
    pub fn from_items(items: Vec<Result<BlockStreamComponents>>) -> Self {
        let stream = futures::stream::iter(items);
        Self::new(stream)
    }
}

impl<S> BlockStream for MockStream<S>
where
    S: Stream<Item = Result<BlockStreamComponents>> + Clone,
{
    type Stream = S;

    fn get_block_stream(&self, _starting_height: u64) -> Result<S> {
        Ok(self.source.clone())
    }
}
