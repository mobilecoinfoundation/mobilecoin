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

impl<S> BlockStream for MockStream<S>
where
    S: Stream<Item = Result<BlockStreamComponents>> + Clone,
{
    type Stream = S;

    fn get_block_stream(&self, _starting_height: u64) -> Result<S> {
        Ok(self.source.clone())
    }
}

/// Create a MockStream with the given iterable of items.
pub fn mock_stream_from_items<I>(
    items: I,
) -> MockStream<impl Stream<Item = Result<BlockStreamComponents>> + Clone>
where
    I: IntoIterator<Item = Result<BlockStreamComponents>>,
    <I as IntoIterator>::IntoIter: Clone,
{
    let stream = futures::stream::iter(items);
    MockStream::new(stream)
}

/// Create a MockStream with the given BlockStreamComponents.
pub fn mock_stream_from_components(
    src: Vec<BlockStreamComponents>,
) -> MockStream<impl Stream<Item = Result<BlockStreamComponents>> + Clone> {
    let items: Vec<Result<BlockStreamComponents>> = src.into_iter().map(Ok).collect();
    mock_stream_from_items(items)
}
