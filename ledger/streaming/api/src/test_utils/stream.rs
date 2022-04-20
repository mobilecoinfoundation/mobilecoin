// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Mock BlockStream

use crate::{BlockStream, BlockStreamComponents, Result};
use futures::{stream::Iter, Stream};
use mc_transaction_core::{Block, BlockData};
use std::{iter::FromIterator, vec::IntoIter};

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
    type Stream<'s>
    where
        S: 's,
    = S;

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