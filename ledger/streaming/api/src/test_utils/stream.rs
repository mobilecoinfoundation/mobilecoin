// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Mock implementation of [Streamer<Result<BlockData>>], backed by pre-defined
//! data.

use crate::{BlockData, BlockIndex, Result, Streamer};
use futures::{
    stream::{iter, Iter},
    Stream, StreamExt,
};

/// Mock [Streamer<Result<BlockData>>], backed by pre-defined data.
#[derive(Clone, Debug)]
pub struct MockStream<S: Stream + Clone> {
    stream: S,
}

impl<S: Stream + Clone> MockStream<S> {
    /// Instantiate a MockStream with the given stream.
    pub fn new(stream: S) -> Self {
        Self { stream }
    }
}

type BlockVecIntoIter = <Vec<Result<BlockData>> as IntoIterator>::IntoIter;
impl MockStream<Iter<BlockVecIntoIter>> {
    /// Instantiate a MockStream with the given results.
    pub fn from_items(results: Vec<Result<BlockData>>) -> Self {
        Self::new(iter(results))
    }

    /// Instantiate a MockStream with the given blocks.
    pub fn from_blocks(src: Vec<BlockData>) -> Self {
        Self::from_items(src.into_iter().map(Ok).collect())
    }
}

impl<S: Stream + Clone> Streamer<S::Item, BlockIndex> for MockStream<S> {
    type Stream<'s> = impl Stream<Item = S::Item> + 's where Self: 's;

    fn get_stream(&self, index: BlockIndex) -> Result<Self::Stream<'_>> {
        Ok(self.stream.clone().skip(index as usize))
    }
}
