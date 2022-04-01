// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Mock BlockStream

use crate::{BlockStream, BlockStreamComponents, Result};
use futures::Stream;
use mc_transaction_core::{Block, BlockData};
use std::iter::FromIterator;
use std::vec::IntoIter;

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

/// Mock stream for generating blocks without the need for clone or generics
#[derive(Clone, Debug)]
pub struct SimpleMockStream {
    num_components: u64,
    components: Vec<BlockStreamComponents>,
}

impl SimpleMockStream {
    /// New simple stream with pre-determined initial components
    pub fn new(num_components: u64) -> Self {
        Self {
            num_components,
            components: super::make_components(num_components as usize),
        }
    }

    /// Simple stream initialized with pre-defined components
    pub fn new_from_components(components: Vec<BlockStreamComponents>) -> Self {
        let num_components = components.len() as u64;
        Self {
            num_components,
            components,
        }
    }

    /// Get simple mock stream
    fn get_stream(
        &self,
        starting_height: u64,
    ) -> impl Stream<Item = Result<BlockStreamComponents>> {
        let slice = Vec::from_iter(
            self.components[starting_height as usize..self.num_components as usize]
                .iter()
                .cloned(),
        );
        futures::stream::iter(slice.into_iter().map(Ok))
    }

    /// Get block data for specific block height
    pub fn get_block_data(&self, height: u64) -> BlockData {
        self.components
            .get(height as usize)
            .unwrap()
            .block_data
            .clone()
    }

    /// Get block for specific block height
    pub fn get_block(&self, height: u64) -> Block {
        self.components
            .get(height as usize)
            .unwrap()
            .block_data
            .block()
            .clone()
    }
}

impl BlockStream for SimpleMockStream {
    type Stream = impl Stream<Item = Result<BlockStreamComponents>>;

    fn get_block_stream(&self, starting_height: u64) -> Result<Self::Stream> {
        Ok(self.get_stream(starting_height))
    }
}

/// Get stream combinator with n components
pub fn get_stream_with_n_components(n: u64) -> SimpleMockStream {
    SimpleMockStream::new(n)
}

/// Get raw stream with n components
pub fn get_raw_stream_with_n_components(n: usize) -> Iter<IntoIter<Result<BlockStreamComponents>>> {
    let components: Vec<Result<BlockStreamComponents>> =
        super::make_components(n).into_iter().map(Ok).collect();
    futures::stream::iter(components)
}
