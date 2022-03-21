// Copyright (c) 2018-2022 The MobileCoin Foundation

use crate::{BlockStreamComponents, Result};
use mc_transaction_core::BlockIndex;
use std::ops::Range;

/// A stream of blocks with associated data.
pub trait BlockStream {
    /// The specific type of stream.
    type Stream: futures::Stream<Item = Result<BlockStreamComponents>>;

    /// Start streaming blocks.
    /// starting_height is a hint to the stream impl for where to start:
    /// the returned stream may start later this height, but no earlier.
    fn get_block_stream(&self, starting_height: u64) -> Result<Self::Stream>;
}

/// A helper that can fetch blocks on demand.
pub trait BlockFetcher {
    /// Future for fetching single blocks.
    type Single: futures::Future<Output = Result<BlockStreamComponents>>;
    /// Stream for fetching multiple blocks.
    type Multiple: futures::Stream<Item = Result<BlockStreamComponents>>;

    /// Fetch a single block with the given index.
    fn fetch_single(&self, index: BlockIndex) -> Result<Self::Single>;

    /// Fetch multiple blocks, with indexes in the given range.
    /// Implementations may fetch a merged block when possible, or fetch the
    /// individual blocks.
    fn fetch_range(&self, indexes: Range<BlockIndex>) -> Result<Self::Multiple>;
}
