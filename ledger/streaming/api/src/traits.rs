// Copyright (c) 2018-2022 The MobileCoin Foundation

use crate::Result;
use futures::{Future, Stream};
use mc_transaction_core::{BlockData, BlockIndex};
use std::ops::Range;

/// A stream of blocks with associated data.
pub trait BlockStream {
    /// The specific type of stream.
    type Stream<'s>: Stream<Item = Result<BlockData>> + 's
    where
        Self: 's;

    /// Start streaming blocks.
    /// starting_height is a hint to the stream impl for where to start:
    /// the returned stream may start later this height, but no earlier.
    fn get_block_stream(&self, starting_height: u64) -> Result<Self::Stream<'_>>;
}

/// A helper that can fetch blocks on demand.
pub trait BlockFetcher {
    /// Future for fetching single blocks.
    type Single<'s>: Future<Output = Result<BlockData>> + 's
    where
        Self: 's;
    /// Stream for fetching multiple blocks.
    type Multiple<'s>: Stream<Item = Result<BlockData>> + 's
    where
        Self: 's;

    /// Fetch a single block with the given index.
    fn fetch_single(&self, index: BlockIndex) -> Self::Single<'_>;

    /// Fetch multiple blocks, with indexes in the given range.
    /// Implementations may fetch a merged block when possible, or fetch the
    /// individual blocks.
    fn fetch_range(&self, indexes: Range<BlockIndex>) -> Self::Multiple<'_>;
}
