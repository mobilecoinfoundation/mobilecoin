// Copyright (c) 2018-2022 The MobileCoin Foundation

use crate::{BlockStreamComponents, Result};

/// A stream of blocks with associated data.
pub trait BlockStream {
    /// The specific type of stream.
    type Stream: futures::Stream<Item = Result<BlockStreamComponents>>;

    /// Start streaming blocks.
    /// starting_height is a hint to the stream impl for where to start:
    /// the returned stream may start later this height, but no earlier.
    fn get_block_stream(&self, starting_height: u64) -> Result<Self::Stream>;
}
