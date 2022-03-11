// Copyright (c) 2018-2022 The MobileCoin Foundation

use crate::{BlockStreamComponents, Result};

pub trait BlockStream {
    type Stream: futures::Stream<Item = Result<BlockStreamComponents>>;

    fn get_block_stream(&self, starting_height: u64) -> Result<Self::Stream>;
}
