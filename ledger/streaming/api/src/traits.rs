use crate::Result;
use mc_transaction_core::{BlockData, BlockIndex};


pub trait BlockSource {
    type BlockStream: futures::Stream<Item = Result<BlockData>>;

    fn get_block_stream(&self, starting_height: u64) -> Result<Self::BlockStream>;
}