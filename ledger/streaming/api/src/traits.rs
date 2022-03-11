use crate::StreamResult;
use mc_transaction_core::BlockData;

pub trait BlockSource {
    type BlockStream: futures::Stream<Item = StreamResult<BlockData>>;

    fn get_block_stream(&self, starting_height: u64) -> StreamResult<Self::BlockStream>;
}
