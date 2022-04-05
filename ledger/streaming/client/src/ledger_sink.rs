// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Helper class for creating a blocksink

use crate::streaming_futures::LedgerStream;
use futures::stream::{Buffered, Stream, StreamExt};
use mc_ledger_db::Ledger;
use mc_ledger_streaming_api::{BlockStream, BlockStreamComponents, Result as StreamResult};

/// A block sink that takes blocks from a passed stream and puts them into
/// ledger db. This sink should live downstream from a verification source that
/// has already done block content, scp, and avr validation and thus is
/// considered a trusted stream
pub struct DbStream<US: BlockStream, L: Ledger + 'static> {
    /// Upstream block stream combinator
    upstream: US,

    /// Block database ledger object
    ledger: L,

    /// Maximum # of blocks that can be buffered before writing
    buffer: usize,
}

impl<US: BlockStream + 'static, L: Ledger + Clone + 'static> BlockStream for DbStream<US, L> {
    type Stream = impl Stream<Item = StreamResult<BlockStreamComponents>>;

    fn get_block_stream(&self, starting_height: u64) -> StreamResult<Self::Stream> {
        let stream = self.upstream.get_block_stream(starting_height).unwrap();
        Ok(LedgerStream::new(self.ledger.clone(), stream).buffered(self.buffer))
    }
}

impl<US: BlockStream + 'static, L: Ledger + Clone + 'static> DbStream<US, L> {
    /// Initialize a pass through stream factory from an upstream source
    pub fn new(upstream: US, ledger: L, buffer: usize) -> Self {
        Self {
            upstream,
            ledger,
            buffer,
        }
    }

    /// If the sink is the terminal element, get it without initializing state
    pub fn get_sink_from_upstream(
        upstream: US,
        ledger: L,
        buffer: usize,
        starting_height: u64,
    ) -> Buffered<LedgerStream<L, impl Stream<Item = StreamResult<BlockStreamComponents>>>> {
        let stream = upstream.get_block_stream(starting_height).unwrap();
        LedgerStream::new(ledger, stream).buffered(buffer)
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use mc_common::logger::{log, test_with_logger, Logger};
    use mc_ledger_db::test_utils::get_mock_ledger;
    use mc_ledger_streaming_api::test_utils::stream::get_stream_with_n_components;

    #[test_with_logger]
    fn assert_pass_through_and_storage(logger: Logger) {
        let upstream = get_stream_with_n_components(43);
        let dest_ledger = get_mock_ledger(0);
        let bs = DbStream::new(upstream, dest_ledger, 43);
        let mut stream = bs.get_block_stream(0).unwrap();

        futures::executor::block_on(async move {
            let mut index: u64 = 0;
            let mut threshold = 0;
            while let Some(component_result) = stream.next().await {
                let component = component_result.unwrap();
                index = component.block_data.block().index;
                threshold = component.quorum_set.unwrap().threshold;
            }

            log::info!(logger, "{} blocks recorded via pass through stream", index);
            assert_eq!(threshold, 2);
            assert_eq!(index, 42);
        });
    }

    #[test_with_logger]
    fn assert_sink_only_works(logger: Logger) {
        let upstream = get_stream_with_n_components(43);
        let dest_ledger = get_mock_ledger(0);
        let mut sink = DbStream::get_sink_from_upstream(upstream, dest_ledger, 43, 0);

        futures::executor::block_on(async move {
            let mut index: u64 = 0;
            let mut threshold = 0;

            while let Some(component_result) = sink.next().await {
                let component = component_result.unwrap();
                index = component.block_data.block().index;
                threshold = component.quorum_set.unwrap().threshold;
            }

            log::info!(logger, "{} blocks recorded via sink only", index);

            assert_eq!(threshold, 2);
            assert_eq!(index, 42);
        });
    }
}
