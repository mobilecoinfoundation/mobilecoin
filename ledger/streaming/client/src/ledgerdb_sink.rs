// Copyright (c) 2018-2021 The MobileCoin Foundation
#![allow(dead_code)]
use futures::stream::{Stream, StreamExt};
use mc_common::logger::{log, Logger};
use mc_ledger_streaming_api::StreamResult;
use mc_transaction_core::BlockData;
use pin_project::pin_project;

/// A block sink that takes blocks from a passed stream and puts them into
/// ledger db. This sink should live downstream from a verification source that
/// has already done block content, scp, and avr validation and thus is
/// considered a trusted stream.
#[pin_project]
pub struct BlockSink<BS: Stream<Item = StreamResult<BlockData>> + std::marker::Unpin> {
    stream: BS,
    logger: Logger,
}

impl<BS: Stream<Item = StreamResult<BlockData>> + std::marker::Unpin> BlockSink<BS> {
    // generate new object from stream
    pub fn new(stream: BS, logger: Logger) -> Self {
        Self { stream, logger }
    }

    // Ingest blocks from stream into a sink for processing
    async fn ingest(&mut self) -> Vec<BlockData> {
        let mut v: Vec<BlockData> = Vec::new();
        while let Some(block) = self.stream.next().await {
            v.push(block.unwrap());
        }

        log::info!(self.logger, "vector is {:?}", v);
        v
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::executor::block_on;
    use mc_common::logger::test_with_logger;
    use mc_ledger_db::{test_utils::get_mock_ledger, Ledger};

    #[test_with_logger]
    fn assert_blocks_arrive(logger: Logger) {
        let mock_ledger = get_mock_ledger(5);
        let mut test_block_data: Vec<StreamResult<BlockData>> = Vec::new();
        for i in 1..5 as u64 {
            test_block_data.push(Ok(mock_ledger.get_block_data(i).unwrap()))
        }

        let stream = futures::stream::iter(test_block_data);

        let mut bs = BlockSink::new(stream, logger);
        let vec = block_on(bs.ingest());
        assert_eq!(vec.len(), 4)
    }
}
