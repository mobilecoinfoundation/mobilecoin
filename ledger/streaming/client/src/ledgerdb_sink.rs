// Copyright (c) 2018-2021 The MobileCoin Foundation
#![allow(dead_code)]

use futures::stream::{Stream, StreamExt};
use mc_common::logger::{log, Logger};
use mc_ledger_db::Ledger;
use mc_ledger_streaming_api::StreamResult;
use mc_transaction_core::BlockData;
use pin_project::pin_project;
use tokio::sync::mpsc;

/// A block sink that takes blocks from a passed stream and puts them into
/// ledger db. This sink should live downstream from a verification source that
/// has already done block content, scp, and avr validation and thus is
/// considered a trusted stream
#[pin_project]
pub struct BlockSink<BS: Stream<Item = StreamResult<BlockData>> + std::marker::Unpin> {
    /// Stream of block data
    stream: BS,

    /// Message channel that sends data to the db
    sender: mpsc::Sender<BlockData>,

    /// Logger running
    logger: Logger,
}

impl<BS: Stream<Item = StreamResult<BlockData>> + std::marker::Unpin> BlockSink<BS> {
    pub fn new(stream: BS, logger: Logger, sender: mpsc::Sender<BlockData>) -> Self {
        Self {
            stream,
            logger,
            sender,
        }
    }

    // Ingest blocks from stream into a sink for processing
    async fn broadcast(&mut self) {
        loop {
            while let Some(block) = self.stream.next().await {
                if let Ok(block) = block {
                    match self.sender.send(block).await {
                        Ok(_) => (log::info!(self.logger, "sent a block!")),
                        Err(_) => panic!("I crashed"),
                    }
                }
            }
        }
    }
}

/// Write to the ledger in a synchronous loop that consistently polls for blocks
pub fn sink(ledger: &mut impl Ledger, mut receiver: mpsc::Receiver<BlockData>, logger: Logger) {
    loop {
        if let Some(block_data) = receiver.blocking_recv() {
            ledger
                .append_block(
                    block_data.block(),
                    block_data.contents(),
                    block_data.signature().clone(),
                )
                .unwrap();
            log::info!(logger, "successfully wrote block");
        } else {
            log::warn!(logger, "Block data failed to write");
            break;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mc_common::logger::test_with_logger;
    use mc_ledger_db::{test_utils::get_mock_ledger, Ledger};
    use tokio::runtime::Builder;

    #[test_with_logger]
    fn assert_blocks_arrive(logger: Logger) {
        let mock_ledger = get_mock_ledger(20);
        let mut test_block_data: Vec<StreamResult<BlockData>> = Vec::new();
        let (tx, rcv) = mpsc::channel(16);

        for i in 1..20 {
            test_block_data.push(Ok(mock_ledger.get_block_data(i).unwrap()));
        }
        let stream = futures::stream::iter(test_block_data);
        let mut bs = BlockSink::new(stream, logger.clone(), tx);

        std::thread::spawn(move || {
            let mut ledger = get_mock_ledger(1);
            let logger = logger.clone();
            sink(&mut ledger, rcv, logger)
        });

        let rt = Builder::new_current_thread().enable_all().build().unwrap();
        rt.block_on(async move {
            bs.broadcast().await;
        });
    }
}
