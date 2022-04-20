// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Helper class for creating a blocksink

use futures::stream::{Stream, StreamExt};
use mc_common::logger::{log, Logger};
use mc_ledger_db::Ledger;
use mc_ledger_streaming_api::{BlockStream, BlockStreamComponents, Result as StreamResult};
use tokio::sync::mpsc::{channel, Receiver, Sender};

/// A block sink that takes blocks from a passed stream and puts them into
/// ledger db. This sink should live downstream from a verification source that
/// has already done block content, scp, and avr validation and thus is
/// considered a trusted stream
pub struct DbStream<US: BlockStream + 'static, L: Ledger + 'static> {
    /// Upstream block stream combinator
    upstream: US,

    /// Block database ledger object
    ledger: L,

    logger: Logger,
}

impl<US: BlockStream + 'static, L: Ledger + Clone + 'static> BlockStream for DbStream<US, L> {
    type Stream = impl Stream<Item = StreamResult<BlockStreamComponents>>;

    /// Get block sink stream at a specific height
    fn get_block_stream(&self, starting_height: u64) -> StreamResult<Self::Stream> {
        let stream = Box::pin(self.upstream.get_block_stream(starting_height).unwrap());
        let (send_in, rcv_out) = self.start_sink_thread();
        let output_stream = futures::stream::unfold(
            (stream, send_in, rcv_out),
            |(mut stream, send_in, mut rcv_out)| async move {
                loop {
                    if let Some(component) = stream.next().await {
                        if component.is_ok() {
                            send_in.send(component).await.unwrap();
                        } else {
                            return Some((component, (stream, send_in, rcv_out)));
                        }
                    };

                    if let Some(component) = rcv_out.recv().await {
                        return Some((component, (stream, send_in, rcv_out)));
                    } else {
                        break;
                    }
                }
                None
            },
        );

        Ok(Box::pin(output_stream))
    }
}

impl<US: BlockStream + 'static, L: Ledger + Clone + 'static> DbStream<US, L> {
    /// Initialize a pass through stream factory from an upstream source
    pub fn new(upstream: US, ledger: L, logger: Logger) -> Self {
        Self {
            upstream,
            ledger,
            logger,
        }
    }

    fn start_sink_thread(
        &self,
    ) -> (
        Sender<StreamResult<BlockStreamComponents>>,
        Receiver<StreamResult<BlockStreamComponents>>,
    ) {
        let (send_in, mut rcv_in): (
            Sender<StreamResult<BlockStreamComponents>>,
            Receiver<StreamResult<BlockStreamComponents>>,
        ) = channel(5000);
        let (send_out, rcv_out): (
            Sender<StreamResult<BlockStreamComponents>>,
            Receiver<StreamResult<BlockStreamComponents>>,
        ) = channel(5000);
        let mut ledger = self.ledger.clone();
        let logger = self.logger.clone();
        std::thread::spawn(move || {
            while let Some(component_result) = rcv_in.blocking_recv() {
                let component = component_result.unwrap();
                let mut signature = None;
                if component.block_data.signature().is_some() {
                    signature = component.block_data.signature().clone();
                }

                ledger
                    .append_block(
                        component.block_data.block(),
                        component.block_data.contents(),
                        signature,
                    )
                    .unwrap();
                if let Err(err) = send_out.try_send(Ok(component)) {
                    log::error!(logger, "stream failed with error {:?}", err);
                    break;
                }
            }
        });
        (send_in, rcv_out)
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
        let upstream = get_stream_with_n_components(403);
        let dest_ledger = get_mock_ledger(0);
        let bs = DbStream::new(upstream, dest_ledger, logger.clone());
        let mut go_stream = bs.get_block_stream(0).unwrap();

        futures::executor::block_on(async move {
            let mut count = 0;
            while let Some(component) = go_stream.next().await {
                assert_eq!(component.unwrap().block_data.block().index, count);
                count += 1;
                if count == 402 {
                    break;
                }
            }

            log::info!(logger, "counted {} blocks", count + 1);
            assert_eq!(count, 402);
        });
    }
}
