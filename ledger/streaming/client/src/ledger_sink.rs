// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Creates a block sink stream factory

use futures::stream::{Stream, StreamExt};
use mc_common::logger::{log, Logger};
use mc_ledger_db::Ledger;
use mc_ledger_streaming_api::{
    BlockStream, BlockStreamComponents, Error as StreamError, Result as StreamResult,
};
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

    /// Pass through already synced blocks
    pass_through_synced_blocks: bool,

    /// Logger
    logger: Logger,
}

/// Object to manage the state of the ledger sink process
struct SinkManager {
    /// Channel to send blocks ledger sink thread to be synced
    sender: Sender<BlockStreamComponents>,

    /// Channel to receive blocks that have been synced
    receiver: Receiver<BlockStreamComponents>,

    /// Last block we've received from the upstream
    last_block_received: u64,

    /// Last block we've synced into the ledger
    last_block_synced: u64,

    /// Block at which we'll start syncing upstream blocks into the ledger
    sync_start_height: u64,

    /// Logger
    logger: Logger,
}

impl SinkManager {
    /// Create new manager for the block sink
    fn new(
        sender: Sender<BlockStreamComponents>,
        receiver: Receiver<BlockStreamComponents>,
        last_block_received: u64,
        last_block_synced: u64,
        sync_start_height: u64,
        logger: Logger,
    ) -> Self {
        SinkManager {
            sender,
            receiver,
            last_block_received,
            last_block_synced,
            sync_start_height,
            logger,
        }
    }

    /// Determine whether blocks we've synced are behind blocks we've been sent
    fn is_behind(&self) -> bool {
        self.last_block_received > self.last_block_synced
    }

    /// Determine if we're able to begin syncing blocks to the ledger
    fn can_start_sync(&self) -> bool {
        self.last_block_received >= self.sync_start_height
    }
}

impl<US: BlockStream + 'static, L: Ledger + Clone + 'static> BlockStream for DbStream<US, L> {
    type Stream<'s> = impl Stream<Item = StreamResult<BlockStreamComponents>> + 's;

    /// Get block stream that performs block sinking
    fn get_block_stream(&self, starting_height: u64) -> StreamResult<Self::Stream<'_>> {
        let num_blocks = self.ledger.num_blocks().unwrap();

        // Check to ensure we don't start more than 1 block ahead of what's currently in
        // the ledger (doing so will cause errors if we try to append a block)
        if num_blocks > 0 && starting_height - num_blocks > 0 {
            let err = StreamError::DBAccess(format!(
                "attempted to start {} blocks ahead of synced ledger height",
                num_blocks - starting_height
            ));
            log::error!(self.logger, "{:?}", err);
            return Err(err);
        }

        // If our local ledger is already ahead, but we still want to forward on blocks,
        // determine at which block we'll start syncing.
        let sync_start_height = if self.pass_through_synced_blocks && num_blocks > 0 {
            num_blocks + 1
        } else {
            // If we're not okay with it, throw an error
            if starting_height < num_blocks {
                let err = StreamError::DBAccess(format!(
                    "ledger height is currently: {} attempted to start at: {}",
                    num_blocks, starting_height
                ));
                log::error!(self.logger, "{:?}", err);
                return Err(err);
            }
            starting_height
        };

        // Get the upstream, start our thread, and initialize our sink management object
        let (tx, rcv) = start_sink_thread(self.ledger.clone(), self.logger.clone());
        let manager = SinkManager::new(tx, rcv, 0, 0, sync_start_height, self.logger.clone());
        let stream = Box::pin(self.upstream.get_block_stream(starting_height).unwrap());

        // Create the stream
        let output_stream =
            futures::stream::unfold((stream, manager), |(mut stream, mut manager)| async move {
                loop {
                    if let Some(component) = stream.next().await {
                        if let Ok(component) = component {
                            manager.last_block_received = component.block_data.block().index;
                            if manager.can_start_sync() {
                                // If we're above what's in the ledger, starting syncing the blocks
                                if let Err(_) = manager.sender.send(component).await {
                                    //TODO: Discuss whether thread error should stop stream or
                                    // self-heal TODO: it's
                                    // possible just to restart the upstream & thread here
                                    // TODO: so that the downstream doesn't necessarily notice
                                    log::error!(
                                        manager.logger,
                                        "ledger sync thread stopped, aborting stream"
                                    );
                                    break;
                                }
                            } else {
                                // Else pass them through
                                return Some((Ok(component), (stream, manager)));
                            }
                        } else {
                            return Some((component, (stream, manager)));
                        }
                    } else {
                        // If we're behind, wait for the rest of the blocks to sync then end
                        if manager.is_behind() {
                            log::debug!(
                                manager.logger,
                                "upstream terminated, waiting for the rest of the blocks to sync"
                            );
                        } else {
                            log::warn!(manager.logger, "upstream stopped, ending stream");
                            break;
                        }
                    }
                    if let Some(component) = manager.receiver.recv().await {
                        manager.last_block_synced = component.block_data.block().index;
                        return Some((Ok(component), (stream, manager)));
                    } else {
                        // TODO: Discuss whether we want to heal the stream or not
                        log::error!(manager.logger, "sink thread stopped, ending stream");
                        break;
                    }
                }
                None
            });
        Ok(Box::pin(output_stream))
    }
}

impl<US: BlockStream + 'static, L: Ledger + Clone + 'static> DbStream<US, L> {
    /// Initialize a stream factory from an upstream source
    pub fn new(upstream: US, ledger: L, pass_through_synced_blocks: bool, logger: Logger) -> Self {
        Self {
            upstream,
            ledger,
            pass_through_synced_blocks,
            logger,
        }
    }
}

fn start_sink_thread(
    mut ledger: impl Ledger + 'static,
    logger: Logger,
) -> (
    Sender<BlockStreamComponents>,
    Receiver<BlockStreamComponents>,
) {
    // Initialize sending and receiving channels
    let (send_out, rcv_out) = channel(10000);
    let (send_in, mut rcv_in): (
        Sender<BlockStreamComponents>,
        Receiver<BlockStreamComponents>,
    ) = channel(10000);

    // Launch ledger sink thread
    std::thread::spawn(move || {
        while let Some(component) = rcv_in.blocking_recv() {
            let signature = match component.block_data.signature() {
                Some(signature) => Some(signature.clone()),
                _ => None,
            };

            // If there's an error syncing the blocks, end thread
            if let Err(err) = ledger.append_block(
                component.block_data.block(),
                component.block_data.contents(),
                signature,
            ) {
                log::error!(
                    logger,
                    "Error {:?} occurred during attempt to write block {}",
                    err,
                    component.block_data.block().index,
                );
                break;
            };

            // If message channels are broken, end thread
            if let Err(err) = send_out.try_send(component) {
                log::error!(
                    logger,
                    "sending component to stream failed with error {:?}",
                    err
                );
                break;
            }
        }
    });
    (send_in, rcv_out)
}

#[cfg(test)]
mod tests {

    use super::*;
    use mc_common::logger::{test_with_logger, Logger};
    use mc_ledger_db::test_utils::get_mock_ledger;
    use mc_ledger_streaming_api::test_utils::{make_components, stream};

    #[test_with_logger]
    fn assert_pass_through_and_storage(logger: Logger) {
        let components = make_components(403);
        let upstream = stream::mock_stream_from_components(components);
        let dest_ledger = get_mock_ledger(0);
        let bs = DbStream::new(upstream, dest_ledger, true, logger);
        let mut go_stream = bs.get_block_stream(0).unwrap();

        futures::executor::block_on(async move {
            let mut count = 0;
            while let Some(component) = go_stream.next().await {
                assert_eq!(component.unwrap().block_data.block().index, count);
                count += 1;
            }

            assert_eq!(count, 403);
        });
    }
}
