// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Stream that validates block components

use futures::{future, Stream, StreamExt};
use mc_common::{
    logger::{log, Logger},
    HashSet,
};
use mc_ledger_db::Ledger;
use mc_ledger_streaming_api::{
    BlockStream, BlockStreamComponents, Error as StreamError, Result as StreamResult,
};
use mc_transaction_core::{compute_block_id, ring_signature::KeyImage, Block};

/// Create stream factory for validating individual blocks within a stream.
/// Valid blocks will passed on, blocks that don't pass will pass an error.
pub struct BlockValidator<US: BlockStream + 'static, L: Ledger + 'static> {
    upstream: US,
    start_block: Block,
    ledger: Option<L>,
    logger: Logger,
}

impl<US: BlockStream + 'static, L: Ledger> BlockValidator<US, L> {
    /// Create new block validation stream
    pub fn new(upstream: US, start_block: Block, ledger: Option<L>, logger: Logger) -> Self {
        Self {
            upstream,
            start_block,
            ledger,
            logger,
        }
    }
}

impl<US: BlockStream + 'static, L: Ledger + Clone + 'static> BlockStream for BlockValidator<US, L> {
    type Stream = impl Stream<Item = StreamResult<BlockStreamComponents>>;

    /// Get block stream that performs validation
    fn get_block_stream(&self, starting_height: u64) -> StreamResult<Self::Stream> {
        //let logger = self.logger.clone();
        let prev_block_id = self.start_block.id.clone();
        let ledger = self.ledger.clone();
        let additional_key_images: HashSet<KeyImage> = HashSet::default();

        log::info!(self.logger, "Creating block validation stream");
        let stream = self.upstream.get_block_stream(starting_height)?;

        Ok(stream.scan(
            (ledger, prev_block_id, additional_key_images),
            |state, component| {
                match component {
                    Ok(component) => {
                        let block = component.block_data.block();
                        let block_contents = component.block_data.contents();

                        // Check if parent block matches last block seen
                        if block.parent_id != state.1 {
                            return future::ready(Some(Err(StreamError::BlockValidation(
                                "Block parent ID doesn't match".to_string(),
                            ))));
                        }

                        // Check if key images already in ledger
                        if let Some(ledger) = &state.0 {
                            for key_image in &block_contents.key_images {
                                // Check if the key image is already in the local ledger.
                                match ledger.contains_key_image(key_image) {
                                    Ok(contains_key_image) => {
                                        if contains_key_image || state.2.contains(key_image) {
                                            return future::ready(Some(Err(
                                                StreamError::BlockValidation(
                                                    "Contains spent key image".to_string(),
                                                ),
                                            )));
                                        }
                                    }
                                    Err(_) => {
                                        return future::ready(Some(Err(StreamError::DBError)));
                                    }
                                }
                                state.2.insert(*key_image);
                            }
                        }

                        // Compute the hash of the block
                        let derived_block_id = compute_block_id(
                            block.version,
                            &block.parent_id,
                            block.index,
                            block.cumulative_txo_count,
                            &block.root_element,
                            &block_contents.hash(),
                        );

                        // The block's ID must agree with the merkle hash of its transactions.
                        if block.id != derived_block_id {
                            return future::ready(Some(Err(StreamError::BlockValidation(
                                "Hash of transactions don't match claimed block id".to_string(),
                            ))));
                        }

                        state.1 = block.id.clone();
                        future::ready(Some(Ok(component)))
                    }
                    Err(err) => future::ready(Some(Err(err))),
                }
            },
        ))
    }
}

#[cfg(test)]
mod tests {
    use mc_common::logger::{log, test_with_logger, Logger};
    use mc_ledger_db::test_utils::{get_mock_ledger, MockLedger};
    use mc_ledger_streaming_api::test_utils::{stream, stream::SimpleMockStream};
    use mc_transaction_core::BlockIndex;

    use super::*;

    #[test_with_logger]
    fn validation_without_ledger(logger: Logger) {
        let simple_stream = stream::get_stream_with_n_components(300);
        let start_block = simple_stream.get_block(1);
        let block_validator: BlockValidator<SimpleMockStream, MockLedger> =
            BlockValidator::new(simple_stream, start_block, None, logger.clone());

        futures::executor::block_on(async move {
            let mut stream = block_validator.get_block_stream(2).unwrap();
            let mut index: BlockIndex = 0;
            while let Some(data) = stream.next().await {
                index = data.unwrap().block_data.block().index;
            }

            log::info!(
                logger,
                "validated {} blocks without ledger validation",
                index
            );
            assert_eq!(index, 299);
        });
    }

    #[test_with_logger]
    fn validation_with_ledger(logger: Logger) {
        let simple_stream = stream::get_stream_with_n_components(300);
        let start_block = simple_stream.get_block(1);
        let mock_ledger = get_mock_ledger(5);
        let block_validator: BlockValidator<SimpleMockStream, MockLedger> = BlockValidator::new(
            simple_stream,
            start_block,
            Some(mock_ledger),
            logger.clone(),
        );

        futures::executor::block_on(async move {
            let mut stream = block_validator.get_block_stream(2).unwrap();
            let mut index: BlockIndex = 0;
            while let Some(data) = stream.next().await {
                index = data.unwrap().block_data.block().index;
            }

            log::info!(logger, "validated {} blocks with ledger validation", index);
            assert_eq!(index, 299);
        });
    }

    #[test_with_logger]
    fn invalid_previous_blocks_fail(logger: Logger) {
        let simple_stream = stream::get_stream_with_n_components(300);
        let start_block = simple_stream.get_block(5);
        let block_validator: BlockValidator<SimpleMockStream, MockLedger> =
            BlockValidator::new(simple_stream, start_block, None, logger.clone());

        futures::executor::block_on(async move {
            let mut stream = block_validator.get_block_stream(2).unwrap();
            if let Some(data) = stream.next().await {
                assert!(matches!(data, Err(StreamError::BlockValidation(_))));
            }
        });
    }

    #[test_with_logger]
    fn pre_existing_key_images_in_ledger_fail(logger: Logger) {
        let simple_stream = stream::get_stream_with_n_components(300);
        let start_block = simple_stream.get_block(1);
        let mut mock_ledger = get_mock_ledger(0);

        for i in 0..2 {
            let pre_existing_block_data = simple_stream.get_block_data(i);
            mock_ledger
                .append_block(
                    pre_existing_block_data.block(),
                    pre_existing_block_data.contents(),
                    pre_existing_block_data.signature().clone(),
                )
                .unwrap();
        }

        let block_validator: BlockValidator<SimpleMockStream, MockLedger> = BlockValidator::new(
            simple_stream,
            start_block,
            Some(mock_ledger),
            logger.clone(),
        );

        futures::executor::block_on(async move {
            let mut stream = block_validator.get_block_stream(1).unwrap();
            if let Some(data) = stream.next().await {
                assert!(matches!(data, Err(StreamError::BlockValidation(_))));
            }
        });
    }
}
