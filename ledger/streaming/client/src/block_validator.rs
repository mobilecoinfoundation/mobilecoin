// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Stream that validates blocks

use futures::{future, Stream, StreamExt};
use mc_common::{
    logger::{log, Logger},
    HashSet,
};
use mc_ledger_db::Ledger;
use mc_ledger_streaming_api::{BlockData, BlockIndex, Error, Result, Streamer};
use mc_transaction_core::{ring_signature::KeyImage, BlockID};

/// Create stream factory for validating individual blocks within a stream.
/// Valid blocks will passed on, blocks that don't pass will pass an error.
#[derive(Debug, Clone)]
pub struct BlockValidator<
    US: Streamer<Result<BlockData>, BlockIndex> + 'static,
    L: Ledger + 'static,
> {
    upstream: US,
    ledger: Option<L>,
    logger: Logger,
}

impl<US: Streamer<Result<BlockData>, BlockIndex> + 'static, L: Ledger + 'static>
    BlockValidator<US, L>
{
    /// Create new block validation stream
    pub fn new(upstream: US, ledger: Option<L>, logger: Logger) -> Self {
        Self {
            upstream,
            ledger,
            logger,
        }
    }
}

impl<US: Streamer<Result<BlockData>, BlockIndex>, L: Ledger + Clone + 'static>
    Streamer<Result<BlockData>, BlockIndex> for BlockValidator<US, L>
{
    type Stream<'s> = impl Stream<Item = Result<BlockData>> + 's where US: 's;

    /// Get block stream that performs validation
    fn get_stream(&self, starting_height: BlockIndex) -> Result<Self::Stream<'_>> {
        //get block id from ledger if it exists, else initialize to an empty value
        let ledger = self.ledger.clone();
        let prev_block_id = if self.ledger.is_some() && starting_height > 0 {
            ledger.as_ref().unwrap().get_block(starting_height - 1)?.id
        } else {
            BlockID::default()
        };
        let additional_key_images: HashSet<KeyImage> = HashSet::default();

        log::info!(self.logger, "Creating block validation stream");
        let stream = self.upstream.get_stream(starting_height)?;

        let result = stream.scan(
            (
                ledger,
                prev_block_id,
                additional_key_images,
                starting_height,
            ),
            |state, result| {
                match result {
                    Ok(block_data) => {
                        let (ledger, prev_block_id, additional_key_images, starting_height) = state;

                        let block = block_data.block();
                        let block_contents = block_data.contents();

                        if *starting_height == block.index && ledger.is_none() && block.index > 0 {
                            *prev_block_id = block.parent_id.clone();
                        }

                        // Check if parent block matches last block seen
                        if &block.parent_id != prev_block_id {
                            return future::ready(Some(Err(Error::BlockValidation(
                                "Block parent ID doesn't match".to_string(),
                            ))));
                        }

                        // Check if key images already in ledger
                        if let Some(ledger) = ledger {
                            for key_image in &block_contents.key_images {
                                // Check if the key image is already in the local ledger.
                                match ledger.contains_key_image(key_image) {
                                    Ok(contains_key_image) => {
                                        if contains_key_image
                                            || additional_key_images.contains(key_image)
                                        {
                                            return future::ready(Some(Err(
                                                Error::BlockValidation(
                                                    "Contains spent key image".to_string(),
                                                ),
                                            )));
                                        }
                                    }
                                    Err(err) => {
                                        return future::ready(Some(Err(Error::DBAccess(
                                            err.to_string(),
                                        ))));
                                    }
                                }
                                additional_key_images.insert(*key_image);
                            }
                        }

                        // The block's ID must agree with the merkle hash of its transactions.
                        if !block.is_block_id_valid() {
                            return future::ready(Some(Err(Error::BlockValidation(
                                "Invalid BlockID".to_string(),
                            ))));
                        }

                        *prev_block_id = block.id.clone();
                        future::ready(Some(Ok(block_data)))
                    }
                    Err(err) => future::ready(Some(Err(err))),
                }
            },
        );
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mc_common::logger::{test_with_logger, Logger};
    use mc_ledger_db::test_utils::{get_mock_ledger, MockLedger};
    use mc_ledger_streaming_api::test_utils::{make_blocks, MockStream};

    #[test_with_logger]
    fn validation_without_ledger(logger: Logger) {
        let blocks = make_blocks(20);
        let upstream = MockStream::from_blocks(blocks);
        let ledger: Option<MockLedger> = None;
        let block_validator = BlockValidator::new(upstream, ledger, logger);

        futures::executor::block_on(async move {
            let mut stream = block_validator.get_stream(2).unwrap();
            let mut index = 0;
            while let Some(data) = stream.next().await {
                index = data.unwrap().block().index;
            }
            assert_eq!(index, 19);
        });
    }

    #[test_with_logger]
    fn validation_from_zero_block(logger: Logger) {
        let blocks = make_blocks(20);
        let upstream = MockStream::from_blocks(blocks);
        let ledger: Option<MockLedger> = None;
        let block_validator = BlockValidator::new(upstream, ledger, logger);

        futures::executor::block_on(async move {
            let mut stream = block_validator.get_stream(0).unwrap();
            let mut index = 0;
            while let Some(data) = stream.next().await {
                index = data.unwrap().block().index;
            }

            assert_eq!(index, 19);
        });
    }

    #[test_with_logger]
    fn validation_with_ledger(logger: Logger) {
        let mut mock_ledger = get_mock_ledger(0);
        let blocks = make_blocks(20);
        for block_data in blocks.iter().take(2) {
            mock_ledger
                .append_block(
                    block_data.block(),
                    block_data.contents(),
                    block_data.signature().clone(),
                )
                .unwrap();
        }
        let upstream = MockStream::from_blocks(blocks);
        let block_validator = BlockValidator::new(upstream, Some(mock_ledger), logger);

        futures::executor::block_on(async move {
            let mut stream = block_validator.get_stream(2).unwrap();
            let mut index = 0;
            while let Some(data) = stream.next().await {
                index = data.unwrap().block().index;
            }

            assert_eq!(index, 19);
        });
    }

    #[test_with_logger]
    fn invalid_previous_blocks_fail(logger: Logger) {
        let mock_ledger = get_mock_ledger(4);
        let upstream = MockStream::from_blocks(make_blocks(4));
        let block_validator = BlockValidator::new(upstream, Some(mock_ledger), logger.clone());

        futures::executor::block_on(async move {
            let mut stream = block_validator.get_stream(2).unwrap();
            if let Some(data) = stream.next().await {
                log::info!(logger, "{:?}", data);
                assert!(matches!(data, Err(Error::BlockValidation(_))));
            }
        });
    }

    #[test_with_logger]
    fn pre_existing_key_images_in_ledger_fail(logger: Logger) {
        let mock_ledger = get_mock_ledger(4);
        let blocks = (1..3)
            .map(|i| mock_ledger.get_block_data(i).unwrap())
            .collect::<Vec<_>>();
        let upstream = MockStream::from_blocks(blocks);
        let block_validator = BlockValidator::new(upstream, Some(mock_ledger), logger);

        futures::executor::block_on(async move {
            let mut stream = block_validator.get_stream(1).unwrap();
            if let Some(data) = stream.next().await {
                assert!(matches!(data, Err(Error::BlockValidation(_))));
            }
        });
    }
}
