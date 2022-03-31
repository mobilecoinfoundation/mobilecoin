// Copyright (c) 2018-2022 The MobileCoin Foundation

//! A BlockStream that backfills missing indices from a given BlockFetcher.

use displaydoc::Display;
use futures::{FutureExt, Stream, StreamExt};
use mc_common::logger::{log, Logger};
use mc_ledger_streaming_api::{BlockFetcher, BlockStream, BlockStreamComponents, Result};
use mc_transaction_core::BlockIndex;
use std::pin::Pin;

/// A [BlockStream] that backfills another [BlockStream] using a [BlockFetcher].
#[derive(Debug, Display)]
pub struct BackfillingStream<S: BlockStream, F: BlockFetcher> {
    upstream: S,
    fetcher: F,
    logger: Logger,
}

impl<S: BlockStream, F: BlockFetcher> BackfillingStream<S, F> {
    /// Instantiate a [BackfillingStream].
    pub fn new(upstream: S, fetcher: F, logger: Logger) -> Self {
        Self {
            upstream,
            fetcher,
            logger,
        }
    }
}

impl<S: BlockStream, F: BlockFetcher> BlockStream for BackfillingStream<S, F> {
    type Stream<'s>
    where
        Self: 's,
    = impl Stream<Item = Result<BlockStreamComponents>> + 's;

    fn get_block_stream(&self, starting_height: u64) -> Result<Self::Stream<'_>> {
        self.upstream
            .get_block_stream(starting_height)
            .map(|upstream| {
                backfill_stream(
                    upstream,
                    starting_height,
                    &self.fetcher,
                    self.logger.clone(),
                )
            })
    }
}

fn backfill_stream<'f, S: Stream<Item = Result<BlockStreamComponents>> + 'f, F: BlockFetcher>(
    upstream: S,
    starting_height: u64,
    fetcher: &'f F,
    logger: Logger,
) -> impl Stream<Item = Result<BlockStreamComponents>> + 'f {
    use futures::stream::{empty, once};

    let mut prev_index: Option<BlockIndex> = None;
    upstream.flat_map(
        move |result| -> Pin<Box<dyn Stream<Item = Result<BlockStreamComponents>>>> {
            let next_index = prev_index.map_or_else(|| starting_height, |index| index + 1);
            match result {
                Ok(components) => {
                    let index = components.block_data.block().index;
                    if prev_index.is_some() && index <= prev_index.unwrap() {
                        log::info!(
                            logger,
                            "Ignoring streamed block with index={} since last fetched index={}",
                            index,
                            prev_index.unwrap()
                        );
                        return Box::pin(empty());
                    }

                    let item_stream = once(async { Ok(components) });
                    if index == next_index {
                        prev_index = Some(index);
                        Box::pin(item_stream)
                    } else {
                        let start = prev_index.unwrap_or(starting_height);
                        prev_index = Some(index);
                        let backfill = fetcher.fetch_range(start..index);
                        Box::pin(backfill.chain(item_stream))
                    }
                }
                Err(upstream_error) => {
                    log::debug!(
                        logger,
                        "Got an error from upstream [prev_index={:?}]: {}",
                        &prev_index,
                        upstream_error
                    );
                    // If we get an error, fetch one item.
                    let future = fetcher.fetch_single(next_index);
                    prev_index = Some(next_index);
                    Box::pin(future.into_stream())
                }
            }
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::executor::block_on;
    use mc_common::logger::test_with_logger;
    use mc_ledger_streaming_api::{
        test_utils::{make_components, MockFetcher, MockStream},
        Error,
    };

    #[test_with_logger]
    fn handles_unordered_stream(logger: Logger) {
        let mut components = make_components(5);
        // Mini-shuffle.
        components.swap(0, 2);
        components.swap(1, 3);
        let upstream = MockStream::from_components(components);
        let fetcher = MockFetcher::new(5);
        let source = BackfillingStream::new(upstream, fetcher, logger);

        let result_fut = source
            .get_block_stream(0)
            .expect("Failed to start upstream")
            .map(|resp| resp.expect("expected no errors").block_data.block().index)
            .collect::<Vec<_>>();

        let result = block_on(result_fut);
        assert_eq!(result, vec![0, 1, 2, 3, 4])
    }

    #[test_with_logger]
    fn backfills_on_error(logger: Logger) {
        let mut items: Vec<Result<BlockStreamComponents>> =
            make_components(5).into_iter().map(Ok).collect();
        // Error at the beginning.
        items[0] = Err(Error::Grpc("start".to_owned()));
        // Mid-stream error.
        items[2] = Err(Error::Grpc("mid".to_owned()));
        // Error at the end.
        items[4] = Err(Error::Grpc("end".to_owned()));

        let upstream = MockStream::from_items(items);
        let fetcher = MockFetcher::new(5);
        let source = BackfillingStream::new(upstream, fetcher, logger);

        let result_fut = source
            .get_block_stream(0)
            .expect("Failed to start upstream")
            .map(|resp| resp.expect("expected no errors").block_data.block().index)
            .collect::<Vec<_>>();

        let result = block_on(result_fut);
        assert_eq!(result, vec![0, 1, 2, 3, 4]);
    }
}
