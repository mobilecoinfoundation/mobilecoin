// Copyright (c) 2018-2022 The MobileCoin Foundation

//! A [Streamer] that backfills another [Streamer] using a [Fetcher].

use displaydoc::Display;
use futures::{FutureExt, Stream, StreamExt};
use mc_common::logger::{log, Logger};
use mc_ledger_streaming_api::{BlockData, BlockIndex, Fetcher, Result, Streamer};
use std::{ops::Range, pin::Pin};

/// A [Streamer] that backfills another [Streamer] using a [Fetcher].
#[derive(Debug, Display)]
pub struct BackfillingStream<
    S: Streamer<Result<BlockData>, BlockIndex>,
    F: Fetcher<Result<BlockData>, BlockIndex, Range<BlockIndex>>,
> {
    upstream: S,
    fetcher: F,
    logger: Logger,
}

impl<
        S: Streamer<Result<BlockData>, BlockIndex>,
        F: Fetcher<Result<BlockData>, BlockIndex, Range<BlockIndex>>,
    > BackfillingStream<S, F>
{
    /// Instantiate a [BackfillingStream].
    pub fn new(upstream: S, fetcher: F, logger: Logger) -> Self {
        Self {
            upstream,
            fetcher,
            logger,
        }
    }
}

impl<
        S: Streamer<Result<BlockData>, BlockIndex>,
        F: Fetcher<Result<BlockData>, BlockIndex, Range<BlockIndex>>,
    > Streamer<Result<BlockData>, BlockIndex> for BackfillingStream<S, F>
{
    type Stream<'s> = impl Stream<Item = Result<BlockData>> + 's where Self: 's;

    fn get_stream(&self, starting_height: BlockIndex) -> Result<Self::Stream<'_>> {
        self.upstream.get_stream(starting_height).map(|upstream| {
            backfill_stream(
                upstream,
                starting_height,
                &self.fetcher,
                self.logger.clone(),
            )
        })
    }
}

fn backfill_stream<
    's,
    S: Stream<Item = Result<BlockData>> + 's,
    F: Fetcher<Result<BlockData>, BlockIndex, Range<BlockIndex>>,
>(
    upstream: S,
    starting_height: u64,
    fetcher: &'s F,
    logger: Logger,
) -> impl Stream<Item = Result<BlockData>> + 's {
    use futures::stream::{empty, once};

    // Track the index of the last received block, so we know whether to filter,
    // backfill, or just return the next block.
    let mut prev_index: Option<BlockIndex> = None;
    // We may need to return more than one item, so we use flat_map.
    upstream.flat_map(
        // The stream types are quite different across the different cases, so Box the
        // intermediate stream.
        move |result| -> Pin<Box<dyn Stream<Item = Result<BlockData>>>> {
            let next_index = prev_index.map_or_else(|| starting_height, |prev| prev + 1);
            match result {
                Ok(block_data) => {
                    let index = block_data.block().index;
                    // Check for whether we already yielded this index.
                    if prev_index.is_some() && index <= prev_index.unwrap() {
                        log::info!(
                            logger,
                            "Ignoring streamed block with index={} since last fetched index={}",
                            index,
                            prev_index.unwrap()
                        );
                        return Box::pin(empty());
                    }

                    let item_stream = once(async { Ok(block_data) });
                    if index == next_index {
                        // Happy path: We got another consecutive item, so just return that.
                        prev_index = Some(index);
                        Box::pin(item_stream)
                    } else {
                        // Need to backfill up to the current index.
                        let start = prev_index.unwrap_or(starting_height);
                        prev_index = Some(index);
                        let backfill = fetcher.fetch_multiple(start..index);
                        Box::pin(backfill.chain(item_stream))
                    }
                }
                // If we get an error, try fetching one item.
                Err(upstream_error) => {
                    log::debug!(
                        logger,
                        "Got an error from upstream [prev_index={:?}]: {}",
                        &prev_index,
                        upstream_error
                    );
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
        test_utils::{make_blocks, MockFetcher, MockStream},
        Error,
    };

    #[test_with_logger]
    fn handles_unordered_stream(logger: Logger) {
        let mut blocks = make_blocks(5);
        // Mini-shuffle.
        blocks.swap(0, 2);
        blocks.swap(1, 3);
        let upstream = MockStream::from_blocks(blocks);
        let fetcher = MockFetcher::new(5);
        let source = BackfillingStream::new(upstream, fetcher, logger);

        let result_fut = source
            .get_stream(0)
            .expect("Failed to start upstream")
            .map(|resp| resp.expect("expected no errors").block().index)
            .collect::<Vec<_>>();

        let result = block_on(result_fut);
        assert_eq!(result, vec![0, 1, 2, 3, 4])
    }

    #[test_with_logger]
    fn backfills_on_error(logger: Logger) {
        let mut items: Vec<Result<BlockData>> = make_blocks(5).into_iter().map(Ok).collect();
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
            .get_stream(0)
            .expect("Failed to start upstream")
            .map(|resp| resp.expect("expected no errors").block().index)
            .collect::<Vec<_>>();

        let result = block_on(result_fut);
        assert_eq!(result, vec![0, 1, 2, 3, 4]);
    }
}
