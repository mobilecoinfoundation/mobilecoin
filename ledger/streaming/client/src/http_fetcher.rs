// Copyright (c) 2018-2022 The MobileCoin Foundation

//! A [BlockFetcher] that downloads [ArchiveBlocks] from the given URI.

use crate::BlockchainUrl;
use displaydoc::Display;
use futures::{lock::Mutex, Future, FutureExt, Stream, StreamExt};
use mc_api::blockchain::{ArchiveBlock, ArchiveBlocks};
use mc_common::{
    logger::{log, o, Logger},
    LruCache,
};
use mc_ledger_streaming_api::{
    archive_blocks_to_components, BlockFetcher, BlockStreamComponents, Error, Result,
};
use mc_transaction_core::{Block, BlockIndex};
use protobuf::Message;
use reqwest::Client;
use std::{
    convert::TryFrom,
    ops::Range,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
};
use url::Url;

/// Default merged blocks bucket sizes. Merged blocks are objects that contain
/// multiple consecutive blocks that have been bundled together in order to
/// reduce the amount of requests needed to get the block data.
/// Notes:
/// - This should match the defaults in `mc-ledger-distribution`.
/// - This must be sorted in descending order.
pub const DEFAULT_MERGED_BLOCKS_BUCKET_SIZES: &[u64] = &[10000, 1000, 100];

/// Maximum number of pre-fetched blocks to keep in cache.
pub const MAX_PREFETCHED_BLOCKS: usize = 10000;

/// A [BlockFetcher] that downloads [ArchiveBlocks] from the given URI.
#[derive(Debug, Display)]
pub struct HttpBlockFetcher {
    /// The blockchain URL.
    url: BlockchainUrl,

    /// The [reqwest::Client].
    client: Client,

    /// Merged blocks bucket sizes to attempt fetching.
    merged_blocks_bucket_sizes: Vec<u64>,

    /// Cache mapping a [BlockIndex] to [BlockStreamComponents], filled by
    /// merged blocks when possible.
    cache: Arc<Mutex<LruCache<BlockIndex, BlockStreamComponents>>>,

    /// Number of successful cache hits when attempting to get block data.
    /// Used for debugging purposes.
    hits: Arc<AtomicU64>,

    /// Number of cache misses when attempting to get block data.
    /// Used for debugging purposes.
    misses: Arc<AtomicU64>,

    /// Logger.
    logger: Logger,
}

impl HttpBlockFetcher {
    /// Instantiate an [HttpBlockFetcher] downloading from the given
    /// [BlockchainUrl].
    pub fn new(url: BlockchainUrl, logger: Logger) -> Result<Self> {
        let logger = logger.new(o!("url" => url.to_string()));
        let client = Client::builder()
            .build()
            .map_err(|e| Error::Other(format!("Failed to create reqwest client: {}", e)))?;
        Ok(Self {
            url,
            client,
            cache: Arc::new(Mutex::new(LruCache::new(MAX_PREFETCHED_BLOCKS))),
            merged_blocks_bucket_sizes: DEFAULT_MERGED_BLOCKS_BUCKET_SIZES.to_vec(),
            hits: Arc::new(AtomicU64::new(0)),
            misses: Arc::new(AtomicU64::new(0)),
            logger,
        })
    }

    /// Instantiate an [HttpBlockFetcher] downloading from the given base [Url].
    pub fn from_url(base_url: Url, logger: Logger) -> Result<Self> {
        let url_str = base_url.to_string();
        let url = BlockchainUrl::new(base_url)
            .map_err(|e| Error::Other(format!("Failed to parse URL '{}': {}", url_str, e)))?;
        Self::new(url, logger)
    }

    /// Set the `merged_blocks_bucket_sizes`.
    pub fn set_merged_blocks_bucket_sizes(&mut self, bucket_sizes: &[u64]) {
        const MAX: u64 = MAX_PREFETCHED_BLOCKS as u64;
        assert!(
            bucket_sizes.iter().all(|n| *n < MAX),
            "max bucket size is {}",
            MAX
        );
        self.merged_blocks_bucket_sizes = bucket_sizes.to_vec();
    }

    /// Fetches a block with the given index.
    /// Optionally validates the fetched block matches an expected block.
    pub async fn get_block_data_by_index(
        &self,
        block_index: BlockIndex,
        expected_block: Option<&Block>,
    ) -> Result<BlockStreamComponents> {
        // Try and see if we can get this block from our cache.
        if let Some(cached) = self.get_cached(block_index, expected_block).await {
            return Ok(cached);
        }

        // Try and fetch a merged block if we stand a chance of finding one.
        for bucket in &self.merged_blocks_bucket_sizes {
            if block_index % bucket == 0 {
                if let Ok(num_merged) = self.get_merged(*bucket, block_index).await {
                    log::debug!(
                        self.logger,
                        "Got a merged block for #{} (bucket size {}): {} entries @ {:?}",
                        block_index,
                        bucket,
                        num_merged,
                        std::thread::current().name()
                    );

                    // Supposedly we have the block we asked for in the cache now.
                    if let Some(cached) = self.get_cached(block_index, expected_block).await {
                        return Ok(cached);
                    }
                }
            }
        }

        // Construct URL for the block we are trying to fetch.
        let url = self.url.block_url(block_index).map_err(|e| {
            Error::Other(format!(
                "failed to get URL for block with index {}: {}",
                block_index, e
            ))
        })?;

        // Try and get the block.
        log::debug!(
            self.logger,
            "Attempting to fetch block {} from {}",
            block_index,
            url
        );

        let archive_block: ArchiveBlock = self.fetch_protobuf_object(&url).await?;
        let components = BlockStreamComponents::try_from(&archive_block)?;

        // If the caller is expecting a specific block, check that we received data for
        // the block they asked for
        if let Some(expected_block) = expected_block {
            if expected_block != components.block_data.block() {
                return Err(Error::Other(format!(
                    "Block data mismatch (downloaded from {})",
                    url
                )));
            }
        }

        let hits = self.hits.load(Ordering::SeqCst);
        let misses = self.misses.fetch_add(1, Ordering::SeqCst);
        log::trace!(
            self.logger,
            "Cache miss while getting block #{} (total hits/misses: {}/{})",
            components.block_data.block().index,
            hits,
            misses
        );

        // Got what we wanted!
        Ok(components)
    }

    async fn get_cached(
        &self,
        block_index: BlockIndex,
        expected_block: Option<&Block>,
    ) -> Option<BlockStreamComponents> {
        // Sanity test.
        if let Some(expected_block) = expected_block {
            assert_eq!(block_index, expected_block.index);
        }

        let mut cache = self.cache.lock().await;

        // Note: If this block index is in the cache, we take it out under the
        // assumption that our primary caller, LedgerSyncService, is not
        // going to try and fetch the same block twice if it managed to get
        // a valid block.
        cache.pop(&block_index).and_then(|components| {
            let index = components.block_data.block().index;
            // If we expect a specific Block then compare what the cache had with what we
            // expect.
            if let Some(expected_block) = expected_block {
                if components.block_data.block() == expected_block {
                    let hits = self.hits.fetch_add(1, Ordering::SeqCst);
                    let misses = self.misses.load(Ordering::SeqCst);
                    log::trace!(
                        self.logger,
                        "Got block #{} from cache (total hits/misses: {}/{})",
                        block_index,
                        hits,
                        misses
                    );
                    Some(components)
                } else {
                    log::warn!(
                        self.logger,
                        "Got cached block {:?} but actually requested {:?}! This should not happen",
                        components.block_data.block(),
                        expected_block
                    );
                    None
                }
            } else if index == block_index {
                Some(components)
            } else {
                log::error!(
                    self.logger,
                    "Got cached block #{} but actually requested #{}! This should not happen",
                    index,
                    block_index
                );
                None
            }
        })
    }

    async fn fetch_protobuf_object<M>(&self, url: &Url) -> Result<M>
    where
        M: Message,
    {
        let bytes = self
            .client
            .get(url.as_str())
            .send()
            .await
            .map_err(|err| Error::Other(format!("Failed to fetch '{}': {}", url, err)))?
            .bytes()
            .await
            .map_err(|err| {
                Error::Other(format!(
                    "Failed to get response bytes for '{}': {}",
                    url, err
                ))
            })?;

        if bytes.is_empty() {
            Err(Error::Other(format!("Got empty response for {}", url)))
        } else {
            Ok(M::parse_from_bytes(&bytes)?)
        }
    }

    async fn get_merged(&self, bucket_size: u64, first_index: BlockIndex) -> Result<usize> {
        log::debug!(
            self.logger,
            "Attempting to fetch a merged block for #{} (bucket size {})",
            first_index,
            bucket_size
        );
        debug_assert!(
            first_index % bucket_size == 0,
            "block index {} is not divisible by bucket size {}",
            first_index,
            bucket_size
        );
        let url = self
            .url
            .merged_block_url(bucket_size, first_index)
            .map_err(|e| {
                Error::Other(format!(
                    "Failed to get URL for merged block with size {} and first index {}: {}",
                    bucket_size, first_index, e
                ))
            })?;
        let archive_blocks: ArchiveBlocks = self.fetch_protobuf_object(&url).await?;
        let merged = archive_blocks_to_components(&archive_blocks)?;
        let result = merged.len();
        log::debug!(self.logger, "Got {} merged results from {}", result, url);

        {
            let mut cache = self.cache.lock().await;
            for components in merged.into_iter() {
                cache.put(components.block_data.block().index, components);
            }
        }
        Ok(result)
    }

    async fn get_range_prefer_merged(
        &self,
        indexes: Range<BlockIndex>,
    ) -> impl Stream<Item = Result<BlockStreamComponents>> + '_ {
        let n = indexes.end - indexes.start - 1;
        for bucket in &self.merged_blocks_bucket_sizes {
            if *bucket < n {
                continue;
            }
            let block_start = indexes.start - indexes.start % *bucket;
            if let Ok(num_merged) = self.get_merged(*bucket, block_start).await {
                if num_merged > 0 {
                    break;
                }
            }
        }

        futures::stream::iter(indexes).then(move |idx| self.get_block_data_by_index(idx, None))
    }
}

impl BlockFetcher for HttpBlockFetcher {
    type Single<'s> = impl Future<Output = Result<BlockStreamComponents>> + 's;
    type Multiple<'s> = impl Stream<Item = Result<BlockStreamComponents>> + 's;

    fn fetch_single(&self, index: BlockIndex) -> Self::Single<'_> {
        self.get_block_data_by_index(index, None)
    }

    fn fetch_range(&self, indexes: Range<BlockIndex>) -> Self::Multiple<'_> {
        self.get_range_prefer_merged(indexes).flatten_stream()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::future::ready;
    use mc_ledger_streaming_api::{components_to_archive_blocks, test_utils::make_components};
    use mockito::{mock, server_url};
    use std::str::FromStr;

    /// Creates a test logger with the given test name.
    // Necessary because tokio::test rejects test methods with parameters.
    #[track_caller]
    fn create_logger() -> Logger {
        let name = format!("{}::{}", module_path!(), std::panic::Location::caller());
        mc_common::logger::create_test_logger(name)
    }

    fn create_fetcher() -> HttpBlockFetcher {
        let url = BlockchainUrl::from_str(&server_url()).expect("BlockchainUrl::from_str");
        HttpBlockFetcher::new(url, create_logger()).expect("HttpBlockFetcher::new")
    }

    #[tokio::test]
    async fn fetch_single() {
        let items = make_components(1);
        let expected = ArchiveBlock::from(&items[0]);
        let mock_request = mock("GET", "/00/00/00/00/00/00/00/0000000000000001.pb")
            .with_body(expected.write_to_bytes().expect("expected.write_to_bytes"))
            .create();

        let result = create_fetcher().fetch_single(1).await;
        mock_request.assert();
        let data = result.expect("expected data");
        // TODO(#1682): Include QuorumSet, VerificationReport.
        assert_eq!(data.block_data, items[0].block_data);
    }

    #[tokio::test]
    async fn fetch_multiple_merged() {
        let items = make_components(10);
        let expected = components_to_archive_blocks(&items);
        let mock_request = mock("GET", "/merged-10/00/00/00/00/00/00/00/0000000000000000.pb")
            .with_body(expected.write_to_bytes().expect("expected.write_to_bytes"))
            .create();

        let mut fetcher = create_fetcher();
        fetcher.set_merged_blocks_bucket_sizes(&[10]);
        fetcher
            .fetch_range(0..10)
            .enumerate()
            .for_each_concurrent(None, move |(index, result)| {
                let components =
                    result.expect(&format!("unexpected error for item #{}", index + 1));
                // TODO(#1682): Include QuorumSet, VerificationReport.
                assert_eq!(components.block_data, items[index].block_data);
                ready(())
            })
            .await;
        mock_request.assert();
    }

    #[tokio::test]
    async fn fetch_multiple_no_merged() {
        let items = make_components(10);
        let mock_requests = items
            .iter()
            .map(|components| {
                let index = components.block_data.block().index;
                let bytes = ArchiveBlock::from(components)
                    .write_to_bytes()
                    .expect(&format!("expected[{}].write_to_bytes", index));
                let path = format!("/00/00/00/00/00/00/00/{:016x}.pb", index);
                mock("GET", &*path).with_body(bytes).create()
            })
            .collect::<Vec<_>>();

        let mut fetcher = create_fetcher();
        fetcher.set_merged_blocks_bucket_sizes(&[10]);
        fetcher
            .fetch_range(0..10)
            .enumerate()
            .for_each_concurrent(None, move |(index, result)| {
                let components =
                    result.expect(&format!("unexpected error for item #{}", index + 1));
                // TODO(#1682): Include QuorumSet, VerificationReport.
                assert_eq!(components.block_data, items[index].block_data);
                ready(())
            })
            .await;
        mock_requests.into_iter().for_each(|m| m.assert());
    }
}
