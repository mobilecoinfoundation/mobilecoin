// Copyright (c) 2018-2022 The MobileCoin Foundation

//! A [Fetcher] that downloads [ArchiveBlock]s from HTTP URLs with a configured
//! base URL.

use crate::BlockchainUrl;
use displaydoc::Display;
use futures::{lock::Mutex, Future, FutureExt, Stream, StreamExt};
use mc_blockchain_types::Block;
use mc_common::{
    logger::{log, o, Logger},
    LruCache,
};
use mc_ledger_streaming_api::{
    ArchiveBlock, ArchiveBlocks, BlockData, BlockIndex, Error, Fetcher, Result,
    DEFAULT_MERGED_BLOCKS_BUCKET_SIZES,
};
use protobuf::Message;
use reqwest::Client;
use std::{
    convert::{TryFrom, TryInto},
    ops::Range,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
};
use url::Url;

/// Maximum number of pre-fetched blocks to keep in cache.
pub const MAX_PREFETCHED_BLOCKS: usize = 10000;

/**
 * A [Fetcher] that downloads [ArchiveBlock]s from HTTP URLs with a
 * configured base URL.
 */
#[derive(Debug, Display)]
pub struct HttpBlockFetcher {
    /// The blockchain URL.
    url: BlockchainUrl,

    /// The [reqwest::Client].
    client: Client,

    /// Merged blocks bucket sizes to attempt fetching.
    merged_blocks_bucket_sizes: Vec<usize>,

    /// Cache mapping a [BlockIndex] to [BlockData], filled by
    /// merged blocks when possible.
    cache: Arc<Mutex<LruCache<BlockIndex, BlockData>>>,

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
    pub fn set_merged_blocks_bucket_sizes(&mut self, bucket_sizes: &[usize]) {
        debug_assert!(
            bucket_sizes.iter().all(|n| *n < MAX_PREFETCHED_BLOCKS),
            "max bucket size is {}",
            MAX_PREFETCHED_BLOCKS
        );
        self.merged_blocks_bucket_sizes = bucket_sizes.to_vec();
    }

    /// Fetches a block with the given index.
    /// Optionally validates the fetched block matches an expected block.
    pub async fn get_block_data_by_index(
        &self,
        block_index: BlockIndex,
        expected_block: Option<&Block>,
    ) -> Result<BlockData> {
        // Try and see if we can get this block from our cache.
        if let Some(cached) = self.get_cached(block_index, expected_block).await {
            return Ok(cached);
        }

        // Try and fetch a merged block if we stand a chance of finding one.
        for bucket in &self.merged_blocks_bucket_sizes {
            if block_index % (*bucket as u64) == 0 {
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
            "Attempting to fetch block #{} from {}",
            block_index,
            url
        );

        let archive_block: ArchiveBlock = self.fetch_protobuf_object(&url).await?;
        let block_data = BlockData::try_from(&archive_block)?;

        // If the caller is expecting a specific block, check that we received data for
        // the block they asked for
        if let Some(expected_block) = expected_block {
            if expected_block != block_data.block() {
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
            block_data.block().index,
            hits,
            misses
        );

        // Got what we wanted!
        Ok(block_data)
    }

    async fn get_cached(
        &self,
        block_index: BlockIndex,
        expected_block: Option<&Block>,
    ) -> Option<BlockData> {
        // Sanity test.
        if let Some(expected_block) = expected_block {
            assert_eq!(block_index, expected_block.index);
        }

        let mut cache = self.cache.lock().await;

        // Note: If this block index is in the cache, we take it out under the
        // assumption that our primary caller, LedgerSyncService, is not
        // going to try and fetch the same block twice if it managed to get
        // a valid block.
        cache.pop(&block_index).and_then(|block_data| {
            let index = block_data.block().index;
            // If we expect a specific Block then compare what the cache had with what we
            // expect.
            if let Some(expected_block) = expected_block {
                if block_data.block() == expected_block {
                    let hits = self.hits.fetch_add(1, Ordering::SeqCst);
                    let misses = self.misses.load(Ordering::SeqCst);
                    log::trace!(
                        self.logger,
                        "Got block #{} from cache (total hits/misses: {}/{})",
                        block_index,
                        hits,
                        misses
                    );
                    Some(block_data)
                } else {
                    log::warn!(
                        self.logger,
                        "Got cached block {:?} but actually requested {:?}! This should not happen",
                        block_data.block(),
                        expected_block
                    );
                    None
                }
            } else if index == block_index {
                Some(block_data)
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

    async fn get_merged(&self, bucket_size: usize, first_index: BlockIndex) -> Result<usize> {
        log::debug!(
            self.logger,
            "Attempting to fetch a merged block for #{} (bucket size {})",
            first_index,
            bucket_size
        );
        debug_assert!(
            first_index % (bucket_size as u64) == 0,
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
        let blocks: Vec<BlockData> = (&archive_blocks).try_into()?;
        let result = blocks.len();
        log::debug!(self.logger, "Got {} merged results from {}", result, url);

        {
            let mut cache = self.cache.lock().await;
            for block_data in blocks.into_iter() {
                cache.put(block_data.block().index, block_data);
            }
        }
        Ok(result)
    }

    async fn get_range_prefer_merged(
        &self,
        indexes: Range<BlockIndex>,
    ) -> impl Stream<Item = Result<BlockData>> + '_ {
        let n = indexes.end - indexes.start - 1;
        for bucket in &self.merged_blocks_bucket_sizes {
            let bucket_u64 = *bucket as u64;
            if bucket_u64 < n {
                continue;
            }
            let block_start = indexes.start - indexes.start % bucket_u64;
            if let Ok(num_merged) = self.get_merged(*bucket, block_start).await {
                if num_merged > 0 {
                    break;
                }
            }
        }

        futures::stream::iter(indexes).then(move |idx| self.get_block_data_by_index(idx, None))
    }
}

impl Fetcher<Result<BlockData>, BlockIndex, Range<BlockIndex>> for HttpBlockFetcher {
    type Single<'s> = impl Future<Output = Result<BlockData>> + 's;
    type Multiple<'s> = impl Stream<Item = Result<BlockData>> + 's;

    fn fetch_single(&self, index: BlockIndex) -> Self::Single<'_> {
        self.get_block_data_by_index(index, None)
    }

    fn fetch_multiple(&self, indexes: Range<BlockIndex>) -> Self::Multiple<'_> {
        self.get_range_prefer_merged(indexes).flatten_stream()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::future::ready;
    use mc_ledger_streaming_api::test_utils::make_blocks;
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
        let items = make_blocks(1);
        let expected = ArchiveBlock::from(&items[0]);
        let mock_request = mock("GET", "/00/00/00/00/00/00/00/0000000000000001.pb")
            .with_body(expected.write_to_bytes().expect("expected.write_to_bytes"))
            .create();

        let result = create_fetcher().fetch_single(1).await;
        mock_request.assert();
        let block_data = result.expect("expected data");
        assert_eq!(block_data, items[0]);
    }

    #[tokio::test]
    async fn fetch_multiple_merged() {
        let items = make_blocks(10);
        let expected = ArchiveBlocks::from(&items[..]);
        let mock_request = mock("GET", "/merged-10/00/00/00/00/00/00/00/0000000000000000.pb")
            .with_body(expected.write_to_bytes().expect("expected.write_to_bytes"))
            .create();

        let mut fetcher = create_fetcher();
        fetcher.set_merged_blocks_bucket_sizes(&[10]);
        fetcher
            .fetch_multiple(0..10)
            .enumerate()
            .for_each_concurrent(None, move |(index, result)| {
                let block_data = result
                    .unwrap_or_else(|e| panic!("unexpected error for item #{}: {}", index + 1, e));
                assert_eq!(block_data, items[index]);
                ready(())
            })
            .await;
        mock_request.assert();
    }

    #[tokio::test]
    async fn fetch_multiple_no_merged() {
        let items = make_blocks(10);
        let mock_requests = items
            .iter()
            .map(|block_data| {
                let index = block_data.block().index;
                let bytes = ArchiveBlock::from(block_data)
                    .write_to_bytes()
                    .unwrap_or_else(|e| panic!("expected[{}].write_to_bytes failed: {}", index, e));
                let path = format!("/00/00/00/00/00/00/00/{:016x}.pb", index);
                mock("GET", &*path).with_body(bytes).create()
            })
            .collect::<Vec<_>>();

        let mut fetcher = create_fetcher();
        fetcher.set_merged_blocks_bucket_sizes(&[10]);
        fetcher
            .fetch_multiple(0..10)
            .enumerate()
            .for_each_concurrent(None, move |(index, result)| {
                let block_data = result
                    .unwrap_or_else(|e| panic!("unexpected error for item #{}: {}", index + 1, e));
                assert_eq!(block_data, items[index]);
                ready(())
            })
            .await;

        for m in mock_requests {
            m.assert();
        }
    }
}
