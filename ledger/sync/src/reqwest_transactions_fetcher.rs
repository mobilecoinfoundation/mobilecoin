// Copyright (c) 2018-2020 MobileCoin Inc.

//! Implementation of the `TransactionsFetcher` trait that fetches transactions data over http(s)
//! using the `reqwest` library. It can be used, for example, to get transaction data from S3.

use crate::transactions_fetcher_trait::{TransactionFetcherError, TransactionsFetcher};
use failure::Fail;
use mc_api::{block_num_to_s3block_path, blockchain, merged_block_num_to_s3block_path};
use mc_common::{
    logger::{log, Logger},
    lru::LruCache,
    ResponderId,
};
use mc_transaction_core::{Block, BlockData, BlockID};
use protobuf::Message;
use reqwest::Error as ReqwestError;
use std::{
    convert::TryFrom,
    fs,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Mutex,
    },
};
use url::Url;

/// Default merged blocks bucket sizes. Merged blocks are objects that contain multiple consecutive
/// blocks that have been bundled together in order to reduce the amount of requests needed to get
/// the block data.
/// Notes:
/// - This should match the defaults in `mc-ledger-distribution`.
/// - This must be sorted in descending order.
pub const DEFAULT_MERGED_BLOCKS_BUCKET_SIZES: &[u64] = &[10000, 1000, 100];

/// Maximum number of pre-fetched blocks to keep in cache.
pub const MAX_PREFETCHED_BLOCKS: usize = 10000;

#[derive(Debug, Fail)]
pub enum ReqwestTransactionsFetcherError {
    #[fail(display = "Url parse error on {}: {}", _0, _1)]
    UrlParse(String, url::ParseError),

    #[fail(display = "reqwest error on {}: {:?}", _0, _1)]
    ReqwestError(String, ReqwestError),

    #[fail(display = "IO error on {}: {:?}", _0, _1)]
    IO(String, std::io::Error),

    #[fail(display = "Received an invalid block from {}: {}", _0, _1)]
    InvalidBlockReceived(String, String),

    #[fail(display = "No URLs configured.")]
    NoUrlsConfigured,
}

impl From<ReqwestError> for ReqwestTransactionsFetcherError {
    fn from(src: ReqwestError) -> Self {
        ReqwestTransactionsFetcherError::ReqwestError(
            String::from(src.url().map_or("", |v| v.as_str())),
            src,
        )
    }
}

impl TransactionFetcherError for ReqwestTransactionsFetcherError {}

#[derive(Clone)]
pub struct ReqwestTransactionsFetcher {
    /// List of URLs to try and fetch objects from.
    pub source_urls: Vec<Url>,

    /// Client used for HTTP(s) requests.
    client: reqwest::blocking::Client,

    /// Logger.
    logger: Logger,

    /// The most recently used URL index (in `source_urls`).
    source_index_counter: Arc<AtomicU64>,

    /// Cache mapping a `BlockID` to `BlockData`, filled by merged blocks when possible.
    blocks_cache: Arc<Mutex<LruCache<BlockID, BlockData>>>,

    /// Merged blocks bucket sizes to attempt fetching.
    merged_blocks_bucket_sizes: Vec<u64>,

    /// Number of successful cache hits when attempting ot get block data.
    /// Used for debugging purposes.
    hits: Arc<AtomicU64>,

    /// Number of cache misses when attempting to get block data.
    /// Used for debugging purposes.
    misses: Arc<AtomicU64>,
}

impl ReqwestTransactionsFetcher {
    pub fn new(
        source_urls: Vec<String>,
        logger: Logger,
    ) -> Result<Self, ReqwestTransactionsFetcherError> {
        Self::new_with_client(source_urls, reqwest::blocking::Client::new(), logger)
    }

    pub fn new_with_client(
        source_urls: Vec<String>,
        client: reqwest::blocking::Client,
        logger: Logger,
    ) -> Result<Self, ReqwestTransactionsFetcherError> {
        let source_urls: Result<Vec<Url>, ReqwestTransactionsFetcherError> = source_urls
            .into_iter()
            // All source_urls must end with a '/'
            .map(|mut url| {
                if !url.ends_with('/') {
                    url.push_str("/");
                }

                url
            })
            // Parse into a Url object
            .map(|url| {
                Url::parse(&url).map_err(|err| ReqwestTransactionsFetcherError::UrlParse(url, err))
            })
            .collect();

        Ok(Self {
            source_urls: source_urls?,
            client,
            logger,
            source_index_counter: Arc::new(AtomicU64::new(0)),
            blocks_cache: Arc::new(Mutex::new(LruCache::new(MAX_PREFETCHED_BLOCKS))),
            merged_blocks_bucket_sizes: DEFAULT_MERGED_BLOCKS_BUCKET_SIZES.to_vec(),
            hits: Arc::new(AtomicU64::new(0)),
            misses: Arc::new(AtomicU64::new(0)),
        })
    }

    pub fn set_merged_blocks_bucket_sizes(&mut self, bucket_sizes: &[u64]) {
        self.merged_blocks_bucket_sizes = bucket_sizes.to_vec();
    }

    pub fn block_from_url(&self, url: &Url) -> Result<BlockData, ReqwestTransactionsFetcherError> {
        let archive_block: blockchain::ArchiveBlock = self.fetch_protobuf_object(&url)?;

        let block_data = BlockData::try_from(&archive_block).map_err(|err| {
            ReqwestTransactionsFetcherError::InvalidBlockReceived(url.to_string(), err.to_string())
        })?;

        Ok(block_data)
    }

    // Fetches multiple blocks (a "merged block") from a given url.
    pub fn blocks_from_url(
        &self,
        url: &Url,
    ) -> Result<Vec<BlockData>, ReqwestTransactionsFetcherError> {
        let archive_blocks: blockchain::ArchiveBlocks = self.fetch_protobuf_object(url)?;

        Ok(Vec::<BlockData>::try_from(&archive_blocks).map_err(|err| {
            ReqwestTransactionsFetcherError::InvalidBlockReceived(url.to_string(), err.to_string())
        })?)
    }

    pub fn get_origin_block_and_transactions(
        &self,
    ) -> Result<BlockData, ReqwestTransactionsFetcherError> {
        let source_url = &self
            .source_urls
            .get(0)
            .ok_or(ReqwestTransactionsFetcherError::NoUrlsConfigured)?;
        let filename = block_num_to_s3block_path(0)
            .into_os_string()
            .into_string()
            .unwrap();
        let url = source_url.join(&filename).unwrap();
        self.block_from_url(&url)
    }

    fn fetch_protobuf_object<M: Message>(
        &self,
        url: &Url,
    ) -> Result<M, ReqwestTransactionsFetcherError> {
        // Special treatment for file:// to read from a local directory.
        let bytes: Vec<u8> = if url.scheme() == "file" {
            let path = &url[url::Position::BeforeHost..url::Position::AfterPath];
            fs::read(path)
                .map_err(|err| ReqwestTransactionsFetcherError::IO(path.to_string(), err))?
                .to_vec()
        } else {
            let mut response = self.client.get(url.as_str()).send().map_err(|err| {
                ReqwestTransactionsFetcherError::ReqwestError(url.to_string(), err)
            })?;

            let mut bytes = Vec::new();
            response.copy_to(&mut bytes)?;
            bytes
        };

        let obj: M = protobuf::parse_from_bytes(&bytes).map_err(|err| {
            ReqwestTransactionsFetcherError::InvalidBlockReceived(
                url.to_string(),
                format!("protobuf parse failed: {:?}", err),
            )
        })?;

        Ok(obj)
    }
}

impl TransactionsFetcher for ReqwestTransactionsFetcher {
    type Error = ReqwestTransactionsFetcherError;

    fn get_block_data(
        &self,
        _safe_responder_ids: &[ResponderId],
        block: &Block,
    ) -> Result<BlockData, Self::Error> {
        // Try and see if we can get this block from our cache.
        {
            let mut blocks_cache = self.blocks_cache.lock().expect("mutex poisoned");

            // Note: If this block id is in the cache, we take it out under the assumption that our
            // primary caller, LedgerSyncService, is not going to try and fetch the same block
            // twice if it managed to get a valid block.
            if let Some(block_data) = blocks_cache.pop(&block.id) {
                if block_data.block() == block {
                    let hits = self.hits.fetch_add(1, Ordering::SeqCst);
                    let misses = self.misses.load(Ordering::SeqCst);
                    log::trace!(
                        self.logger,
                        "Got block #{} from cache (total hits/misses: {}/{})",
                        block.index,
                        hits,
                        misses
                    );
                    return Ok(block_data);
                }
            }
        }

        // Get the source to fetch from.
        let source_index_counter =
            self.source_index_counter.fetch_add(1, Ordering::SeqCst) as usize;
        let source_url = &self.source_urls[source_index_counter % self.source_urls.len()];

        // Try and fetch a merged block if we stand a chance of finding one.
        for bucket in self.merged_blocks_bucket_sizes.iter() {
            if block.index % bucket == 0 {
                log::debug!(
                    self.logger,
                    "Attempting to fetch a merged block for #{} (bucket size {})",
                    block.index,
                    bucket
                );
                let filename = merged_block_num_to_s3block_path(*bucket, block.index)
                    .into_os_string()
                    .into_string()
                    .unwrap();
                let url = source_url
                    .join(&filename)
                    .map_err(|e| ReqwestTransactionsFetcherError::UrlParse(filename.clone(), e))?;

                if let Ok(blocks_data) = self.blocks_from_url(&url) {
                    log::debug!(
                        self.logger,
                        "Got a merged block for #{} (bucket size {}): {} entries",
                        block.index,
                        bucket,
                        blocks_data.len()
                    );

                    let mut blocks_cache = self.blocks_cache.lock().expect("mutex poisoned");
                    for block_data in blocks_data.into_iter() {
                        blocks_cache.put(block_data.block().id.clone(), block_data);
                    }
                    break;
                }
            }
        }

        // Construct URL for the block we are trying to fetch.
        let filename = block_num_to_s3block_path(block.index)
            .into_os_string()
            .into_string()
            .unwrap();
        let url = source_url
            .join(&filename)
            .map_err(|e| ReqwestTransactionsFetcherError::UrlParse(filename, e))?;

        // Try and get the block.
        log::debug!(
            self.logger,
            "Attempting to fetch block {} from {}",
            block.index,
            url
        );

        let block_data = self.block_from_url(&url)?;

        // Check that we received data for the block we actually asked about.
        if block != block_data.block() {
            return Err(ReqwestTransactionsFetcherError::InvalidBlockReceived(
                url.to_string(),
                "block data mismatch".to_string(),
            ));
        }

        let hits = self.hits.load(Ordering::SeqCst);
        let misses = self.misses.fetch_add(1, Ordering::SeqCst);
        log::trace!(
            self.logger,
            "Cache miss while getting block #{} (total hits/misses: {}/{})",
            block.index,
            hits,
            misses
        );

        // Got what we wanted!
        Ok(block_data)
    }
}
