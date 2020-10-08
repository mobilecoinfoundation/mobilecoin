// Copyright (c) 2018-2020 MobileCoin Inc.

//! Implementation of the `TransactionsFetcher` trait that fetches transactions data over http(s)
//! using the `reqwest` library. It can be used, for example, to get transaction data from S3.

use crate::transactions_fetcher_trait::{TransactionFetcherError, TransactionsFetcher};
use failure::Fail;
use mc_api::{block_num_to_s3block_path, blockchain};
use mc_common::{
    logger::{log, Logger},
    ResponderId,
};
use mc_transaction_core::{Block, BlockData};
use reqwest::Error as ReqwestError;
use std::{
    convert::TryFrom,
    fs,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
};
use url::Url;

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
    pub source_urls: Vec<Url>,
    client: reqwest::blocking::Client,
    logger: Logger,
    source_index_counter: Arc<AtomicU64>,
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
        })
    }

    pub fn block_from_url(&self, url: &Url) -> Result<BlockData, ReqwestTransactionsFetcherError> {
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

        let archive_block: blockchain::ArchiveBlock =
            protobuf::parse_from_bytes(&bytes).map_err(|err| {
                ReqwestTransactionsFetcherError::InvalidBlockReceived(
                    url.to_string(),
                    format!("protobuf parse failed: {:?}", err),
                )
            })?;

        let block_data = BlockData::try_from(&archive_block).map_err(|err| {
            ReqwestTransactionsFetcherError::InvalidBlockReceived(url.to_string(), err.to_string())
        })?;

        Ok(block_data)
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
}

impl TransactionsFetcher for ReqwestTransactionsFetcher {
    type Error = ReqwestTransactionsFetcherError;

    fn get_block_data(
        &self,
        _safe_responder_ids: &[ResponderId],
        block: &Block,
    ) -> Result<BlockData, Self::Error> {
        // Get the source to fetch from.
        let source_index_counter =
            self.source_index_counter.fetch_add(1, Ordering::SeqCst) as usize;
        let source_url = &self.source_urls[source_index_counter % self.source_urls.len()];

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

        // Got what we wanted!
        Ok(block_data)
    }
}
