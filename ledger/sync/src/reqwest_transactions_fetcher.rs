// Copyright (c) 2018-2020 MobileCoin Inc.

//! Implementation of the `TransactionsFetcher` trait that fetches transactions data over http(s)
//! using the `reqwest` library. It can be used, for example, to get transaction data from S3.

use crate::transactions_fetcher_trait::{TransactionFetcherError, TransactionsFetcher};
use failure::Fail;
use mc_common::{
    logger::{log, Logger},
    ResponderId,
};
use mc_consensus_api::{blockchain, conversions::block_num_to_s3block_path};
use mc_transaction_core::{Block, BlockContents, BlockSignature};
use reqwest::Error as ReqwestError;
use serde::{Deserialize, Serialize};
use std::{
    convert::TryFrom,
    fs,
    sync::atomic::{AtomicU64, Ordering},
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

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct S3BlockData {
    pub block: Block,
    pub block_contents: BlockContents,
    pub signature: Option<BlockSignature>,
}

pub struct ReqwestTransactionsFetcher {
    pub source_urls: Vec<Url>,
    client: reqwest::Client,
    logger: Logger,
    source_index_counter: AtomicU64,
}

impl ReqwestTransactionsFetcher {
    pub fn new(
        source_urls: Vec<String>,
        logger: Logger,
    ) -> Result<Self, ReqwestTransactionsFetcherError> {
        Self::new_with_client(source_urls, reqwest::Client::new(), logger)
    }

    pub fn new_with_client(
        source_urls: Vec<String>,
        client: reqwest::Client,
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
            source_index_counter: AtomicU64::new(0),
        })
    }

    pub fn block_from_url(
        &self,
        url: &Url,
    ) -> Result<S3BlockData, ReqwestTransactionsFetcherError> {
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

        let s3_block: blockchain::S3Block = protobuf::parse_from_bytes(&bytes).map_err(|err| {
            ReqwestTransactionsFetcherError::InvalidBlockReceived(
                url.to_string(),
                format!("protobuf parse failed: {:?}", err),
            )
        })?;

        if !s3_block.has_v1() {
            return Err(ReqwestTransactionsFetcherError::InvalidBlockReceived(
                url.to_string(),
                "v1 block not present".to_owned(),
            ));
        }

        let block = Block::try_from(s3_block.get_v1().get_block()).map_err(|err| {
            ReqwestTransactionsFetcherError::InvalidBlockReceived(
                url.to_string(),
                format!("Block conversion failed: {:?}", err),
            )
        })?;

        let block_contents = BlockContents::try_from(s3_block.get_v1().get_block_contents())
            .map_err(|err| {
                ReqwestTransactionsFetcherError::InvalidBlockReceived(
                    url.to_string(),
                    format!("Block contents conversion failed: {:?}", err),
                )
            })?;

        let signature = s3_block
            .get_v1()
            .signature
            .as_ref()
            .map(BlockSignature::try_from)
            .transpose()
            .map_err(|err| {
                ReqwestTransactionsFetcherError::InvalidBlockReceived(
                    url.to_string(),
                    format!("Invalid block signature: {:?}", err),
                )
            })?;

        if let Some(signature) = signature.as_ref() {
            signature.verify(&block).map_err(|err| {
                ReqwestTransactionsFetcherError::InvalidBlockReceived(
                    url.to_string(),
                    format!("Unable to verify block signature: {:?}", err),
                )
            })?;
        }

        if block.contents_hash != block_contents.hash() {
            return Err(ReqwestTransactionsFetcherError::InvalidBlockReceived(
                url.to_string(),
                format!(
                    "Invalid block contents hash. Block: {:?}, BlockContents: {:?}",
                    block, block_contents
                ),
            ));
        }

        let s3_block_data = S3BlockData {
            block,
            block_contents,
            signature,
        };
        Ok(s3_block_data)
    }

    pub fn get_origin_block_and_transactions(
        &self,
    ) -> Result<(Block, BlockContents), ReqwestTransactionsFetcherError> {
        let source_url = &self.source_urls[0];
        let filename = block_num_to_s3block_path(0)
            .into_os_string()
            .into_string()
            .unwrap();
        let url = source_url.join(&filename).unwrap();
        let s3block = self.block_from_url(&url)?;
        Ok((s3block.block, s3block.block_contents))
    }
}

impl TransactionsFetcher for ReqwestTransactionsFetcher {
    type Error = ReqwestTransactionsFetcherError;

    fn get_block_contents(
        &self,
        _safe_responder_ids: &[ResponderId],
        block: &Block,
    ) -> Result<BlockContents, Self::Error> {
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

        let s3_block_data = self.block_from_url(&url)?;

        // Check that we received data for the block we actually asked about.
        if *block != s3_block_data.block {
            return Err(ReqwestTransactionsFetcherError::InvalidBlockReceived(
                url.to_string(),
                "block data mismatch".to_string(),
            ));
        }

        // Got what we wanted!
        Ok(s3_block_data.block_contents)
    }
}
