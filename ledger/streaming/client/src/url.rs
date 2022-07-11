// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Helper for `ArchiveBlock` and `ArchiveBlocks` URLs.

use mc_api::{block_num_to_s3block_path, merged_block_num_to_s3block_path};
use mc_ledger_streaming_api::BlockIndex;
use std::{fmt::Display, str::FromStr};
use url::Url;

/// Helper for `ArchiveBlock` and `ArchiveBlocks` URLs.
// TODO: Move this into mc_[ledger_streaming_]api?
#[derive(Clone, Debug)]
pub struct BlockchainUrl(Url);

impl BlockchainUrl {
    /// Instantiate an object with the given base URL.
    pub fn new(mut base_url: Url) -> Result<Self, url::ParseError> {
        if !base_url.path().ends_with('/') {
            base_url = base_url.join(&format!("{}/", base_url.path()))?;
        }
        Ok(Self(base_url))
    }

    /// Get a URL for the given block index.
    pub fn block_url(&self, index: BlockIndex) -> Result<Url, url::ParseError> {
        let filename = block_num_to_s3block_path(index)
            .into_os_string()
            .into_string()
            .unwrap();
        self.0.join(&filename)
    }

    /// Get a URL for the given merged block parameters.
    pub fn merged_block_url(
        &self,
        bucket_size: u64,
        first_index: BlockIndex,
    ) -> Result<Url, url::ParseError> {
        let filename = merged_block_num_to_s3block_path(bucket_size, first_index)
            .into_os_string()
            .into_string()
            .unwrap();
        self.0.join(&filename)
    }
}

impl FromStr for BlockchainUrl {
    type Err = url::ParseError;

    fn from_str(src: &str) -> Result<Self, Self::Err> {
        Self::new(Url::parse(src)?)
    }
}

impl Display for BlockchainUrl {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "BlockchainUrl[base={}]", self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_url_adds_trailing_slash() {
        let url = Url::parse("https://example.com/foo").expect("Parse https URL");
        let burl = BlockchainUrl::new(url).expect("BlockchainUrl::new");
        assert_eq!(burl.0.as_str(), "https://example.com/foo/");

        let url = Url::parse("http://example.com/bar").expect("Parse http URL");
        let burl = BlockchainUrl::new(url).expect("BlockchainUrl::new");
        assert_eq!(burl.0.as_str(), "http://example.com/bar/");
    }

    #[test]
    fn from_str_validates_url() {
        let result = BlockchainUrl::from_str("not_url");
        assert!(result.is_err());
    }

    #[test]
    fn from_str_adds_trailing_slash() {
        let url = BlockchainUrl::from_str("https://example.com/foo").expect("https URL");
        assert_eq!(url.0.as_str(), "https://example.com/foo/");

        let url = BlockchainUrl::from_str("http://example.com/bar").expect("http URL");
        assert_eq!(url.0.as_str(), "http://example.com/bar/");
    }

    #[test]
    fn test_block_url() {
        let url = BlockchainUrl::from_str("https://example.com/foo").expect("https URL");
        let block_url = url.block_url(0).expect("block_url(0)");
        assert_eq!(
            block_url.to_string(),
            "https://example.com/foo/00/00/00/00/00/00/00/0000000000000000.pb"
        );

        let block_url = url
            .block_url(0x1a2b_3c4e_5a6b_7c8d)
            .expect("block_url(0x1a2b_3c4e_5a6b_7c8d)");
        assert_eq!(
            block_url.to_string(),
            "https://example.com/foo/1a/2b/3c/4e/5a/6b/7c/1a2b3c4e5a6b7c8d.pb"
        )
    }

    #[test]
    fn test_merged_block_url() {
        let url = BlockchainUrl::from_str("https://example.com/foo").expect("https URL");

        let merged_block_url = url
            .merged_block_url(10, 1_000_000_000_000_000)
            .expect("merged_block_url(10, 1_000_000_000_000_000)");
        assert_eq!(
            merged_block_url.to_string(),
            "https://example.com/foo/merged-10/00/03/8d/7e/a4/c6/80/00038d7ea4c68000.pb"
        );

        let merged_block_url = url
            .merged_block_url(1000, 1_000_000_000_000_000)
            .expect("merged_block_url(1000, 1_000_000_000_000_000)");
        assert_eq!(
            merged_block_url.to_string(),
            "https://example.com/foo/merged-1000/00/03/8d/7e/a4/c6/80/00038d7ea4c68000.pb"
        )
    }
}
