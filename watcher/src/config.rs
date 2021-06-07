// Copyright (c) 2018-2021 The MobileCoin Foundation

//! Configuration parameters for the watcher test utility.

use mc_util_uri::{ConsensusClientUri, WatcherUri};
use serde::{Deserialize, Serialize};
use std::{fs, path::PathBuf, str::FromStr, time::Duration};
use structopt::StructOpt;
use url::Url;

#[derive(Clone, Debug, StructOpt)]
#[structopt(
    name = "mc-watcher",
    about = "Sync data from multiple sources, reconcile blocks, and verify signatures."
)]
/// Configuration for the Watcher Node.
pub struct WatcherConfig {
    /// Path to watcher db (lmdb).
    #[structopt(long, default_value = "/tmp/watcher-db", parse(from_os_str))]
    pub watcher_db: PathBuf,

    /// The location of the sources.toml file. This file configures the list of
    /// block sources and consensus nodes that are being watched.
    #[structopt(long)]
    pub sources_path: PathBuf,

    /// (Optional) Number of blocks to sync
    #[structopt(long)]
    pub max_block_height: Option<u64>,

    /// How many seconds to wait between polling.
    #[structopt(long, default_value = "1", parse(try_from_str=parse_duration_in_seconds))]
    pub poll_interval: Duration,
    /// Store block data for every fetched block.
    #[structopt(long)]
    pub store_block_data: bool,

    /// gRPC listening URI.
    #[structopt(long, default_value = "insecure-watcher://0.0.0.0:3226/")]
    pub client_listen_uri: WatcherUri,
}

impl WatcherConfig {
    /// Load the sources configuration file.
    pub fn sources_config(&self) -> SourcesConfig {
        // Read configuration file.
        let data = fs::read_to_string(&self.sources_path)
            .unwrap_or_else(|err| panic!("failed reading {:?}: {:?}", self.sources_path, err));

        // Parse configuration file.
        toml::from_str(&data)
            .unwrap_or_else(|err| panic!("failed TOML parsing {:?}: {:?}", self.sources_path, err))
    }
}

/// A single watched source configuration.
#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq, Hash)]
pub struct SourceConfig {
    /// URL to use for pulling blocks.
    ///
    /// For example: https://s3-us-west-1.amazonaws.com/mobilecoin.chain/node1.test.mobilecoin.com/
    tx_source_url: String,

    /// (Optional) Consensus node client URL to use for fetching the remote
    /// attestation report whenever a block signer change is detected.
    consensus_client_url: Option<ConsensusClientUri>,

    /// (Optional) Client authentication token secret, for generating
    /// Authorization tokens when connecting to consensus nodes.
    consensus_client_auth_token_secret: Option<String>,
}

impl SourceConfig {
    /// Construct a new SourceConfig object.
    pub fn new(
        tx_source_url: String,
        consensus_client_url: Option<ConsensusClientUri>,
        consensus_client_auth_token_secret: Option<String>,
    ) -> Self {
        Self {
            tx_source_url,
            consensus_client_url,
            consensus_client_auth_token_secret,
        }
    }

    /// Get the tx_source_url and ensure it has a trailing slash.
    /// This is compatible with the behavior inside ReqwestTransactionsFetcher
    /// and ensures everywhere we use URLs we always have "slash-terminated"
    /// URLs
    pub fn tx_source_url(&self) -> Url {
        let mut url = self.tx_source_url.clone();
        if !url.ends_with('/') {
            url.push('/');
        }
        Url::from_str(&url).unwrap_or_else(|err| panic!("invalid url {}: {}", url, err))
    }

    /// Get consensus client URL, if available.
    pub fn consensus_client_url(&self) -> &Option<ConsensusClientUri> {
        &self.consensus_client_url
    }

    /// Get consensus client authentication token secret, if available.
    pub fn consensus_client_auth_token_secret(&self) -> Option<[u8; 32]> {
        self.consensus_client_auth_token_secret.as_ref().map(|s| {
            hex::FromHex::from_hex(s).unwrap_or_else(|err| {
                panic!("failed parsing consensus client auth token secret: {}", err)
            })
        })
    }
}

/// Sources configuration - this configures which sources are being watched.
#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq, Hash)]
pub struct SourcesConfig {
    /// List of sources being watched.
    sources: Vec<SourceConfig>,
}

impl SourcesConfig {
    /// Returns a list of URLs that can be used to fetch block contents from.
    pub fn tx_source_urls(&self) -> Vec<Url> {
        self.sources
            .iter()
            .map(|source_config| source_config.tx_source_url())
            .collect()
    }

    /// Get the complete list of sources we are watching.
    pub fn sources(&self) -> &[SourceConfig] {
        &self.sources
    }
}

fn parse_duration_in_seconds(src: &str) -> Result<Duration, std::num::ParseIntError> {
    Ok(Duration::from_secs(u64::from_str(src)?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn sources_config_toml() {
        let expected_config = SourcesConfig {
            sources: vec![
                SourceConfig::new("https://www.source.com/".to_owned(), None, None),
                SourceConfig::new(
                    "https://www.2nd-source.com/".to_owned(),
                    Some(ConsensusClientUri::from_str("mc://www.x.com:443/").unwrap()),
                    Some(
                        "1111111111111111111111111111111111111111111111111111111111111111"
                            .to_owned(),
                    ),
                ),
            ],
        };

        let input_toml: &str = r#"
            [[sources]]
            tx_source_url = "https://www.source.com/"

            [[sources]]
            tx_source_url = "https://www.2nd-source.com/"
            consensus_client_url = "mc://www.x.com:443/"
            consensus_client_auth_token_secret = "1111111111111111111111111111111111111111111111111111111111111111"
        "#;
        let config: SourcesConfig = toml::from_str(input_toml).expect("failed parsing toml");

        assert_eq!(config, expected_config);
    }
}
