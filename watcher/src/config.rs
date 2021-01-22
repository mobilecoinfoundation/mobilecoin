// Copyright (c) 2018-2021 The MobileCoin Foundation

//! Configuration parameters for the watcher test utility.

use mc_util_uri::ConsensusClientUri;
use serde::{Deserialize, Serialize};
use std::{fs, path::PathBuf};
use structopt::StructOpt;

#[derive(Debug, StructOpt)]
#[structopt(
    name = "watcher",
    about = "Sync data from multiple sources, reconcile blocks, and verify signatures."
)]
/// Configuration for the Watcher Node.
pub struct WatcherConfig {
    /// Path to watcher db (lmdb).
    #[structopt(long, default_value = "/tmp/watcher-db", parse(from_os_str))]
    pub watcher_db: PathBuf,

    /// The location of the sources.toml file. This file configures the list of block sources and
    /// consensus nodes that are being watched.
    #[structopt(long)]
    pub sources_path: PathBuf,

    /// (Optional) Number of blocks to sync
    #[structopt(long)]
    pub max_block_height: Option<u64>,
}

impl WatcherConfig {
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
    /// For example: https://s3-us-west-1.amazonaws.com/mobilecoin.chain/node1.master.mobilecoin.com/
    pub tx_source_url: String,

    /// (Optional) Consensus node client URL to use for fetching the remote attestation report
    /// whenever a block signer change is detected.
    pub consensus_client_url: Option<ConsensusClientUri>,
}

/// Sources configuration - this configures which sources are being watched.
#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq, Hash)]
pub struct SourcesConfig {
    pub sources: Vec<SourceConfig>,
}

impl SourcesConfig {
    pub fn tx_source_urls(&self) -> Vec<String> {
        self.sources
            .iter()
            .map(|source_config| source_config.tx_source_url.clone())
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn sources_config_toml() {
        let expected_config = SourcesConfig {
            sources: vec![
                SourceConfig {
                    tx_source_url: "https://www.source.com/".to_owned(),
                    consensus_client_url: None,
                },
                SourceConfig {
                    tx_source_url: "https://www.2nd-source.com/".to_owned(),
                    consensus_client_url: Some(
                        ConsensusClientUri::from_str("mc://www.x.com:443/").unwrap(),
                    ),
                },
            ],
        };

        let input_toml: &str = r#"
            [[sources]]
            tx_source_url = "https://www.source.com/"

            [[sources]]
            tx_source_url = "https://www.2nd-source.com/"
            consensus_client_url = "mc://www.x.com:443/"
        "#;
        let config: SourcesConfig = toml::from_str(input_toml).expect("failed parsing toml");

        assert_eq!(config, expected_config);
    }
}
