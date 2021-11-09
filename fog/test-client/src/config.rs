// Copyright (c) 2018-2021 The MobileCoin Foundation

//! Configuration parameters for the test client binary

use mc_common::logger::{log, Logger};
use mc_fog_sample_paykit::AccountKey;
use mc_fog_uri::{FogLedgerUri, FogViewUri};
use mc_util_uri::{AdminUri, ConsensusClientUri};

use serde::Serialize;
use std::{path::PathBuf, str::FromStr, time::Duration};
use structopt::StructOpt;

/// StructOpt for test-client binary
#[derive(Debug, StructOpt, Serialize, Clone)]
#[structopt(name = "test-client", about = "Test client for Fog infrastructure.")]
pub struct TestClientConfig {
    /// A URI to host the prometheus data at.
    ///
    /// Prometheus data includes number of successes and failure, and histograms
    /// of transaction clearing and finality times.
    #[structopt(long)]
    pub admin_listen_uri: Option<AdminUri>,

    /// If set, then we continuously send test transfers.
    ///
    /// The frequency of transactions can be configured with "transfer_period".
    ///
    /// When running continuously, num_transactions is ignored, and we do not
    /// fail fast when deadlines are exceeded.
    ///
    /// You should usually set `admin_listen_uri` when you use this
    #[structopt(long)]
    pub continuous: bool,

    /// Account key directory.
    #[structopt(long)]
    pub key_dir: PathBuf,

    /// Number of clients to load from key directory
    #[structopt(long, default_value = "6")]
    pub num_clients: usize,

    /// Config specific to consensus
    #[structopt(flatten)]
    pub consensus_config: ConsensusConfig,

    /// Fog Ledger service URI
    #[structopt(long, required = true)]
    pub fog_ledger: FogLedgerUri,

    /// Fog View service URI.
    #[structopt(long)]
    pub fog_view: FogViewUri,

    /// Seconds to wait for a transaction to clear, before it has exceeded
    /// deadline.
    #[structopt(long, default_value = "5", parse(try_from_str=parse_duration_in_seconds))]
    pub consensus_wait: Duration,

    /// Seconds to wait for ledger sync on fog
    #[structopt(long, default_value = "5", parse(try_from_str=parse_duration_in_seconds))]
    pub ledger_sync_wait: Duration,

    /// Number of transactions to attempt (only when not running continuously)
    #[structopt(long, default_value = "36")]
    pub num_transactions: usize,

    /// When running continuously, specifies the length of the pause between
    /// test transfers
    ///
    /// By default the pause is 15 minutes.
    #[structopt(long, default_value = "900", parse(try_from_str=parse_duration_in_seconds))]
    pub transfer_period: Duration,

    /// Amount to transfer per transaction
    #[structopt(long, default_value = "20")]
    pub transfer_amount: u64,

    /// Consensus enclave CSS file (overriding the build-time CSS)
    #[structopt(long)]
    pub consensus_enclave_css: Option<String>,

    /// Fog ingest enclave CSS file (overriding the build-time CSS)
    #[structopt(long)]
    pub fog_ingest_enclave_css: Option<String>,

    /// Fog ledger enclave CSS file (overriding the build-time CSS)
    #[structopt(long)]
    pub fog_ledger_enclave_css: Option<String>,

    /// Fog view enclave CSS file (overriding the build-time CSS)
    #[structopt(long)]
    pub fog_view_enclave_css: Option<String>,

    /// Whether to turn off memos, for backwards compatibility
    #[structopt(long)]
    pub no_memos: bool,
}

impl TestClientConfig {
    /// Load account keys from disk corresponding to this config
    pub fn load_accounts(&self, logger: &Logger) -> Vec<AccountKey> {
        // Load key_dir or read from bootstrap keys.
        let key_dir: String = self.key_dir.clone().to_str().unwrap().to_string();
        log::info!(logger, "Using key_dir: {:?}", key_dir);

        // Load the key files
        log::info!(logger, "Loading account keys from {:?}", key_dir);
        mc_util_keyfile::keygen::read_default_root_entropies(&key_dir)
            .unwrap()
            .iter()
            .take(self.num_clients)
            .map(AccountKey::from)
            .collect()
    }
}

/// StructOpt container for consensus config information
#[derive(Clone, Debug, StructOpt, Serialize)]
#[structopt()]
pub struct ConsensusConfig {
    /// Consensus Validator nodes to connect to.
    #[structopt(long = "consensus", required = true, min_values = 1)]
    pub consensus_validators: Vec<ConsensusClientUri>,
}

fn parse_duration_in_seconds(src: &str) -> Result<Duration, std::num::ParseIntError> {
    Ok(Duration::from_secs(u64::from_str(src)?))
}
