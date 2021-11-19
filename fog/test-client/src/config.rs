// Copyright (c) 2018-2021 The MobileCoin Foundation

//! Configuration parameters for the test client binary

use mc_common::logger::{log, Logger};
use mc_fog_sample_paykit::AccountKey;
use mc_fog_uri::{FogLedgerUri, FogViewUri};
use mc_util_parse::parse_duration_in_seconds;
use mc_util_uri::{AdminUri, ConsensusClientUri};
use serde::Serialize;
use std::{convert::TryFrom, path::PathBuf, str::FromStr, time::Duration};
use structopt::StructOpt;

/// StructOpt for test-client binary
///
/// Serialize is used to create a json summary
#[derive(Debug, StructOpt, Clone, Serialize)]
#[structopt(name = "test-client", about = "Test client for Fog infrastructure.")]
pub struct TestClientConfig {
    /// A URI to host the prometheus data at.
    ///
    /// Prometheus data includes number of successes and failure, and histograms
    /// of transaction clearing and finality times.
    #[structopt(long, env)]
    pub admin_listen_uri: Option<AdminUri>,

    /// If set, then we continuously send test transfers.
    ///
    /// The frequency of transactions can be configured with "transfer_period".
    ///
    /// When running continuously, num_transactions is ignored, and we do not
    /// fail fast when deadlines are exceeded.
    ///
    /// You should usually set `admin_listen_uri` when you use this
    #[structopt(long, env)]
    pub continuous: bool,

    /// If not set, the test is terminated if a deadline is passed. We fail
    /// immediately, then start counting down for the next trial.
    ///
    /// If set, then we continue waiting after the deadline until the
    /// transaction succeeds.
    /// * The failed status is still reported immediately to prometheus
    /// * This allows us to alert on transactions taking too long, and still
    ///   collect accurate timing histograms even if our transactions are taking
    ///   too long.
    ///
    /// This is only intended to be set in the continuous mode of operation.
    #[structopt(long, env)]
    pub measure_after_deadline: bool,

    /// Account key directory.
    #[structopt(long, env)]
    pub key_dir: PathBuf,

    /// Number of clients to load from key directory
    #[structopt(long, env, default_value = "6")]
    pub num_clients: usize,

    /// Config specific to consensus
    #[structopt(flatten)]
    pub consensus_config: ConsensusConfig,

    /// Fog Ledger service URI
    #[structopt(long, required = true, env)]
    pub fog_ledger: FogLedgerUri,

    /// Fog View service URI.
    #[structopt(long, env)]
    pub fog_view: FogViewUri,

    /// Seconds to wait for a transaction to clear, before it has exceeded
    /// deadline. The healthy status will be set false if we exceed this
    /// deadline.
    #[structopt(long, env, default_value = "5", parse(try_from_str=parse_duration_in_seconds))]
    pub consensus_wait: Duration,

    /// Seconds to wait for ledger sync on fog
    /// This affects the double-spend test but not the continuous mode of
    /// operation.
    #[structopt(long, env, default_value = "5", parse(try_from_str=parse_duration_in_seconds))]
    pub ledger_sync_wait: Duration,

    /// Number of transactions to attempt (only when not running continuously)
    #[structopt(long, env, default_value = "36")]
    pub num_transactions: usize,

    /// When running continuously, specifies the length of the pause between
    /// test transfers
    ///
    /// By default the pause is 15 minutes.
    #[structopt(long, env, default_value = "900", parse(try_from_str=parse_duration_in_seconds))]
    pub transfer_period: Duration,

    /// Amount to transfer per transaction
    #[structopt(long, env, default_value = "20")]
    pub transfer_amount: u64,

    /// Consensus enclave CSS file (overriding the build-time CSS)
    #[structopt(long, env)]
    pub consensus_enclave_css: Option<String>,

    /// Fog ingest enclave CSS file (overriding the build-time CSS)
    #[structopt(long, env)]
    pub ingest_enclave_css: Option<String>,

    /// Fog ledger enclave CSS file (overriding the build-time CSS)
    #[structopt(long, env)]
    pub ledger_enclave_css: Option<String>,

    /// Fog view enclave CSS file (overriding the build-time CSS)
    #[structopt(long, env)]
    pub view_enclave_css: Option<String>,

    /// Whether to turn off memos, for backwards compatibility
    #[structopt(long, env)]
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
        mc_util_keyfile::keygen::read_default_slip10_identities(&key_dir)
            .unwrap()
            .iter()
            .take(self.num_clients)
            .map(AccountKey::try_from)
            .collect::<Result<_, _>>()
            .expect("Could not decode slip10 account key")
    }
}

/// StructOpt container for consensus config information
#[derive(Clone, Debug, StructOpt, Serialize)]
#[structopt()]
pub struct ConsensusConfig {
    /// Consensus Validator nodes to connect to.
    #[structopt(long = "consensus", env, required = true, min_values = 1)]
    pub consensus_validators: Vec<ConsensusClientUri>,
}
