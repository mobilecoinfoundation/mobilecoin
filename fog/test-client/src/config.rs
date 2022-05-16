// Copyright (c) 2018-2022 The MobileCoin Foundation
#![deny(missing_docs)]

//! Configuration parameters for the test client binary

use clap::Parser;
use mc_common::logger::{log, Logger};
use mc_fog_sample_paykit::{AccountKey, TokenId};
use mc_fog_uri::{FogLedgerUri, FogViewUri};
use mc_util_grpc::GrpcRetryConfig;
use mc_util_parse::parse_duration_in_seconds;
use mc_util_uri::{AdminUri, ConsensusClientUri};
use serde::Serialize;
use std::{path::PathBuf, time::Duration};

/// Parser for test-client binary
///
/// Serialize is used to create a json summary
#[derive(Clone, Debug, Parser, Serialize)]
#[clap(
    name = "test-client",
    about = "Test client for Fog infrastructure.",
    version
)]
pub struct TestClientConfig {
    /// A URI to host the prometheus data at.
    ///
    /// Prometheus data includes number of successes and failure, and histograms
    /// of transaction clearing and finality times.
    #[clap(long, env = "MC_ADMIN_LISTEN_URI")]
    pub admin_listen_uri: Option<AdminUri>,

    /// If set, then we continuously send test transfers.
    ///
    /// The frequency of transactions can be configured with "transfer_period".
    ///
    /// When running continuously, num_transactions is ignored, and we do not
    /// fail fast when deadlines are exceeded.
    ///
    /// You should usually set `admin_listen_uri` when you use this
    #[clap(long, env = "MC_CONTINUOUS")]
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
    #[clap(long, env = "MC_MEASURE_AFTER_DEADLINE")]
    pub measure_after_deadline: bool,

    /// Account key directory.
    #[clap(long, env = "MC_KEY_DIR")]
    pub key_dir: PathBuf,

    /// Number of clients to load from key directory
    #[clap(long, default_value = "6", env = "MC_NUM_CLIENTS")]
    pub num_clients: usize,

    /// Config specific to consensus
    #[clap(flatten)]
    pub consensus_config: ConsensusConfig,

    /// Fog Ledger service URI
    #[clap(long, required = true, env = "MC_FOG_LEDGER")]
    pub fog_ledger: FogLedgerUri,

    /// Fog View service URI.
    #[clap(long, env = "MC_FOG_VIEW")]
    pub fog_view: FogViewUri,

    /// Seconds to wait for a transaction to clear, before it has exceeded
    /// deadline. The healthy status will be set false if we exceed this
    /// deadline.
    #[clap(long, default_value = "5", parse(try_from_str = parse_duration_in_seconds), env = "MC_CONSENSUS_WAIT")]
    pub consensus_wait: Duration,

    /// Seconds to wait for ledger sync on fog
    /// This affects the double-spend test but not the continuous mode of
    /// operation.
    #[clap(long, default_value = "5", parse(try_from_str = parse_duration_in_seconds), env = "MC_LEDGER_SYNC_WAIT")]
    pub ledger_sync_wait: Duration,

    /// Number of transactions to attempt (only when not running continuously)
    #[clap(long, default_value = "36", env = "MC_NUM_TRANSACTIONS")]
    pub num_transactions: usize,

    /// When running continuously, specifies the length of the pause between
    /// test transfers
    ///
    /// By default the pause is 15 minutes.
    #[clap(long, default_value = "900", parse(try_from_str = parse_duration_in_seconds), env = "MC_TRANSFER_PERIOD")]
    pub transfer_period: Duration,

    /// Amount to transfer per transaction
    #[clap(long, default_value = "20", env = "MC_TRANSFER_AMOUNT")]
    pub transfer_amount: u64,

    /// Consensus enclave CSS file (overriding the build-time CSS)
    #[clap(long, env = "MC_CONSENSUS_ENCLAVE_CSS")]
    pub consensus_enclave_css: Option<String>,

    /// Fog ingest enclave CSS file (overriding the build-time CSS)
    #[clap(long, env = "MC_INGEST_ENCLAVE_CSS")]
    pub ingest_enclave_css: Option<String>,

    /// Fog ledger enclave CSS file (overriding the build-time CSS)
    #[clap(long, env = "MC_LEDGER_ENCLAVE_CSS")]
    pub ledger_enclave_css: Option<String>,

    /// Fog view enclave CSS file (overriding the build-time CSS)
    #[clap(long, env = "MC_VIEW_ENCLAVE_CSS")]
    pub view_enclave_css: Option<String>,

    /// Whether to turn off memos, for backwards compatibility
    #[clap(long, env = "MC_NO_MEMOS")]
    pub no_memos: bool,

    /// Grpc retry config
    #[clap(flatten)]
    pub grpc_retry_config: GrpcRetryConfig,

    /// What token id to use for the test
    #[clap(long, env = "MC_TOKEN_ID", default_value = "0")]
    pub token_id: TokenId,

    /// Additional token ids to use for the test
    #[clap(long, env = "MC_EXTRA_TOKEN_IDS", use_value_delimiter = true)]
    pub extra_token_ids: Vec<TokenId>,
}

impl TestClientConfig {
    /// Load account keys from disk corresponding to this config
    pub fn load_accounts(&self, logger: &Logger) -> Vec<AccountKey> {
        // Load key_dir or read from bootstrap keys.
        let key_dir: String = self.key_dir.clone().to_str().unwrap().to_string();
        log::info!(logger, "Using key_dir: {:?}", key_dir);

        // Load the key files
        log::info!(logger, "Loading account keys from {:?}", key_dir);
        mc_util_keyfile::keygen::read_default_mnemonics(&key_dir)
            .unwrap()
            .into_iter()
            .take(self.num_clients)
            .collect::<_>()
    }

    /// Get the primary token id and any extra token ids
    pub fn token_ids(&self) -> Vec<TokenId> {
        (&[self.token_id])
            .iter()
            .chain(self.extra_token_ids.iter())
            .cloned()
            .collect()
    }
}

/// Parser container for consensus config information
#[derive(Clone, Debug, Parser, Serialize)]
pub struct ConsensusConfig {
    /// Consensus Validator nodes to connect to.
    #[clap(
        long = "consensus",
        required = true,
        min_values = 1,
        env = "MC_CONSENSUS",
        use_value_delimiter = true
    )]
    pub consensus_validators: Vec<ConsensusClientUri>,
}
