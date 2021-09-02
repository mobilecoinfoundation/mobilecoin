// Copyright (c) 2018-2021 The MobileCoin Foundation

use mc_common::logger::{log, Logger};
use mc_util_uri::ConsensusClientUri;

use mc_fog_sample_paykit::AccountKey;

use std::{path::PathBuf, str::FromStr, time::Duration};
use structopt::StructOpt;

pub const TEST_FOG_AUTHORITY_FINGERPRINT: [u8; 4] = [9, 9, 9, 9];
pub const TEST_FOG_REPORT_ID: &str = "";

#[derive(Debug, StructOpt)]
#[structopt(name = "test-client", about = "Test client for Fog infrastructure.")]
pub struct Config {
    /// Account key directory.
    #[structopt(long)]
    pub key_dir: PathBuf,

    /// Number of clients to load from key directory
    #[structopt(long, default_value = "6")]
    pub num_clients: usize,

    #[structopt(flatten)]
    pub consensus_config: ConsensusConfig,

    /// Fog Ledger service URI
    #[structopt(long, required = true)]
    pub fog_ledger: String,

    /// Fog View service URI.
    #[structopt(long)]
    pub fog_view: String,

    /// Seconds to wait for consensus to clear
    #[structopt(long, default_value = "5", parse(try_from_str=parse_duration_in_seconds))]
    pub consensus_wait: Duration,

    /// Seconds to wait for ledger sync on fog
    #[structopt(long, default_value = "5", parse(try_from_str=parse_duration_in_seconds))]
    pub ledger_sync_wait: Duration,

    /// Number of transactions to attempt
    #[structopt(long, default_value = "36")]
    pub num_transactions: usize,

    /// Amount to transfer per transaction
    #[structopt(long, default_value = "20")]
    pub transfer_amount: u64,
}

impl Config {
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

#[derive(Clone, Debug, StructOpt)]
#[structopt()]
pub struct ConsensusConfig {
    /// Consensus Validator nodes to connect to.
    #[structopt(long = "consensus", required = true, min_values = 1)]
    pub consensus_validators: Vec<ConsensusClientUri>,
}

fn parse_duration_in_seconds(src: &str) -> Result<Duration, std::num::ParseIntError> {
    Ok(Duration::from_secs(u64::from_str(src)?))
}
