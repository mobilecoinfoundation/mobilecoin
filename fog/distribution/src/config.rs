// Copyright (c) 2018-2021 The MobileCoin Foundation

//! Configuration parameters for the fog distribution utility

use grpcio::EnvBuilder;
use mc_attest_core::{MrSignerVerifier, Verifier, DEBUG_ENCLAVE};
use mc_common::logger::{o, Logger};
use mc_connection::{
    HardcodedCredentialsProvider, Result as ConnectionResult, SyncConnection, ThickClient,
};
use mc_mobilecoind::config::PeersConfig;
use mc_util_uri::ConnectionUri;
use std::{fs, path::PathBuf, str::FromStr, sync::Arc};
use structopt::StructOpt;

#[derive(Clone, Debug, StructOpt)]
#[structopt(name = "fog-distribution", about = "Generate valid fog txs.")]
pub struct Config {
    /// Path to sample data for keys/ and ledger/
    #[structopt(long, parse(from_os_str))]
    pub sample_data_dir: PathBuf,

    /// Number of transactions to send per account
    #[structopt(long, default_value = "-1")]
    pub num_tx_to_send: isize,

    /// Number of inputs in the ring
    #[structopt(long, default_value = "11")]
    pub ring_size: usize,

    /// Block after which to tombstone
    #[structopt(long, default_value = "50")]
    pub tombstone_block: u64,

    #[structopt(long, default_value = "1")]
    pub num_inputs: usize,

    /// Ask consensus for the current block to set tombstone appropriately
    #[structopt(long)]
    pub query_consensus_for_cur_block: bool,

    /// Offset into transactions to start
    #[structopt(long, default_value = "0")]
    pub start_offset: usize,

    /// Num transactions per account - must set this if using start_offset
    #[structopt(long, default_value = "0")]
    pub num_transactions_per_account: usize,

    /// Offset into accounts
    #[structopt(long, default_value = "0")]
    pub account_offset: usize,

    /// Number of threads with which to submit transactions (threadpool uses min
    /// with cpu)
    #[structopt(long, default_value = "32")]
    pub max_threads: usize,

    /// Delay (in milliseconds) before each add_transaction call
    #[structopt(long, default_value = "0")]
    pub add_tx_delay_ms: u64,

    /// URLs to use for transaction data.
    ///
    /// For example: https://s3-us-west-1.amazonaws.com/mobilecoin.chain/node1.master.mobilecoin.com/
    #[structopt(long, default_value = "fog_keys")]
    pub fog_keys_subdir: String,

    #[structopt(flatten)]
    pub peers_config: PeersConfig,
}

impl Config {
    pub fn get_connections(
        &self,
        logger: &Logger,
    ) -> ConnectionResult<Vec<SyncConnection<ThickClient<HardcodedCredentialsProvider>>>> {
        let mut mr_signer_verifier =
            MrSignerVerifier::from(mc_consensus_enclave_measurement::sigstruct());
        mr_signer_verifier.allow_hardening_advisory("INTEL-SA-00334");

        let mut verifier = Verifier::default();
        verifier.mr_signer(mr_signer_verifier).debug(DEBUG_ENCLAVE);

        self.peers_config
            .peers
            .clone()
            .unwrap()
            .iter()
            .map(|uri| {
                // We create a new environment for each peer to maintain current behavior
                let env = Arc::new(
                    EnvBuilder::new()
                        .name_prefix(format!("fog-distro-{}", uri.addr()))
                        .build(),
                );
                let logger = logger.new(o!("mc.cxn" => uri.addr()));
                ThickClient::new(
                    uri.clone(),
                    verifier.clone(),
                    env,
                    HardcodedCredentialsProvider::from(uri),
                    logger.clone(),
                )
                .map(|inner| SyncConnection::new(inner, logger))
            })
            .collect()
    }
}

#[derive(Clone, Debug)]
pub struct FileData(pub Vec<u8>);

impl FromStr for FileData {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self(fs::read(s).map_err(|e| {
            format!("Failed reading \"{}\": {:?}", s, e)
        })?))
    }
}
