// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Configuration parameters for the fog distribution utility

use clap::Parser;
use grpcio::EnvBuilder;
use mc_attest_verifier::{MrSignerVerifier, Verifier, DEBUG_ENCLAVE};
use mc_common::logger::{o, Logger};
use mc_connection::{
    HardcodedCredentialsProvider, Result as ConnectionResult, SyncConnection, ThickClient,
};
use mc_util_uri::{ConnectionUri, ConsensusClientUri};
use std::{path::PathBuf, sync::Arc};

/// Configuration parameters for the fog distribution utility
#[derive(Clone, Debug, Parser)]
#[clap(
    name = "fog-distribution",
    about = "Transfer funds from source accounts (bootstrapped) to destination accounts (which may have fog). This slams the network with many Txs in parallel as a stress test.",
    version
)]
pub struct Config {
    /// Path to sample data for keys/ and ledger/
    #[clap(long, parse(from_os_str), env = "MC_SAMPLE_DATA_DIR")]
    pub sample_data_dir: PathBuf,

    /// Number of transactions to send per account
    #[clap(long, default_value = "-1", env = "MC_NUM_TX_TO_SEND")]
    pub num_tx_to_send: isize,

    /// Number of inputs in the ring
    #[clap(long, default_value = "11", env = "MC_RING_SIZE")]
    pub ring_size: usize,

    /// Block after which to tombstone
    #[clap(long, default_value = "50", env = "MC_TOMBSTONE_BLOCK")]
    pub tombstone_block: u64,

    /// Number of SpendableTxOut inputs to use per transactions
    #[clap(long, default_value = "1", env = "MC_NUM_INPUTS")]
    pub num_inputs: usize,

    /// Offset into transactions to start
    #[clap(long, default_value = "0", env = "MC_START_OFFSET")]
    pub start_offset: usize,

    /// Num transactions per source account in the bootstrapped ledger - must
    /// set this if using start_offset
    #[clap(
        long,
        default_value = "0",
        env = "MC_NUM_TRANSACTIONS_PER_SOURCE_ACCOUNT"
    )]
    pub num_transactions_per_source_account: usize,

    /// Num seed transactions per destination account. Each destination is
    /// guaranteed to receive at least this many TxOuts. If the ledger is
    /// bootstrapped with multiple token ids, this can be set to guarantee no
    /// destination has a zero balance for any token.
    #[clap(
        long,
        default_value = "0",
        env = "MC_NUM_SEED_TRANSACTIONS_PER_DESTINATION_ACCOUNT"
    )]
    pub num_seed_transactions_per_destination_account: usize,

    /// Number of threads with which to submit transactions (threadpool uses
    /// min with cpu)
    #[clap(long, default_value = "32", env = "MC_MAX_THREADS")]
    pub max_threads: usize,

    /// Delay (in milliseconds) before each add_transaction call
    #[clap(long, default_value = "0", env = "MC_ADD_TX_DELAY_MS")]
    pub add_tx_delay_ms: u64,

    /// Destination keys subdirectory. Defaults to `fog_keys`
    #[clap(long, default_value = "fog_keys", env = "MC_FOG_KEYS_SUBDIR")]
    pub fog_keys_subdir: String,

    /// Validator nodes to connect to.
    /// Sample usages:
    ///     --peer mc://foo:123 --peer mc://bar:456
    ///     --peer mc://foo:123,mc://bar:456
    ///     env MC_PEER=mc://foo:123,mc://bar:456
    #[clap(long = "peer", env = "MC_PEER", use_value_delimiter = true)]
    pub peers: Option<Vec<ConsensusClientUri>>,

    /// Dry run (don't actually submit transactions, just load from bootstrapped
    /// ledger)
    #[clap(long)]
    pub dry_run: bool,
}

impl Config {
    /// Get thick client connections to all configured consensus nodes
    pub fn get_connections(
        &self,
        logger: &Logger,
    ) -> ConnectionResult<Vec<SyncConnection<ThickClient<HardcodedCredentialsProvider>>>> {
        let mut mr_signer_verifier =
            MrSignerVerifier::from(mc_consensus_enclave_measurement::sigstruct());
        mr_signer_verifier.allow_hardening_advisory("INTEL-SA-00334");

        let mut verifier = Verifier::default();
        verifier.mr_signer(mr_signer_verifier).debug(DEBUG_ENCLAVE);

        self.peers
            .as_ref()
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
