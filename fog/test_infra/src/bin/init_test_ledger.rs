// Copyright (c) 2018-2021 The MobileCoin Foundation

//! Initialize a ledger db with genesis block,
//! and a watcher db suitable for conformance testing
//!
//! Use command line arguments to configure locations of keys and ledger etc.

use digest::Digest;
use mc_common::logger::create_root_logger;
use mc_crypto_hashes::Blake2b256;
use std::path::PathBuf;
use structopt::StructOpt;

#[derive(Debug, StructOpt)]
struct Config {
    /// Path to keys
    #[structopt(long)]
    pub keys: PathBuf,

    /// Path to output ledger
    #[structopt(long = "ledger-db")]
    pub ledger: PathBuf,

    /// Path to output watcher db
    #[structopt(long = "watcher-db")]
    pub watcher: PathBuf,

    // Seed to use when generating blocks
    #[structopt(long, default_value = "42")]
    pub seed: u64,
}

fn main() {
    // Logging must go to stderr to not interfere with STDOUT
    std::env::set_var("MC_LOG_STDERR", "1");
    let config = Config::from_args();

    let logger = create_root_logger();

    // Read user public keys from disk
    let pub_addrs = mc_util_keyfile::keygen::read_default_pubfiles(config.keys)
        .expect("Could not read public key files");
    assert_ne!(0, pub_addrs.len());

    let mut hasher = Blake2b256::new();
    hasher.update(config.seed.to_le_bytes());
    let seed = Some(<[u8; 32]>::from(hasher.finalize()));

    // Bootstrap the ledger db
    // Only one block, and 0 key images in the block
    mc_util_generate_sample_ledger::bootstrap_ledger(
        &config.ledger,
        &pub_addrs,
        pub_addrs.len(),
        1,
        0,
        seed,
        None,
        logger.clone(),
    );

    // Initialize the watcher db
    mc_watcher::watcher_db::create_or_open_rw_watcher_db(&config.watcher, &[], logger)
        .expect("Could not create watcher_db");
}
