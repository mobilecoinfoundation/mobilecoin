// Copyright (c) 2018-2022 The MobileCoin Foundation
#![deny(missing_docs)]

//! Initialize a ledger db with genesis block,
//! and a watcher db suitable for conformance testing
//!
//! Use command line arguments to configure locations of keys and ledger etc.

use clap::Parser;
use mc_common::logger::create_root_logger;
use mc_crypto_hashes::{Blake2b256, Digest};
use std::path::PathBuf;

#[derive(Debug, Parser)]
struct Config {
    /// Path to keys
    #[clap(long, env = "MC_KEYS")]
    pub keys: PathBuf,

    /// Path to output ledger
    #[clap(long = "ledger-db", env = "MC_LEDGER_DB")]
    pub ledger: PathBuf,

    /// Path to output watcher db
    #[clap(long = "watcher-db", env = "MC_WATCHER_DB")]
    pub watcher: PathBuf,

    // Seed to use when generating blocks
    #[clap(long, default_value = "42", env = "MC_SEED")]
    pub seed: u64,
}

fn main() {
    // Logging must go to stderr to not interfere with STDOUT
    std::env::set_var("MC_LOG_STDERR", "1");
    let config = Config::parse();

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
        0,
        logger.clone(),
    );

    // Initialize the watcher db
    mc_watcher::watcher_db::create_or_open_rw_watcher_db(&config.watcher, &[], logger)
        .expect("Could not create watcher_db");
}
