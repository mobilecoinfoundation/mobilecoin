// Copyright (c) 2018-2022 The MobileCoin Foundation
#![deny(missing_docs)]

//! A utility to generate a sample ledger.

use clap::Parser;
use mc_common::logger::create_root_logger;
use std::path::PathBuf;

/// Configuration.
#[derive(Debug, Parser)]
struct Config {
    /// Number of transactions per key to generate
    #[clap(long, short, default_value = "100", env = "MC_TXS")]
    pub txs: usize,

    /// Number of blocks to divide transactions.
    #[clap(long, short, default_value = "1", env = "MC_BLOCKS")]
    pub blocks: usize,

    /// Key images per transaction
    #[clap(long, short, default_value = "1", env = "MC_KEY_IMAGES")]
    pub key_images: usize,

    /// Seed to use when generating blocks (e.g.
    // 1234567812345678123456781234567812345678123456781234567812345678).
    #[clap(long, short, parse(try_from_str = hex::FromHex::from_hex), env = "MC_SEED")]
    pub seed: Option<[u8; 32]>,

    /// Max token id. If set to 1, then this will double the number of tx's in
    /// the bootstrap. First will come all token id 0, then all token id 1.
    ///
    /// Historically this was not present, and is only added to support testing
    /// of confidential token ids.
    #[clap(long, default_value = "0", env = "MC_MAX_TOKEN_ID")]
    pub max_token_id: u64,
}

fn main() {
    let config = Config::parse();

    mc_common::setup_panic_handler();
    let logger = create_root_logger();

    // Read user public keys from disk
    let pub_addrs = mc_util_keyfile::keygen::read_default_pubfiles("keys")
        .expect("Could not read default pubfiles from ./keys");
    assert!(!pub_addrs.is_empty());

    // Bootstrap the ledger db
    mc_util_generate_sample_ledger::bootstrap_ledger(
        &PathBuf::from("ledger"),
        &pub_addrs,
        config.txs,
        config.blocks,
        config.key_images,
        config.seed,
        config.max_token_id,
        logger,
    );
}
