// Copyright (c) 2018-2020 MobileCoin Inc.

use std::path::PathBuf;
use structopt::StructOpt;

#[derive(Debug, StructOpt)]
struct Config {
    /// Number of transactions per key to generate
    #[structopt(long = "txs", short = "t", default_value = "100")]
    pub num_txs: usize,

    /// Number of blocks to divide transactions.
    #[structopt(long = "blocks", short = "b", default_value = "1")]
    pub num_blocks: usize,

    /// Key images per transaction
    #[structopt(long = "key-images", short = "k", default_value = "0")]
    pub num_key_images: usize,
}

fn main() {
    let config = Config::from_args();

    // Read user public keys from disk
    let pub_addrs = mc_util_keyfile::keygen::read_default_pubfiles("keys")
        .expect("Could not read default pubfiles from ./keys");
    assert_ne!(0, pub_addrs.len());

    // Bootstrap the ledger db
    mc_util_generate_sample_ledger::bootstrap_ledger(
        &PathBuf::from("ledger"),
        &pub_addrs,
        config.num_txs,
        config.num_blocks,
        config.num_key_images,
    );
}
