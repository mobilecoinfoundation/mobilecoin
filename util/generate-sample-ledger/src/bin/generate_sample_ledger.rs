// Copyright (c) 2018-2021 The MobileCoin Foundation

use mc_common::logger::create_root_logger;
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

    // Seed to use when generating blocks (e.g.
    // 1234567812345678123456781234567812345678123456781234567812345678).
    #[structopt(long = "seed", short = "s", parse(try_from_str=hex::FromHex::from_hex))]
    pub seed: Option<[u8; 32]>,

    #[structopt(long = "hint-text")]
    pub hint_text: Option<String>,
}

fn main() {
    let config = Config::from_args();

    mc_common::setup_panic_handler();
    let logger = create_root_logger();

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
        config.seed,
        config.hint_text.as_deref(),
        logger,
    );
}
