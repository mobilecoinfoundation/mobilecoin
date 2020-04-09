// Copyright (c) 2018-2020 MobileCoin Inc.

use std::path::PathBuf;
use structopt::StructOpt;

#[derive(Debug, StructOpt)]
struct Config {
    /// FogURL
    #[structopt(short, long)]
    pub acct: Option<String>,

    /// Number of user keys to generate.
    #[structopt(short, long, default_value = "10")]
    pub num: usize,

    /// Output directory, defaults to ./keys
    #[structopt(long)]
    pub output_dir: Option<PathBuf>,

    // Seed to use when generating keys (e.g. 1234567812345678123456781234567812345678123456781234567812345678).
    #[structopt(short, long, parse(try_from_str=hex::FromHex::from_hex))]
    pub seed: Option<[u8; 32]>,
}

fn main() {
    let config = Config::from_args();

    let path = config
        .output_dir
        .clone()
        .unwrap_or_else(|| std::env::current_dir().unwrap().join("keys"));

    println!("Writing to {:?}", path);

    keyfile::keygen::write_default_keyfiles(
        path,
        config.num,
        config.acct.as_ref().map(|x| x.as_str()),
        config.seed.unwrap_or(keyfile::keygen::DEFAULT_SEED),
    )
    .unwrap();
}
