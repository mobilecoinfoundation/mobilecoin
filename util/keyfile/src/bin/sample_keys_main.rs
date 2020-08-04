// Copyright (c) 2018-2020 MobileCoin Inc.

use hex::FromHex;
use std::{path::PathBuf, vec::Vec};
use structopt::StructOpt;

// Hack to work around Vec special handling in structopt
type VecBytes = Vec<u8>;

#[derive(Debug, StructOpt)]
struct Config {
    /// Fog Report URL
    #[structopt(long)]
    pub fog_report_url: Option<String>,

    /// Fog Report ID
    #[structopt(long)]
    pub fog_report_id: Option<String>,

    /// Fog Authority Fingerprint, hex encoded
    #[structopt(long, parse(try_from_str=parse_hex_to_vec))]
    pub fog_authority_fingerprint: Option<VecBytes>,

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

fn parse_hex_to_vec(src: &str) -> Result<VecBytes, String> {
    let v: Vec<u8> = Vec::from_hex(src)
        .map_err(|e| format!("Could not get Vec from hex {}: {:?}", src, e))
        .into_iter()
        .flatten()
        .collect();

    Ok(v)
}

fn main() {
    let config = Config::from_args();

    let path = config
        .output_dir
        .clone()
        .unwrap_or_else(|| std::env::current_dir().unwrap().join("keys"));

    println!("Writing {} keys to {:?}", config.num, path);

    mc_util_keyfile::keygen::write_default_keyfiles(
        path,
        config.num,
        config.fog_report_url.as_deref(),
        config.fog_report_id.as_deref(),
        config.fog_authority_fingerprint.as_deref(),
        config.seed.unwrap_or(mc_util_keyfile::keygen::DEFAULT_SEED),
    )
    .unwrap();
}
