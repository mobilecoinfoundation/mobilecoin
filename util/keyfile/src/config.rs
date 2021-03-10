// Copyright (c) 2018-2021 The MobileCoin Foundation

use rand::{rngs::StdRng, SeedableRng};
use std::path::PathBuf;
use structopt::StructOpt;

/// Configuration for generating key files for a new user identity
#[derive(Debug, StructOpt)]
pub struct Config {
    /// Optional FogURL for the accounts
    #[structopt(short, long)]
    pub acct: Option<String>,

    /// Desired name of keyfiles e.g. 'alice' -> alice.pub, alice.bin.
    #[structopt(short, long)]
    pub name: String,

    // Root entropy to use, in hex format (e.g.
    // 1234567812345678123456781234567812345678123456781234567812345678).
    #[structopt(short, long, parse(try_from_str=hex::FromHex::from_hex), conflicts_with("seed"))]
    pub root: Option<[u8; 32]>,

    /// Seed to use to generate root entropy.
    #[structopt(short, long, conflicts_with("root"))]
    pub seed: Option<u8>,

    /// Output directory, defaults to current directory.
    #[structopt(long)]
    pub output_dir: Option<PathBuf>,
}

impl Config {
    // This consumes self because it might not be deterministic
    pub fn get_root_entropy(self) -> [u8; 32] {
        if let Some(root) = self.root {
            return root;
        }
        if let Some(seed) = self.seed {
            use rand::Rng;
            let mut rng: StdRng = SeedableRng::from_seed([seed; 32]);
            return rng.gen();
        }
        use mc_crypto_rand::RngCore;
        let mut result = [0u8; 32];
        mc_crypto_rand::McRng::default().fill_bytes(&mut result);
        result
    }
}
