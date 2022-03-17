// Copyright (c) 2018-2022 The MobileCoin Foundation

//! A utility for generating a predictable Ed25519 private key from a seed, used
//! for testing purposes.

use clap::Parser;
use hex::FromHex;
use mc_crypto_keys::{DistinguishedEncoding, Ed25519Pair};
use mc_util_from_random::FromRandom;
use pem::{encode, Pem};
use rand::SeedableRng;
use rand_hc::Hc128Rng;

#[derive(Parser)]
#[clap(
    name = "mc-util-seeded-ed25519-key-gen",
    about = "A utility for generating a predictable Ed25519 private key from a seed, used for testing purposes."
)]
pub struct Config {
    #[clap(long, parse(try_from_str = FromHex::from_hex), env = "MC_SEED")]
    seed: [u8; 32],
}

fn main() {
    let config = Config::parse();

    let mut rng: Hc128Rng = SeedableRng::from_seed(config.seed);
    let keypair = Ed25519Pair::from_random(&mut rng);
    let der_bytes = keypair.private_key().to_der();
    let pem = encode(&Pem {
        tag: String::from("PRIVATE KEY"),
        contents: der_bytes,
    });
    println!("{}", pem);
}
