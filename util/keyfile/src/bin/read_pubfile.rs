// Copyright (c) 2018-2022 The MobileCoin Foundation
#![deny(missing_docs)]

//! Utility to read .pub files.

use clap::Parser;
use mc_util_keyfile::read_pubfile;
use std::path::PathBuf;

#[derive(Debug, Parser)]
struct Config {
    /// Path to pubfile
    #[clap(long, env = "MC_PUBFILE")]
    pub pubfile: PathBuf,
}

fn main() {
    let config = Config::parse();

    let pubaddress = read_pubfile(&config.pubfile).expect("Could not read pubfile");

    println!(
        "Public address for {:?}: \n\t {:?}",
        config.pubfile, pubaddress
    );

    println!(
        "View Public Bytes: {:?}",
        pubaddress.view_public_key().to_bytes()
    );

    println!(
        "View Public Bytes (hex): {:?}",
        hex::encode(pubaddress.view_public_key().to_bytes())
    );

    println!(
        "Spend Public Bytes: {:?}",
        pubaddress.spend_public_key().to_bytes()
    );

    println!(
        "Spend Public Bytes (hex): {:?}",
        hex::encode(pubaddress.spend_public_key().to_bytes())
    );
}
