// Copyright (c) 2018-2022 The MobileCoin Foundation
#![deny(missing_docs)]

//! A CLI tool for generating individual MobileCoin identities

use bip39::{Language, Mnemonic};
use clap::Parser;
use mc_util_keyfile::{config::Config as GeneralConfig, keygen};
use rand::{RngCore, SeedableRng};
use rand_hc::Hc128Rng;
#[derive(Debug, Parser)]
struct Config {
    #[clap(flatten)]
    pub general: GeneralConfig,

    /// The key name.
    pub name: String,
}
fn main() {
    let config = Config::parse();
    let path = config
        .general
        .output_dir
        .clone()
        .unwrap_or_else(|| std::env::current_dir().unwrap());
    let fog_report_url = config
        .general
        .fog_report_url
        .as_ref()
        .map(AsRef::<str>::as_ref);
    let fog_report_id = config
        .general
        .fog_report_id
        .as_ref()
        .map(String::as_str);
    let fog_authority_spki = config
        .general
        .fog_authority_spki
        .as_ref()
        .map(AsRef::<[u8]>::as_ref);
    let name = config.name.as_str();

    let mut csprng = Hc128Rng::from_seed(config.general.seed);

    let mut entropy = [0u8; 32];
    csprng.fill_bytes(&mut entropy[..]);
    let mnemonic = Mnemonic::from_entropy(&entropy, Language::English)
        .expect("Could not create mnemonic from entropy");

    println!("Writing to {:?}", path);

    keygen::write_keyfiles(
        path,
        name,
        &mnemonic,
        0,
        fog_report_url,
        fog_report_id,
        fog_authority_spki,
    )
    .expect("Could not write keyfile");
}
