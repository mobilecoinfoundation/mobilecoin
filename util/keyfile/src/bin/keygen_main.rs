// Copyright (c) 2018-2022 The MobileCoin Foundation
#![deny(missing_docs)]

//! A CLI tool for generating individual MobileCoin identities

use clap::Parser;
use mc_account_keys::{RootEntropy, RootIdentity};
use mc_util_keyfile::config::Config;

fn main() {
    let config = Config::parse();
    let path = config
        .output_dir
        .clone()
        .unwrap_or_else(|| std::env::current_dir().unwrap());

    let fog_url = config.acct.clone();
    let name = config.name.clone();
    let root_entropy = config.get_root_entropy();

    let id = RootIdentity {
        root_entropy: RootEntropy::from(&root_entropy),
        fog_report_url: fog_url.unwrap_or_default(),
        fog_report_id: Default::default(),
        fog_authority_spki: Default::default(),
    };

    println!("Writing to {:?}", path);

    mc_util_keyfile::keygen::write_keyfiles(path, &name, &id).unwrap();
}
