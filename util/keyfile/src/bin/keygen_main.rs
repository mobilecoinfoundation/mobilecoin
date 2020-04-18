// Copyright (c) 2018-2020 MobileCoin Inc.

//! A CLI tool for generating individual MobileCoin identities

use mc_transaction_std::identity::RootIdentity;
use mc_util_keyfile::config::Config;
use structopt::StructOpt;

fn main() {
    let config = Config::from_args();
    let path = config
        .output_dir
        .clone()
        .unwrap_or_else(|| std::env::current_dir().unwrap());

    let fog_url = config.acct.clone();
    let name = config.name.clone();
    let root_entropy = config.get_root_entropy();

    let id = RootIdentity {
        root_entropy,
        fog_url,
    };

    println!("Writing to {:?}", path);

    mc_util_keyfile::keygen::write_keyfiles(path, &name, &id).unwrap();
}
