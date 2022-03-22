// Copyright (c) 2018-2021 The MobileCoin Foundation

//! A tool for inspecting binary keyfiles
//! Reads .bin file on stdin, or a path to .bin file, emits description on
//! stdout

use mc_account_keys::AccountKey;
use mc_util_keyfile::Slip10IdentityJson;
use std::convert::TryFrom;

fn main() {
    let slip10_id: Slip10IdentityJson = {
        let args: Vec<String> = std::env::args().collect();
        match args.get(1) {
            None => mc_util_keyfile::read_keyfile_data(&mut std::io::stdin())
                .unwrap_or_else(|_| panic!("Failed when reading from stdin")),
            Some(arg) => mc_util_keyfile::read_keyfile(arg)
                .unwrap_or_else(|_| panic!("Failed when reading from {}", arg)),
        }
    };
    let acct_key = AccountKey::try_from(&slip10_id).expect("Failed to build account key");
    println!("{:?}\n{:?}", slip10_id, acct_key,);
}
