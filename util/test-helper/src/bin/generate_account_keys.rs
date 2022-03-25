// Copyright (c) 2018-2022 The MobileCoin Foundation
#![deny(missing_docs)]

//! A tool for exporting known accounts to std out
//!
//! It is convenient to be able export a set of known accounts to a file
//! for use in another program (e.g. for use in python scripts)
//!
//! Suggested use:
//! cargo run --release -- --num 1000 >> account_keys.json
use clap::Parser;
use mc_util_test_helper::{known_accounts, AccountKey};

#[derive(Debug, Parser)]
struct Config {
    /// Number of user keys to generate.
    #[clap(short, long, default_value = "10", env = "MC_NUM")]
    pub num: usize,
}

fn main() {
    let config = Config::parse();

    let account_keys: Vec<AccountKey> = known_accounts::generate(config.num);

    // Write a valid JSON blob to stdout, of the form:
    //{"account_keys":[
    //  {"vpk":[u8;32],
    //   "spk":[u8;32]}
    //  ,{"vpk":[u8;32],
    //   "spk":[u8;32]}
    //  ,{"vpk":[u8;32],
    //   "spk":[u8;32]}
    //]}

    println!("{{\"account_keys\":[");

    let mut i = 0;
    let mut remaining: usize = config.num;
    while remaining > 0 {
        let vpk = account_keys[i].view_private_key().to_bytes();
        let spk = account_keys[i].spend_private_key().to_bytes();
        if i != 0 {
            print!(",");
        } else {
            print!(" ");
        }
        println!("{{\"vpk\":{:?},", vpk);
        println!("   \"spk\":{:?}}}", spk);
        remaining -= 1;
        i += 1;
    }
    println!("]}}");
}
