// Copyright (c) 2018-2021 The MobileCoin Foundation

//! A tool for exporting known accounts to std out
//!
//! It is convenient to be able export a set of known accounts to a file
//! for use in another program (e.g. for use in python scripts)
//!
//! Suggested use:
//! cargo run --release -- --num 1000 >> account_keys.json
use mc_util_test_helper::{known_accounts, AccountKey};
use structopt::StructOpt;

#[derive(Debug, StructOpt)]
struct Config {
    /// Number of user keys to generate.
    #[structopt(short, long, default_value = "10")]
    pub num: usize,
}

fn main() {
    let config = Config::from_args();

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
