// Copyright (c) 2018-2022 The MobileCoin Foundation

//! A utility for decoding b58 strings
#![deny(missing_docs)]

use clap::Parser;
use mc_api::printable::PrintableWrapper;

#[derive(Parser)]
struct Config {
    pub b58_string: String,
}

fn main() {
    let config = Config::parse();

    match PrintableWrapper::b58_decode(config.b58_string) {
        Ok(printable_wrapper) => {
            println!("B58 decoded successfully to {:?}", printable_wrapper);
        }

        Err(err) => {
            println!("Failed decoding b58 into a known object: {}", err);
            std::process::exit(1);
        }
    }
}
