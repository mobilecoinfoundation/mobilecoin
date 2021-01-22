// Copyright (c) 2018-2021 The MobileCoin Foundation

//! A utility for generating GRPC authentication tokens.

use mc_common::time::SystemTimeProvider;
use mc_util_grpc::TokenBasicCredentialsGenerator;
use percent_encoding::{utf8_percent_encode, NON_ALPHANUMERIC};
use structopt::StructOpt;

#[derive(Clone, Debug, StructOpt)]
#[structopt(
    name = "mc-util-grpc-token-generator",
    about = "GRPC Token Generator Utility"
)]
pub struct Config {
    /// Secret shared between the token generator and the token validator.
    #[structopt(long, parse(try_from_str=hex::FromHex::from_hex))]
    pub shared_secret: [u8; 32],

    /// Username to generator the token for
    #[structopt(long)]
    pub username: String,
}

fn main() {
    let config = Config::from_args();
    let token_generator =
        TokenBasicCredentialsGenerator::new(config.shared_secret, SystemTimeProvider::default());
    let creds = token_generator
        .generate_for(&config.username)
        .expect("Failed generating token");
    println!("Username: {}", creds.username());
    println!("Password: {}", creds.password());
    println!(
        "Password (percent-encoded): {}",
        utf8_percent_encode(creds.password(), NON_ALPHANUMERIC).to_string()
    );
}
