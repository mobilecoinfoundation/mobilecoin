// Copyright (c) 2018-2020 MobileCoin Inc.

//! A utility for generating GRPC authentication tokens.

use mc_util_grpc::auth::TokenBasicCredentialsGenerator;
use percent_encoding::{utf8_percent_encode, NON_ALPHANUMERIC};
use structopt::StructOpt;

#[derive(Clone, Debug, StructOpt)]
#[structopt(
    name = "mc-util-grpc-token-generator",
    about = "GRPC Token Generator Utility"
)]
pub struct Config {
    /// Secret shared between the token generator and the token validator.
    #[structopt(long, parse(try_from_str=from_hex_32))]
    pub shared_secret: [u8; 32],

    /// Username to generator the token for
    #[structopt(long)]
    pub username: String,
}

fn main() {
    let config = Config::from_args();
    let token_generator = TokenBasicCredentialsGenerator::new(config.shared_secret.clone());
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

/// Converts a hex-encoded string into an array of 32 bytes.
fn from_hex_32(src: &str) -> Result<[u8; 32], String> {
    let bytes = hex::decode(src).map_err(|err| format!("Invalid input: {}", err))?;
    if bytes.len() != 32 {
        return Err(format!(
            "Invalid input length, got {} bytes while expecting 32",
            bytes.len()
        ));
    }

    let mut output = [0; 32];
    output.copy_from_slice(&bytes[..]);
    Ok(output)
}
