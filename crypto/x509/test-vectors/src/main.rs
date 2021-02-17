// Copyright (c) 2018-2021 MobileCoin Inc.

//! Retrieve the paths of previously generated test vectors

use std::{
    fmt::{Debug, Display, Formatter, Result as FmtResult},
    str::FromStr,
};
use structopt::StructOpt;

#[derive(Debug)]
struct PathKindParseError;

impl Display for PathKindParseError {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        write!(f, "Unknown type given")
    }
}

#[derive(Debug, PartialEq, StructOpt)]
enum PathKind {
    /// Retrieve the path to the PEM chain
    Chain,
    /// Retrieve the path to the PEM private key
    Key,
}

impl FromStr for PathKind {
    type Err = PathKindParseError;

    fn from_str(src: &str) -> Result<PathKind, PathKindParseError> {
        match src.to_lowercase().as_str() {
            "chain" => Ok(PathKind::Chain),
            "key" => Ok(PathKind::Key),
            _ => Err(PathKindParseError),
        }
    }
}

#[derive(Debug, PartialEq, StructOpt)]
struct Config {
    /// The name of the test to use
    #[structopt(long = "test-name")]
    pub test_name: String,
    /// The type of path to retrieve
    #[structopt(long = "type")]
    pub kind: PathKind,
}

fn main() {
    let config = Config::from_args();
    let output = match config.kind {
        PathKind::Chain => mc_crypto_x509_test_vectors::chain_path(&config.test_name),
        PathKind::Key => mc_crypto_x509_test_vectors::key_path(&config.test_name),
    };
    println!("{}", output.display())
}
