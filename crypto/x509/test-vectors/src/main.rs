// Copyright (c) 2018-2021 MobileCoin Inc.

//! Retrieve the paths of previously generated test vectors

use clap::{ArgEnum, Parser};
use std::fmt::Debug;

#[derive(ArgEnum, Clone, Debug, PartialEq)]
enum PathKind {
    /// Retrieve the path to the PEM chain
    Chain,
    /// Retrieve the path to the PEM private key
    Key,
}

#[derive(Debug, Parser, PartialEq)]
struct Config {
    /// The name of the test to use
    #[clap(long, env = "MC_TEST_NAME")]
    pub test_name: String,
    /// The type of path to retrieve
    #[clap(arg_enum, long, alias = "type", env = "MC_TYPE")]
    pub kind: PathKind,
}

fn main() {
    let config = Config::parse();
    let output = match config.kind {
        PathKind::Chain => mc_crypto_x509_test_vectors::chain_path(&config.test_name),
        PathKind::Key => mc_crypto_x509_test_vectors::key_path(&config.test_name),
    };
    println!("{}", output.display())
}
