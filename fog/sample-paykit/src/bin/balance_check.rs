// Copyright (c) 2018-2022 The MobileCoin Foundation

//! This unix command-line tool exposes the balance check functionality of
//! fog-sample-paykit in a way compatible with the fog-conformance-test. (It
//! could be used against a deployed network too though.)
//!
//! It takes path to account key, and fog urls, as command line parameters, and
//! prints balance check results on STDOUT, in a json format `{ 'block_count':
//! XXX, 'balance': YYY }`.
//!
//! If STDIN is not closed, the program will block on STDIN until a byte is
//! written there, and then print another balance. If the byte is 'd', that
//! signals to dump debug information and exit (because the previous balance
//! didn't have the expected value). See fog-conformance-test documentation for
//! more details.

use clap::Parser;
use mc_common::logger::{create_root_logger, log};
use mc_fog_sample_paykit::ClientBuilder;
use mc_fog_uri::{FogLedgerUri, FogViewUri};
use mc_util_uri::ConsensusClientUri;
use serde_json::json;
use std::{
    io::{ErrorKind, Read},
    path::PathBuf,
    str::FromStr,
};

#[derive(Debug, Parser)]
struct Config {
    /// Path to root identity file to use
    /// Note: This contains the fog-url which is the same as the report-server
    /// uri
    #[clap(long, env = "MC_KEYFILE")]
    pub keyfile: PathBuf,

    /// Ledger server URI
    #[clap(long, env = "MC_LEDGER_URI")]
    pub ledger_uri: FogLedgerUri,

    /// View server URI
    #[clap(long, env = "MC_VIEW_URI")]
    pub view_uri: FogViewUri,
}

fn main() {
    // Logging must go to stderr to not interfere with STDOUT
    std::env::set_var("MC_LOG_STDERR", "1");
    let config = Config::parse();
    let logger = create_root_logger();

    let account_key =
        mc_util_keyfile::read_keyfile(config.keyfile).expect("Could not read private key file");

    // Note: The balance check program is not supposed to submit anything to
    // consensus or talk to consensus, so this is just a dummy value
    let consensus_client_uri = ConsensusClientUri::from_str("mc://127.0.0.1")
        .expect("Could not create dummy consensus client uri");

    let mut sample_paykit = ClientBuilder::new(
        consensus_client_uri,
        config.view_uri.clone(),
        config.ledger_uri,
        account_key,
        logger.clone(),
    )
    .build();

    loop {
        // Do a balance check and print result on one line in stdout
        let (balance, block_count) = sample_paykit
            .check_balance()
            .expect("Failed to compute balance!");
        println!(
            "{}",
            json!({ "block_count": u64::from(block_count), "balance": balance})
        );

        // Read one byte and block on this. Exit if pipe is closed.
        // If the byte we read is 'd', then dump debug output and exit.
        let mut buffer = [0u8; 1];
        if let Err(err) = std::io::stdin().read_exact(&mut buffer) {
            match err.kind() {
                ErrorKind::BrokenPipe => return,
                ErrorKind::UnexpectedEof => return,
                _ => {}
            }
        } else if buffer[0] == b'd' {
            // Our previous reported balance was wrong, we should dump balance data to
            // STDERR, then exit
            for line in sample_paykit.debug_balance().lines() {
                log::info!(logger, "{}", line);
            }
            return;
        }
    }
}
