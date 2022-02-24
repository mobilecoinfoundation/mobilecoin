// Copyright (c) 2018-2021 The MobileCoin Foundation

//! Configuration parameters for the Fog ingest client

use clap::{Parser, Subcommand};
use mc_crypto_keys::CompressedRistrettoPublic;
use mc_util_parse::parse_duration_in_seconds;
use std::time::Duration;

#[derive(Clone, Parser)]
pub struct IngestConfig {
    /// URI for ingest server
    #[clap(long, env = "MC_URI")]
    pub uri: String,

    /// How long to retry if unavailable, this is useful for tests
    #[clap(long, short, default_value = "10", parse(try_from_str = parse_duration_in_seconds), env = "MC_RETRY_SECONDS")]
    pub retry_seconds: Duration,

    #[clap(subcommand)]
    pub cmd: IngestConfigCommand,
}

fn parse_ristretto_hex(src: &str) -> Result<CompressedRistrettoPublic, String> {
    let mut key_bytes = [0u8; 32];
    hex::decode_to_slice(src.as_bytes(), &mut key_bytes[..])
        .map_err(|err| format!("Hex decode error: {:?}", err))?;
    Ok(CompressedRistrettoPublic::from(&key_bytes))
}

#[derive(Clone, Subcommand)]
pub enum IngestConfigCommand {
    /// Get a summary of the state of the ingest server.
    GetStatus,

    /// Wipe out all keys and oram state in the enclave, replacing them with new
    /// random keys.
    NewKeys,

    /// Set the list of peers of this ingest server.
    SetPeers { peer_uris: Vec<String> },

    /// Set the pubkey_expiry_window of the ingest server.
    SetPubkeyExpiryWindow {
        /// This value is a number of blocks that is added to the current block
        /// index to compute the "pubkey_expiry" value of fog reports.
        #[clap(env = "MC_PUBKEY_EXPIRY_WINDOW")]
        pubkey_expiry_window: u64,
    },

    /// Attempt to put an idle server in the active mode.
    Activate,

    /// Attempt to put an active server in the retiring mode, after which it
    /// will eventually become idle.
    Retire,

    /// Attempt to take a retired server out of retirement.
    Unretire,

    /// Report a lost ingress key, with pubkey bytes specified in hex
    ReportLostIngressKey {
        /// The lost key.
        #[clap(long, short, parse(try_from_str = parse_ristretto_hex), env = "MC_KEY")]
        key: CompressedRistrettoPublic,
    },

    /// Gets the list of reported missed block ranges.
    GetMissedBlockRanges,

    /// Retrieves a private key from a remote ingest enclave and sets it as
    /// the current enclaves's private key.
    SyncKeysFromRemote {
        /// The Fog Ingest Peer URI.
        #[clap(env = "MC_PEER_URI")]
        peer_uri: String,
    },

    ///  Retrieves the ingress public keys for the entire system (as opposed to
    ///  those of a single IngestServer) and filters according to the provided
    ///  parameters.
    GetIngressPublicKeyRecords {
        /// Ingress keys are "started" at certain blocks. Only ingress keys that
        /// are "started"  at this block index will be included in the response.
        #[clap(short, long, env = "MC_START_BLOCK_AT_LEAST", default_value_t)]
        start_block_at_least: u64,
        /// If true the response will include ingress keys that have been lost.
        #[clap(short = 'l', long = "include-lost", env = "MC_INCLUDE_LOST")]
        should_include_lost_keys: bool,
        /// If true the response will include ingress keys that have been
        /// retired.
        #[clap(short = 'r', long = "include-retired", env = "MC_INCLUDE_RETIRED")]
        should_include_retired_keys: bool,
    },
}
