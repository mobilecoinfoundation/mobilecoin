// Copyright (c) 2018-2021 The MobileCoin Foundation

//! Configuration parameters for the Fog ingest client

use mc_crypto_keys::CompressedRistrettoPublic;
use mc_util_parse::parse_duration_in_seconds;
use std::time::Duration;
use structopt::StructOpt;

#[derive(Clone, StructOpt)]
pub struct IngestConfig {
    /// URI for ingest server
    #[structopt(long)]
    pub uri: String,

    /// How long to retry if unavailable, this is useful for tests
    #[structopt(long, short = "r", default_value = "10", parse(try_from_str=parse_duration_in_seconds))]
    pub retry_seconds: Duration,

    #[structopt(subcommand)]
    pub cmd: IngestConfigCommand,
}

fn parse_ristretto_hex(src: &str) -> Result<CompressedRistrettoPublic, String> {
    let mut key_bytes = [0u8; 32];
    hex::decode_to_slice(src.as_bytes(), &mut key_bytes[..])
        .map_err(|err| format!("Hex decode error: {:?}", err))?;
    Ok(CompressedRistrettoPublic::from(&key_bytes))
}

#[derive(Clone, StructOpt)]
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
        #[structopt(long, short = "k", parse(try_from_str=parse_ristretto_hex))]
        key: CompressedRistrettoPublic,
    },

    /// Gets the list of reported missed block ranges.
    GetMissedBlockRanges,

    /// Retrieves a private key from a remote ingest enclave and sets it as
    /// the current enclaves's private key.
    SyncKeysFromRemote { peer_uri: String },

    ///  Retrieves the ingress public keys for the entire system (as opposed to
    ///  those of a single IngestServer) and filters according to the provided
    ///  parameters.
    GetIngressPublicKeyRecords {
        /// Ingress keys are "started" at certain blocks. Only ingress keys that
        /// are "started"  at this block index will be included in the response.
        #[structopt(default_value, short = "s", long = "start-block-at-least")]
        start_block_at_least: u64,
        /// If true the response will include ingress keys that have been lost.
        #[structopt(short = "l", long = "include-lost")]
        should_include_lost_keys: bool,
        /// If true the response will include ingress keys that have been
        /// retired.
        #[structopt(short = "r", long = "include-retired")]
        should_include_retired_keys: bool,
    },
}
