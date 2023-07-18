// Copyright (c) 2018-2023 The MobileCoin Foundation
#![deny(missing_docs)]

//! Config parameters for the binary target

use clap::Parser;
use mc_blockchain_types::BlockIndex;
use mc_util_uri::AdminUri;
use serde::Serialize;
use std::path::PathBuf;

/// Configuration parameters for light client relayer
#[derive(Debug, Parser, Serialize)]
#[clap(
    name = "mc-light-client-relayer",
    about = "A process which scans the blockchain and forwards blocks matching some criteria, and block metadata signatures to a remote party"
)]
pub struct Config {
    /// Path to ledger db (lmdb).
    #[clap(long, default_value = "/tmp/ledgerdb", env = "MC_LEDGER_DB")]
    pub ledger_db: PathBuf,

    /// Path to watcher db (lmdb).
    #[clap(long, env = "MC_WATCHER_DB")]
    pub watcher_db: PathBuf,

    /// Optional admin listening URI.
    #[clap(long, env = "MC_ADMIN_LISTEN_URI")]
    pub admin_listen_uri: Option<AdminUri>,

    /// Block index to start working at.
    // Note that targets of the relayer generally are expected to tolerate replays of old messages,
    // and the relayer is supposed to be trustless.
    #[clap(long, default_value = "1", env = "MC_START_BLOCK_INDEX")]
    pub start_block_index: BlockIndex,

    /// The minimum number of signatures a block must have for the relayer to
    /// forward it
    // Note, we could alternatively have a quorum set config here, or a light-client verifier
    // config.
    #[clap(long, env = "MC_MIN_SIGNATURES")]
    pub min_signatures: u32,
    // TODO: Remote API?
}
