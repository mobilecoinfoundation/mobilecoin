// Copyright (c) 2018-2021 The MobileCoin Foundation

//! Configuration parameters for the ledger server

use mc_attest_core::ProviderId;
use mc_common::ResponderId;
use mc_fog_uri::FogLedgerUri;
use mc_util_uri::AdminUri;
use serde::Serialize;
use std::{path::PathBuf, str::FromStr, time::Duration};
use structopt::StructOpt;

#[derive(Clone, Serialize, StructOpt)]
pub struct LedgerServerConfig {
    /// gRPC listening URI for client requests.
    #[structopt(long)]
    pub client_listen_uri: FogLedgerUri,

    /// Path to ledger db (lmdb)
    #[structopt(long, parse(from_os_str))]
    pub ledger_db: PathBuf,

    /// Path to watcher db (lmdb) - includes block timestamps
    #[structopt(long, parse(from_os_str))]
    pub watcher_db: PathBuf,

    /// Client Responder id.
    ///
    /// This ID needs to match the host:port clients use in their URI when
    /// referencing this node.
    #[structopt(long)]
    pub client_responder_id: ResponderId,

    /// IAS Api Key.
    #[structopt(long)]
    pub ias_api_key: String,

    /// IAS Service Provider ID.
    #[structopt(long)]
    pub ias_spid: ProviderId,

    /// Optional admin listening URI.
    #[structopt(long)]
    pub admin_listen_uri: Option<AdminUri>,

    /// Enables authenticating client requests using Authorization tokens using
    /// the provided hex-encoded 32 bytes shared secret.
    #[structopt(long, parse(try_from_str=hex::FromHex::from_hex))]
    pub client_auth_token_secret: Option<[u8; 32]>,

    /// Maximal client authentication token lifetime, in seconds (only relevant
    /// when --client-auth-token-secret is used. Defaults to 86400 - 24
    /// hours).
    #[structopt(long, default_value = "86400", parse(try_from_str=parse_duration_in_seconds))]
    pub client_auth_token_max_lifetime: Duration,

    /// The capacity to build the OMAP (ORAM hash table) with.
    /// About 75% of this capacity can be used.
    /// The hash table will overflow when there are more Keyimages than this,
    /// and the server will have to be restarted with a larger number.
    ///
    /// Note: At time of writing, the hash table will be allocated to use all
    /// available SGX EPC memory, and then beyond that it will be allocated on
    /// the heap in the untrusted side. Once the needed capacity exceeds RAM,
    /// you will either get killed by OOM killer, or it will start being swapped
    /// to disk by linux kernel. (Unless / until a kernel-bypass pathway is
    /// developed.)
    #[structopt(long, default_value = "1048576")]
    pub omap_capacity: u64,
}

/// Converts a string containing number of seconds to a Duration object.
fn parse_duration_in_seconds(src: &str) -> Result<Duration, std::num::ParseIntError> {
    Ok(Duration::from_secs(u64::from_str(src)?))
}
