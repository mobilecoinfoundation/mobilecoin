// Copyright (c) 2018-2021 The MobileCoin Foundation

//! Configuration parameters for the Fog Ingest Node

use mc_attest_core::ProviderId;
use mc_common::ResponderId;
use mc_fog_uri::{FogIngestUri, IngestPeerUri};
use mc_util_uri::AdminUri;
use serde::Serialize;
use std::{path::PathBuf, str::FromStr, time::Duration};
use structopt::StructOpt;

/// StructOpt configuration options for an Ingest Server
#[derive(Clone, Serialize, StructOpt)]
pub struct IngestConfig {
    /// The IAS SPID to use when getting a quote
    #[structopt(long)]
    pub ias_spid: ProviderId,

    /// PEM-formatted keypair to send with an Attestation Request.
    #[structopt(long)]
    pub ias_api_key: String,

    /// Path to watcher db (lmdb) - includes block timestamps
    #[structopt(long)]
    pub watcher_db: PathBuf,

    /// Local Ingest Node ID
    #[structopt(long)]
    pub local_node_id: ResponderId,

    /// gRPC listening URI for client requests.
    #[structopt(long)]
    pub client_listen_uri: FogIngestUri,

    /// gRPC listening URI for peer requests.
    #[structopt(long)]
    pub peer_listen_uri: IngestPeerUri,

    /// List of all peers in this cluster
    #[structopt(long, use_delimiter = true)]
    pub peers: Vec<IngestPeerUri>,

    /// Path to ledger db (lmdb), used for ingest in a polling fashion
    #[structopt(long)]
    pub ledger_db: PathBuf,

    /// report_id associated the reports produced by this ingest service.
    /// This should match what appears in users' public addresses.
    /// Defaults to empty string.
    #[structopt(long, default_value = "")]
    pub fog_report_id: String,

    /// Capacity of table for user rng's.
    /// Must be a power of two at time of writing.
    ///
    /// One entry is added to this table with every transaction.
    /// When the table overflows, egress key rotation will occur and the table
    /// will be flushed. This will cause all users to get a new RNG and have
    /// some extra traffic at fog-view servers.
    ///
    /// This determines the memory utilization / storage requirement of the
    /// server.
    #[structopt(long, default_value = "262144")]
    pub user_capacity: u64,

    /// Max number of transactions ingest can eat at one time.  This is mostly
    /// determined by SGX memory allocation limits, so it must be configurable
    #[structopt(long, default_value = "100000")]
    pub max_transactions: usize,

    /// The amount we add to current block height to compute pubkey_expiry in
    /// reports
    #[structopt(long, default_value = "100")]
    pub pubkey_expiry_window: u64,

    /// How often the active server checks up on each of the peer backups
    /// Defaults to once a minute
    #[structopt(long, default_value = "60", parse(try_from_str=parse_duration_in_seconds))]
    pub peer_checkup_period: Duration,

    /// The amount of time we wait for the watcher db to catchup if it falls
    /// behind If this timeout is exceeded then the ETxOut's will have no
    /// timestamp
    #[structopt(long, default_value = "5", parse(try_from_str=parse_duration_in_seconds))]
    pub watcher_timeout: Duration,

    /// Optional admin listening URI.
    #[structopt(long)]
    pub admin_listen_uri: Option<AdminUri>,

    /// State file, defaults to ~/.mc-fog-ingest-state
    #[structopt(long)]
    pub state_file: Option<PathBuf>,
}

/// Converts a string containing number of seconds to a Duration object.
fn parse_duration_in_seconds(src: &str) -> Result<Duration, std::num::ParseIntError> {
    Ok(Duration::from_secs(u64::from_str(src)?))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn ingest_server_config_example() {
        let config = IngestConfig::from_iter_safe(
         &["/usr/bin/fog_ingest_server",
      "--ledger-db", "/fog-data/ledger",
      "--watcher-db", "/fog-data/watcher",
     "--ias-spid", "00000000000000000000000000000000", "--ias-api-key", "00000000000000000000000000000000",
      "--client-listen-uri", "insecure-fog-ingest://0.0.0.0:3226/",
      "--peer-listen-uri", "insecure-igp://0.0.0.0:8090/",
      "--local-node-id", "fogingest2.buildtest.svc.cluster.local:443",
      "--peers", "insecure-igp://fogingest1.buildtest.svc.cluster.local:443,insecure-igp://fogingest2.buildtest.svc.cluster.local:443",
      "--state-file", "/foo/bar",
      "--admin-listen-uri", "insecure-mca://127.0.0.1:8003/",
      "--pubkey-expiry-window", "100"]).expect("Could not parse command line arguments");
        assert_eq!(config.peers.len(), 2);
    }
}
