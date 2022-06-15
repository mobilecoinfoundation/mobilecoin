// Copyright (c) 2018-2022 The MobileCoin Foundation
#![deny(missing_docs)]

//! Configuration parameters for the Fog Ingest Node

use clap::Parser;
use mc_attest_core::ProviderId;
use mc_common::ResponderId;
use mc_fog_sql_recovery_db::SqlRecoveryDbConnectionConfig;
use mc_fog_uri::{FogIngestUri, IngestPeerUri};
use mc_util_parse::parse_duration_in_seconds;
use mc_util_uri::AdminUri;
use serde::Serialize;
use std::{path::PathBuf, time::Duration};

/// Command-line configuration options for an Ingest Server
#[derive(Clone, Serialize, Parser)]
#[clap(version)]
pub struct IngestConfig {
    /// The IAS SPID to use when getting a quote
    #[clap(long, env = "MC_IAS_SPID")]
    pub ias_spid: ProviderId,

    /// PEM-formatted keypair to send with an Attestation Request.
    #[clap(long, env = "MC_IAS_API_KEY")]
    pub ias_api_key: String,

    /// Local Ingest Node ID
    #[clap(long, env = "MC_LOCAL_NODE_ID")]
    pub local_node_id: ResponderId,

    /// gRPC listening URI for client requests.
    #[clap(long, env = "MC_CLIENT_LISTEN_URI")]
    pub client_listen_uri: FogIngestUri,

    /// gRPC listening URI for peer requests.
    #[clap(long, env = "MC_PEER_LISTEN_URI")]
    pub peer_listen_uri: IngestPeerUri,

    /// List of all peers in this cluster
    /// Sample usages:
    ///     --peers mc://foo:123 --peers mc://bar:456
    ///     --peers mc://foo:123,mc://bar:456
    ///     env MC_PEERS=mc://foo:123,mc://bar:456

    #[clap(long, use_value_delimiter = true, env = "MC_PEERS")]
    pub peers: Vec<IngestPeerUri>,

    /// Path to ledger db (lmdb), used for ingest in a polling fashion
    #[clap(long, env = "MC_LEDGER_DB")]
    pub ledger_db: PathBuf,

    /// report_id associated the reports produced by this ingest service.
    /// This should match what appears in users' public addresses.
    /// Defaults to empty string.
    #[clap(long, default_value = "", env = "MC_FOG_REPORT_ID")]
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
    #[clap(long, default_value = "262144", env = "MC_USER_CAPACITY")]
    pub user_capacity: u64,

    /// Max number of transactions ingest can eat at one time.  This is mostly
    /// determined by SGX memory allocation limits, so it must be configurable
    #[clap(long, default_value = "100000", env = "MC_MAX_TRANSACTIONS")]
    pub max_transactions: usize,

    /// The amount we add to current block height to compute pubkey_expiry in
    /// reports
    #[clap(long, default_value = "100", env = "MC_PUBKEY_EXPIRY_WINDOW")]
    pub pubkey_expiry_window: u64,

    /// How often the active server checks up on each of the peer backups
    /// Defaults to once a minute
    #[clap(long, default_value = "60", parse(try_from_str = parse_duration_in_seconds), env = "MC_PEER_CHECKUP_PERIOD")]
    pub peer_checkup_period: Duration,

    /// Optional admin listening URI.
    #[clap(long, env = "MC_ADMIN_LISTEN_URI")]
    pub admin_listen_uri: Option<AdminUri>,

    /// State file, defaults to ~/.mc-fog-ingest-state
    #[clap(long, env = "MC_STATE_FILE")]
    pub state_file: Option<PathBuf>,

    /// Postgres config
    #[clap(flatten)]
    pub postgres_config: SqlRecoveryDbConnectionConfig,
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn ingest_server_config_example() {
        let config = IngestConfig::try_parse_from(
         &["/usr/bin/fog_ingest_server",
      "--ledger-db", "/fog-data/ledger",
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
