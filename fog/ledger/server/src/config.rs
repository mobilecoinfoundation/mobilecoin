// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Configuration parameters for the ledger server

#![deny(missing_docs)]

use crate::sharding_strategy::EpochShardingStrategy;
use clap::Parser;
use mc_attest_core::ProviderId;
use mc_common::ResponderId;
use mc_fog_uri::{FogLedgerUri, KeyImageStoreUri};
use mc_util_parse::parse_duration_in_seconds;
use mc_util_uri::AdminUri;
use serde::Serialize;
use std::{path::PathBuf, str::FromStr, time::Duration};

/// Configuration parameters for the ledger server
#[derive(Clone, Parser, Serialize)]
#[clap(version)]
pub struct LedgerServerConfig {
    /// The chain id of the network we are a part of
    #[clap(long, env = "MC_CHAIN_ID")]
    pub chain_id: String,

    /// gRPC listening URI for client requests.
    #[clap(long, env = "MC_CLIENT_LISTEN_URI")]
    pub client_listen_uri: FogLedgerUri,

    /// Path to ledger db (lmdb)
    #[clap(long, env = "MC_LEDGER_DB")]
    pub ledger_db: PathBuf,

    /// Path to watcher db (lmdb) - includes block timestamps
    #[clap(long, env = "MC_WATCHER_DB")]
    pub watcher_db: PathBuf,

    /// Client Responder id.
    ///
    /// This ID needs to match the host:port clients use in their URI when
    /// referencing this node.
    #[clap(long, env = "MC_CLIENT_RESPONDER_ID")]
    pub client_responder_id: ResponderId,

    /// IAS Api Key.
    #[clap(long, env = "MC_IAS_API_KEY")]
    pub ias_api_key: String,

    /// IAS Service Provider ID.
    #[clap(long, env = "MC_IAS_SPID")]
    pub ias_spid: ProviderId,

    /// Optional admin listening URI.
    #[clap(long, env = "MC_ADMIN_LISTEN_URI")]
    pub admin_listen_uri: Option<AdminUri>,

    /// Enables authenticating client requests using Authorization tokens using
    /// the provided hex-encoded 32 bytes shared secret.
    #[clap(long, value_parser = mc_util_parse::parse_hex::<[u8; 32]>, env = "MC_CLIENT_AUTH_TOKEN_SECRET")]
    pub client_auth_token_secret: Option<[u8; 32]>,

    /// Maximal client authentication token lifetime, in seconds (only relevant
    /// when --client-auth-token-secret is used. Defaults to 86400 - 24
    /// hours).
    #[clap(long, default_value = "86400", value_parser = parse_duration_in_seconds, env = "MC_CLIENT_AUTH_TOKEN_MAX_LIFETIME")]
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
    /// to disk by linux kernel.
    #[clap(long, default_value = "1048576", env = "MC_OMAP_CAPACITY")]
    pub omap_capacity: u64,
}

/// Configuration parameters for the Fog Ledger Router service.
#[derive(Clone, Parser, Serialize)]
#[clap(version)]
pub struct LedgerRouterConfig {
    /// The chain id of the network we are a part of
    #[clap(long, env = "MC_CHAIN_ID")]
    pub chain_id: String,

    /// The ID with which to respond to client attestation requests.
    ///
    /// This ID needs to match the host:port clients use in their URI when
    /// referencing this node.
    #[clap(long, env = "MC_CLIENT_RESPONDER_ID")]
    pub client_responder_id: ResponderId,

    /// gRPC listening URI for client requests.
    #[clap(long, env = "MC_CLIENT_LISTEN_URI")]
    pub client_listen_uri: FogLedgerUri,

    /// Router admin listening URI.
    #[clap(long, env = "MC_ADMIN_LISTEN_URI")]
    pub admin_listen_uri: AdminUri,

    /// Number of query attempts with no forward progress
    /// before reporting an error.
    #[clap(long, default_value = "3")]
    pub query_retries: usize,

    /// Enables authenticating client requests using Authorization tokens using
    /// the provided hex-encoded 32 bytes shared secret.
    #[clap(long, value_parser = mc_util_parse::parse_hex::<[u8; 32]>, env = "MC_CLIENT_AUTH_TOKEN_SECRET")]
    pub client_auth_token_secret: Option<[u8; 32]>,

    /// Maximal client authentication token lifetime, in seconds (only relevant
    /// when --client-auth-token-secret is used. Defaults to 86400 - 24
    /// hours).
    #[clap(long, default_value = "86400", value_parser = parse_duration_in_seconds, env = "MC_CLIENT_AUTH_TOKEN_MAX_LIFETIME")]
    pub client_auth_token_max_lifetime: Duration,

    /// Path to ledger db (lmdb)
    #[clap(long, env = "MC_LEDGER_DB")]
    pub ledger_db: PathBuf,

    // TODO: Add store instance uris which are of type Vec<FogLedgerStoreUri>.
    /// The capacity to build the OMAP (ORAM hash table) with.
    /// About 75% of this capacity can be used.
    /// The hash table will overflow when there are more TxOut's than this,
    /// and the server will have to be restarted with a larger number.
    ///
    /// Note: At time of writing, the hash table will be allocated to use all
    /// available SGX EPC memory, and then beyond that it will be allocated on
    /// the heap in the untrusted side. Once the needed capacity exceeds RAM,
    /// you will either get killed by OOM killer, or it will start being swapped
    /// to disk by linux kernel.
    #[clap(long, default_value = "1048576", env = "MC_OMAP_CAPACITY")]
    pub omap_capacity: u64,
}

/// Configuration parameters for the Fog Ledger Store service.
#[derive(Clone, Parser, Serialize)]
#[clap(version)]
pub struct LedgerStoreConfig {
    /// The chain id of the network we are a part of
    #[clap(long, env = "MC_CHAIN_ID")]
    pub chain_id: String,

    /// The ID with which to respond to client attestation requests.
    ///
    /// This ID needs to match the host:port clients use in their URI when
    /// referencing this node.
    #[clap(long, env = "MC_CLIENT_RESPONDER_ID")]
    pub client_responder_id: ResponderId,

    /// gRPC listening URI for client requests.
    #[clap(long, env = "MC_CLIENT_LISTEN_URI")]
    pub client_listen_uri: KeyImageStoreUri,

    /// Path to ledger db (lmdb)
    #[clap(long, value_parser(clap::value_parser!(PathBuf)), env = "MC_LEDGER_DB")]
    pub ledger_db: PathBuf,

    /// Path to watcher db (lmdb) - includes block timestamps
    #[clap(long, value_parser(clap::value_parser!(PathBuf)), env = "MC_WATCHER_DB")]
    pub watcher_db: PathBuf,

    /// IAS Api Key.
    #[clap(long, env = "MC_IAS_API_KEY")]
    pub ias_api_key: String,

    /// IAS Service Provider ID.
    #[clap(long, env = "MC_IAS_SPID")]
    pub ias_spid: ProviderId,

    /// Optional admin listening URI.
    #[clap(long, env = "MC_ADMIN_LISTEN_URI")]
    pub admin_listen_uri: Option<AdminUri>,

    /// Enables authenticating client requests using Authorization tokens using
    /// the provided hex-encoded 32 bytes shared secret.
    #[clap(long, value_parser = mc_util_parse::parse_hex::<[u8; 32]>, env = "MC_CLIENT_AUTH_TOKEN_SECRET")]
    pub client_auth_token_secret: Option<[u8; 32]>,

    /// Maximal client authentication token lifetime, in seconds (only relevant
    /// when --client-auth-token-secret is used. Defaults to 86400 - 24
    /// hours).
    #[clap(long, default_value = "86400", value_parser = parse_duration_in_seconds, env = "MC_CLIENT_AUTH_TOKEN_MAX_LIFETIME")]
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
    /// to disk by linux kernel.
    #[clap(long, default_value = "1048576", env = "MC_OMAP_CAPACITY")]
    pub omap_capacity: u64,

    /// Determines which group of Key Images the Key Image Store instance will
    /// process.
    #[clap(long, default_value = "default")]
    pub sharding_strategy: ShardingStrategy,
}

/// Enum for parsing strategy from command line w/ clap
#[derive(Clone, Serialize)]
pub enum ShardingStrategy {
    /// Epoch strategy (continuous block range)
    Epoch(EpochShardingStrategy),
}

impl FromStr for ShardingStrategy {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.eq("default") {
            return Ok(ShardingStrategy::Epoch(EpochShardingStrategy::default()));
        }
        if let Ok(epoch_sharding_strategy) = EpochShardingStrategy::from_str(s) {
            return Ok(ShardingStrategy::Epoch(epoch_sharding_strategy));
        }

        Err("Invalid sharding strategy config.".to_string())
    }
}

/// Uri for any node in the key image store system.
/// Old-style single-node servers and routers are both referred to with
/// a KeyImageClientListenUri::ClientFacing(FogLedgerUri), whereas ledger
/// store shard Uris will be KeyImageClientListenUri::Store(KeyImageStoreUri).
#[derive(Clone, Serialize)]
pub enum KeyImageClientListenUri {
    /// URI used by the KeyImageStoreServer when fulfilling direct client
    /// requests.
    ClientFacing(FogLedgerUri),
    /// URI used by the KeyImageStoreServer when fulfilling Fog Ledger Router
    /// requests.
    Store(KeyImageStoreUri),
}
