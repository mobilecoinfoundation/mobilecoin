// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Configuration parameters for the MobileCoin Fog View Node
#![deny(missing_docs)]
use crate::sharding_strategy::EpochShardingStrategy;
use clap::Parser;
use mc_common::ResponderId;
use mc_fog_sql_recovery_db::SqlRecoveryDbConnectionConfig;
use mc_fog_uri::{FogViewRouterUri, FogViewStoreUri, FogViewUri};
use mc_util_parse::{parse_duration_in_millis, parse_duration_in_seconds};
use mc_util_uri::AdminUri;
use serde::Serialize;
use std::{str::FromStr, time::Duration};

/// Configuration parameters for the MobileCoin Fog View Node
#[derive(Clone, Parser, Serialize)]
#[clap(version)]
pub struct MobileAcctViewConfig {
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
    pub client_listen_uri: FogViewStoreUri,

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

    /// Postgres config
    #[clap(flatten)]
    pub postgres_config: SqlRecoveryDbConnectionConfig,

    /// How many blocks to request at once when requesting blocks from postgres
    /// Increasing this may help if there is high network latency with postgres,
    /// and should not much harm performance otherwise when loading the DB.
    #[clap(long, default_value = "1000", env = "MC_BLOCK_QUERY_BATCH_SIZE")]
    pub block_query_batch_size: usize,

    /// Database polling interval in ms.
    #[clap(long, default_value = "250", value_parser = parse_duration_in_millis, env = "MC_DB_POLLING_INTERVAL_MS")]
    pub db_polling_interval_ms: Duration,

    /// Determines which group of TxOuts the Fog View Store instance will
    /// process.
    #[clap(long, default_value = "default", env = "MC_SHARDING_STRATEGY")]
    pub sharding_strategy: ShardingStrategy,
}

/// Determines which group of TxOuts the Fog View Store instance will process.
#[derive(Clone, Serialize)]
pub enum ShardingStrategy {
    /// URI used by the FogViewServer when fulfilling direct client requests.
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

/// Configuration parameters for the Fog View Router.
#[derive(Clone, Parser, Serialize)]
#[clap(version)]
pub struct FogViewRouterConfig {
    /// The ID with which to respond to client attestation requests.
    ///
    /// This ID needs to match the host:port clients use in their URI when
    /// referencing this node.
    #[clap(long, env = "MC_CLIENT_RESPONDER_ID")]
    pub client_responder_id: ResponderId,

    /// gRPC listening URI for client requests.
    #[clap(long, env = "MC_CLIENT_LISTEN_URI")]
    pub client_listen_uri: RouterClientListenUri,

    /// gRPC listening URI for Fog View Stores. Should be indexed the same as
    /// the `sharding_strategies` field.
    #[clap(long, use_value_delimiter = true, env = "MC_VIEW_SHARD_URIS")]
    pub shard_uris: Vec<FogViewStoreUri>,

    /// Router admin listening URI.
    #[clap(long, env = "MC_ADMIN_LISTEN_URI")]
    pub admin_listen_uri: AdminUri,

    /// The chain id of the network we are a part of
    #[clap(long, env = "MC_CHAIN_ID")]
    pub chain_id: String,

    /// Enables authenticating client requests using Authorization tokens using
    /// the provided hex-encoded 32 bytes shared secret.
    #[clap(long, value_parser = mc_util_parse::parse_hex::<[u8; 32]>, env = "MC_CLIENT_AUTH_TOKEN_SECRET")]
    pub client_auth_token_secret: Option<[u8; 32]>,

    /// Maximal client authentication token lifetime, in seconds (only relevant
    /// when --client-auth-token-secret is used. Defaults to 86400 - 24
    /// hours).
    #[clap(long, default_value = "86400", value_parser = parse_duration_in_seconds, env = "MC_CLIENT_AUTH_TOKEN_MAX_LIFETIME")]
    pub client_auth_token_max_lifetime: Duration,
}

/// A FogViewRouterServer can either fulfill streaming or unary requests, and
/// these different modes require different URIs.
#[derive(Clone, Serialize)]
pub enum RouterClientListenUri {
    /// URI used by the FogViewRouterAPI service.
    Streaming(FogViewRouterUri),
    /// URI used by the FogViewAPI service.
    Unary(FogViewUri),
}

impl FromStr for RouterClientListenUri {
    type Err = String;
    fn from_str(input: &str) -> Result<Self, String> {
        if let Ok(fog_view_uri) = FogViewUri::from_str(input) {
            return Ok(RouterClientListenUri::Unary(fog_view_uri));
        }
        if let Ok(fog_view_router_uri) = FogViewRouterUri::from_str(input) {
            return Ok(RouterClientListenUri::Streaming(fog_view_router_uri));
        }

        Err(format!("Incorrect ClientListenUri string: {input}."))
    }
}
