// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Configuration parameters for the MobileCoin Fog View Node
#![deny(missing_docs)]

use clap::Parser;
use mc_attest_core::ProviderId;
use mc_common::ResponderId;
use mc_fog_sql_recovery_db::SqlRecoveryDbConnectionConfig;
use mc_fog_uri::FogViewUri;
use mc_util_parse::parse_duration_in_seconds;
use mc_util_uri::AdminUri;
use serde::Serialize;
use std::time::Duration;

/// Configuration parameters for the MobileCoin Fog View Node
#[derive(Clone, Parser, Serialize)]
#[clap(version)]
pub struct MobileAcctViewConfig {
    /// The network id of the network we are a part of
    #[clap(long, env = "MC_NETWORK_ID")]
    pub network_id: String,

    /// The ID with which to respond to client attestation requests.
    ///
    /// This ID needs to match the host:port clients use in their URI when
    /// referencing this node.
    #[clap(long, env = "MC_CLIENT_RESPONDER_ID")]
    pub client_responder_id: ResponderId,

    /// PEM-formatted keypair to send with an Attestation Request.
    #[clap(long, env = "MC_IAS_API_KEY")]
    pub ias_api_key: String,

    /// The IAS SPID to use when getting a quote
    #[clap(long, env = "MC_IAS_SPID")]
    pub ias_spid: ProviderId,

    /// gRPC listening URI for client requests.
    #[clap(long, env = "MC_CLIENT_LISTEN_URI")]
    pub client_listen_uri: FogViewUri,

    /// Optional admin listening URI.
    #[clap(long, env = "MC_ADMIN_LISTEN_URI")]
    pub admin_listen_uri: Option<AdminUri>,

    /// Enables authenticating client requests using Authorization tokens using
    /// the provided hex-encoded 32 bytes shared secret.
    #[clap(long, parse(try_from_str = hex::FromHex::from_hex), env = "MC_CLIENT_AUTH_TOKEN_SECRET")]
    pub client_auth_token_secret: Option<[u8; 32]>,

    /// Maximal client authentication token lifetime, in seconds (only relevant
    /// when --client-auth-token-secret is used. Defaults to 86400 - 24
    /// hours).
    #[clap(long, default_value = "86400", parse(try_from_str = parse_duration_in_seconds), env = "MC_CLIENT_AUTH_TOKEN_MAX_LIFETIME")]
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
}
