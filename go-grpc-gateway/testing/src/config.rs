// Copyright (c) 2018-2022 The MobileCoin Foundation

use clap::Parser;
use mc_util_uri::FogUri;
use serde::Serialize;

/// Configuration options for the stub server
#[derive(Clone, Debug, Parser, Serialize)]
#[clap(name = "stub-server", about = "Stub which implements fog grpc apis.")]
pub struct Config {
    /// gRPC listening URI for client requests.
    #[clap(long, env = "MC_CLIENT_LISTEN_URI")]
    pub client_listen_uri: FogUri,
}
