// Copyright (c) 2018-2023 The MobileCoin Foundation

//! Configuration parameters for the light-client verifier server

use clap::Parser;
use light_client_api::LightClientUri;

/// Command-line configuration options for the light-client verifier server
#[derive(Parser)]
#[clap(version)]
pub struct VerifierConfig {
    /// gRPC listening URI for client requests.
    #[clap(long, env = "MC_CLIENT_LISTEN_URI")]
    pub client_listen_uri: LightClientUri,
}
