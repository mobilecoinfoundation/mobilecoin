use mc_util_uri::FogUri;
use serde::Serialize;
use structopt::StructOpt;

/// Configuration options for the stub server
#[derive(Clone, Debug, StructOpt, Serialize)]
#[structopt(name = "stub-server", about = "Stub which implements fog grpc apis.")]
pub struct Config {
    /// gRPC listening URI for client requests.
    #[structopt(long)]
    pub client_listen_uri: FogUri,
}
