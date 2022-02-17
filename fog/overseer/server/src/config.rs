// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Configuration parameters for Fog Overseer.

use mc_fog_sql_recovery_db::SqlRecoveryDbConnectionConfig;
use mc_fog_uri::FogIngestUri;
use serde::Serialize;
use structopt::StructOpt;

/// StructOpt configuration options for an Overseer Server
#[derive(Clone, Serialize, StructOpt)]
pub struct OverseerConfig {
    /// Host that the Overseer server listens on.
    #[structopt(long, env, default_value = "127.0.0.1")]
    pub overseer_listen_host: String,

    /// Port to start the Overseer webserver on.
    #[structopt(long, env, default_value = "9090")]
    pub overseer_listen_port: u16,

    /// gRPC listening URIs for client requests.
    #[structopt(long, env, use_delimiter = true)]
    pub ingest_cluster_uris: Vec<FogIngestUri>,

    /// Postgres config
    #[structopt(flatten)]
    pub postgres_config: SqlRecoveryDbConnectionConfig,
}

#[cfg(test)]
mod tests {
    use super::*;
    use mc_fog_uri::ConnectionUri;
    #[test]
    fn ingest_server_config_example() {
        let config = OverseerConfig::from_iter_safe(&[
            "/usr/bin/fog_overseer_server",
            "--overseer-listen-host",
            "www.mycoolhost.com",
            "--overseer-listen-port",
            "8080",
            "--ingest-cluster-uris",
            "insecure-fog-ingest://0.0.0.0:3226/,insecure-fog-ingest://0.0.0.0:3227/",
        ])
        .expect("Could not parse command line arguments.");

        assert_eq!(config.ingest_cluster_uris.len(), 2);

        assert_eq!(config.ingest_cluster_uris[0].port(), 3226);
        assert_eq!(config.ingest_cluster_uris[1].port(), 3227);
    }
}
