// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Configuration parameters for Fog Overseer.

use mc_fog_sql_recovery_db::SqlRecoveryDbConnectionConfig;
use mc_fog_uri::FogIngestUri;
use serde::Serialize;
use structopt::StructOpt;

/// StructOpt configuration options for an Overseer Server
#[derive(Clone, Serialize, StructOpt)]
pub struct OverseerConfig {
    /// Host to listen on.
    #[structopt(long, default_value = "127.0.0.1")]
    pub listen_host: String,

    /// Port to start webserver on.
    #[structopt(long, default_value = "9090")]
    pub listen_port: u16,

    /// TODO: Make this an environment variable that can be dynamically
    /// refreshed. This will allow ops to have one Fog Overseer instance that
    /// can look at the new Fog Ingest cluster during the blue / green
    /// deployment.
    ///
    /// gRPC listening URIs for client requests.
    #[structopt(long, use_delimiter = true)]
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
            "/usr/bin/start_overseer_server",
            "--listen-host",
            "www.mycoolhost.com",
            "--listen-port",
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
