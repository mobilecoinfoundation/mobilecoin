// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Configuration parameters for Fog Overseer.
#![deny(missing_docs)]

use clap::Parser;
use mc_fog_sql_recovery_db::SqlRecoveryDbConnectionConfig;
use mc_fog_uri::FogIngestUri;
use serde::Serialize;

/// Parser configuration options for an Overseer Server
#[derive(Clone, Serialize, Parser)]
pub struct OverseerConfig {
    /// Host to listen on.
    #[clap(long, default_value = "127.0.0.1", env = "MC_OVERSEER_LISTEN_HOST")]
    pub overseer_listen_host: String,

    /// Port to start webserver on.
    #[clap(long, default_value = "9090", env = "MC_OVERSEER_LISTEN_PORT")]
    pub overseer_listen_port: u16,

    /// TODO: Make this an environment variable that can be dynamically
    /// refreshed. This will allow ops to have one Fog Overseer instance that
    /// can look at the new Fog Ingest cluster during the blue / green
    /// deployment.
    ///
    /// gRPC listening URIs for client requests.
    #[clap(long, use_value_delimiter = true, env = "MC_INGEST_CLUSTER_URIS")]
    pub ingest_cluster_uris: Vec<FogIngestUri>,

    /// Postgres config
    #[clap(flatten)]
    pub postgres_config: SqlRecoveryDbConnectionConfig,
}

#[cfg(test)]
mod tests {
    use super::*;
    use mc_fog_uri::ConnectionUri;
    #[test]
    fn ingest_server_config_example() {
        let config = OverseerConfig::try_parse_from(&[
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
