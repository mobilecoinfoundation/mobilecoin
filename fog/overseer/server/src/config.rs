// Copyright (c) 2018-2021 The MobileCoin Foundation
use mc_common::ResponderId;
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

    /// Local Ingest Node ID
    #[structopt(long)]
    pub local_overseer_node_id: ResponderId,

    /// gRPC listening URI for client requests.
    #[structopt(long, use_delimiter = true)]
    pub ingest_cluster_uris: Vec<FogIngestUri>,

    /// Postgres config
    #[structopt(flatten)]
    pub postgres_config: SqlRecoveryDbConnectionConfig,
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn ingest_server_config_example() {
        let config = OverseerConfig::from_iter_safe(&[
            "/usr/bin/start_overseer_server",
            "--listen-host",
            "www.mycoolhost.com",
            "--listen-port",
            "8080",
            "--local-overseer-node-id",
            "fogoverseer.svc.cluster.local:443",
            "--ingest-cluster-uris",
            "insecure-fog-ingest://0.0.0.0.3226/,insecure-fog-ingest://0.0.0.0.3227/",
        ])
        .expect("Could not parse command line arguments.");

        assert_eq!(config.ingest_cluster_uris.len(), 2);
    }
}
