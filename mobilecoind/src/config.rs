// Copyright (c) 2018-2020 MobileCoin Inc.

//! Configuration parameters for mobilecoind

use mc_attest_core::Measurement;
use mc_common::{logger::Logger, ResponderId};
use mc_connection::{ConnectionManager, ThickClient};
use mc_consensus_scp::QuorumSet;
use mc_mobilecoind_api::MobilecoindUri;
use mc_util_uri::{ConnectionUri, ConsensusClientUri};
use std::{path::PathBuf, str::FromStr, sync::Arc, time::Duration};
use structopt::StructOpt;

#[derive(Debug, StructOpt)]
#[structopt(name = "mobilecoind", about = "The MobileCoin client daemon.")]
pub struct Config {
    /// Path to ledger db (lmdb).
    #[structopt(long, default_value = "/tmp/ledgerdb", parse(from_os_str))]
    pub ledger_db: PathBuf,

    /// Path to existing ledger db that contains the origin block, used when initializing new ledger dbs.
    #[structopt(long)]
    pub ledger_db_bootstrap: Option<String>,

    /// Path to watcher db (lmdb).
    #[structopt(long, parse(from_os_str))]
    pub watcher_db: Option<PathBuf>,

    #[structopt(flatten)]
    pub peers_config: PeersConfig,

    /// Quorum set for ledger syncing. By default, the quorum set would include all peers.
    ///
    /// The quorum set is represented in JSON. For example:
    /// {"threshold":1,"members":[{"type":"Node","args":"node2.test.mobilecoin.com:443"},{"type":"Node","args":"node3.test.mobilecoin.com:443"}]}
    #[structopt(long, parse(try_from_str=parse_quorum_set_from_json))]
    quorum_set: Option<QuorumSet<ResponderId>>,

    /// URLs to use for transaction data.
    ///
    /// For example: https://s3-us-west-1.amazonaws.com/mobilecoin.chain/node1.test.mobilecoin.com/
    #[structopt(long = "tx-source-url", required = true, min_values = 1)]
    pub tx_source_urls: Vec<String>,

    /// How many seconds to wait between polling.
    #[structopt(long, default_value = "5", parse(try_from_str=parse_duration_in_seconds))]
    pub poll_interval: Duration,

    // Mobilecoind specific arguments
    /// Path to mobilecoind database used to store transactions and accounts.
    #[structopt(long, parse(from_os_str))]
    pub mobilecoind_db: Option<PathBuf>,

    /// URI to listen on and serve requests from.
    #[structopt(long)]
    pub listen_uri: Option<MobilecoindUri>,

    /// Number of worker threads to use for view key scanning.
    /// Defaults to number of logical CPU cores.
    #[structopt(long)]
    pub num_workers: Option<usize>,
}

fn parse_duration_in_seconds(src: &str) -> Result<Duration, std::num::ParseIntError> {
    Ok(Duration::from_secs(u64::from_str(src)?))
}

fn parse_quorum_set_from_json(src: &str) -> Result<QuorumSet<ResponderId>, String> {
    Ok(serde_json::from_str(src)
        .map_err(|err| format!("Error parsing quorum set {}: {:?}", src, err))?)
}

impl Config {
    pub fn quorum_set(&self) -> QuorumSet<ResponderId> {
        // If we have an explicit quorum set, use that.
        if let Some(quorum_set) = &self.quorum_set {
            return quorum_set.clone();
        }

        // Otherwise create a quorum set that includes all of the peers we know about.
        let node_ids = self
            .peers_config
            .peers
            .iter()
            .map(|p| {
                p.responder_id().unwrap_or_else(|e| {
                    panic!(
                        "Could not get responder_id from uri {}: {:?}",
                        p.to_string(),
                        e
                    )
                })
            })
            .collect::<Vec<ResponderId>>();
        QuorumSet::new_with_node_ids(node_ids.len() as u32, node_ids)
    }
}

#[derive(Clone, Debug, StructOpt)]
#[structopt()]
pub struct PeersConfig {
    /// validator nodes to connect to.
    #[structopt(long = "peer", required = true, min_values = 1)]
    pub peers: Vec<ConsensusClientUri>,
}

impl PeersConfig {
    pub fn responder_ids(&self) -> Vec<ResponderId> {
        self.peers
            .iter()
            .map(|peer| {
                peer.responder_id()
                    .expect("Could not get responder_id from peer")
            })
            .collect()
    }

    pub fn create_peers(
        &self,
        expected_measurements: &[Measurement],
        grpc_env: Arc<grpcio::Environment>,
        logger: Logger,
    ) -> Vec<ThickClient> {
        self.peers
            .iter()
            .map(|client_uri| {
                ThickClient::new(
                    client_uri.clone(),
                    expected_measurements.to_vec(),
                    grpc_env.clone(),
                    logger.clone(),
                )
                .expect("Could not create thick client.")
            })
            .collect()
    }

    pub fn create_peer_manager(
        &self,
        measurement: impl Into<Measurement>,
        logger: &Logger,
    ) -> ConnectionManager<ThickClient> {
        let grpc_env = Arc::new(
            grpcio::EnvBuilder::new()
                .name_prefix("RPC".to_string())
                .build(),
        );
        let measurements = [measurement.into()];
        let peers = self.create_peers(&measurements, grpc_env, logger.clone());

        ConnectionManager::new(peers, logger.clone())
    }
}
