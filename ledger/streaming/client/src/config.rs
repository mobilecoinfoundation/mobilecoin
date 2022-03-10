use crate::source::GrpcBlockSource;
use mc_common::{logger::Logger, ResponderId};
use mc_consensus_scp::QuorumSet;
use mc_ledger_db::Ledger;
use mc_ledger_streaming_api::BlockSource;
use mc_util_uri::{ConnectionUri, ConsensusClientUri};
use std::{path::PathBuf, sync::Arc, time::Duration};

#[derive(Debug, StructOpt)]
#[structopt(name = "mobilecoind", about = "The MobileCoin client daemon.")]
pub struct Config {
    /// Path to ledger db (lmdb).
    #[structopt(long, default_value = "/tmp/ledgerdb", parse(from_os_str))]
    pub ledger_db: PathBuf,

    /// Path to existing ledger db that contains the origin block, used when
    /// initializing new ledger dbs.
    #[structopt(long)]
    pub ledger_db_bootstrap: Option<String>,

    #[structopt(flatten)]
    pub peers_config: PeersConfig,

    /// Quorum set for ledger syncing. By default, the quorum set would include
    /// all peers.
    ///
    /// The quorum set is represented in JSON. For example:
    /// {"threshold":1,"members":[{"type":"Node","args":"node2.test.mobilecoin.
    /// com:443"},{"type":"Node","args":"node3.test.mobilecoin.com:443"}]}
    #[structopt(long, parse(try_from_str = parse_quorum_set_from_json))]
    quorum_set: Option<QuorumSet<ResponderId>>,

    /// Automatically migrate the ledger db into the most recent version.
    #[structopt(long)]
    pub ledger_db_migrate: bool,
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
            .clone()
            .unwrap_or_default()
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
    #[structopt(long = "peer", required_unless = "offline")]
    pub peers: Option<Vec<ConsensusClientUri>>,
}

impl PeersConfig {
    pub fn responder_ids(&self) -> Vec<ResponderId> {
        self.peers
            .clone()
            .unwrap_or_default()
            .iter()
            .map(|peer| {
                peer.responder_id()
                    .expect("Could not get responder_id from peer")
            })
            .collect()
    }
}
