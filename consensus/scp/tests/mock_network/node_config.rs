//! Describes one simulated node

use mc_common::NodeID;
use mc_consensus_scp::QuorumSet;
use std::collections::HashSet;

#[derive(Clone)]
pub struct NodeConfig {
    /// This node's short name
    pub name: String,

    /// This node's id
    pub id: NodeID,

    /// The nodes to which this node broadcasts
    pub peers: HashSet<NodeID>,

    /// This node's quorum set
    pub quorum_set: QuorumSet,
}

impl NodeConfig {
    pub fn new(name: String, id: NodeID, peers: HashSet<NodeID>, quorum_set: QuorumSet) -> Self {
        Self {
            name,
            id,
            peers,
            quorum_set,
        }
    }
}
