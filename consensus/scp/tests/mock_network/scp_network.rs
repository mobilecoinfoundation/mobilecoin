//! A simulated SCP network.

use crate::mock_network::{
    scp_node::{SCPNode, SCPNodeSharedData},
    NodeConfig, TestOptions,
};
use mc_common::{
    logger::{log, Logger},
    NodeID,
};
use mc_consensus_scp::Msg;
use std::{
    collections::{HashMap, HashSet},
    sync::{Arc, Mutex},
    thread::JoinHandle,
};

#[derive(Clone)]
pub struct NetworkConfig {
    pub name: String,
    pub nodes: Vec<NodeConfig>,
}

impl NetworkConfig {
    pub fn new(name: String, nodes: Vec<NodeConfig>) -> Self {
        Self { name, nodes }
    }

    /// The NodeID of each node in the network.
    #[allow(unused)]
    pub fn node_ids(&self) -> Vec<NodeID> {
        self.nodes.iter().map(|n| n.id.clone()).collect()
    }
}

pub struct SCPNetwork {
    /// NodeID to node.
    nodes: Arc<Mutex<HashMap<NodeID, SCPNode>>>,

    /// NodeID to the node's thread handle.
    handles: HashMap<NodeID, JoinHandle<()>>,

    /// NodeID to node name.
    pub names: HashMap<NodeID, String>,

    /// NodeID to ...???
    shared_data: HashMap<NodeID, Arc<Mutex<SCPNodeSharedData>>>,

    logger: Logger,
}

impl SCPNetwork {
    // Creates a simulated network.
    pub fn new(node_configs: &[NodeConfig], test_options: &TestOptions, logger: Logger) -> Self {
        let mut handles = HashMap::default();
        let mut names = HashMap::default();
        let nodes = Arc::new(Mutex::new(HashMap::default()));
        let mut shared_data = HashMap::default();

        for node_config in node_configs {
            let node_id = &node_config.id;
            let name = &node_config.name;
            assert!(!node_config.peers.contains(node_id)); // ???

            let (node, join_handle) = {
                let nodes_map = nodes.clone(); // ???
                let peers = node_config.peers.clone();

                SCPNode::new(
                    node_config.clone(),
                    test_options,
                    Arc::new(move |logger, msg| {
                        SCPNetwork::broadcast_msg(logger, &nodes_map, &peers, msg)
                    }),
                    0, // first slot index
                    logger.clone(),
                )
            };

            handles.insert(node_id.clone(), join_handle);
            names.insert(node_id.clone(), name.clone());
            shared_data.insert(node_id.clone(), node.shared_data.clone());
            nodes.lock().unwrap().insert(node_id.clone(), node);
        }

        SCPNetwork {
            handles,
            names,
            nodes,
            shared_data,
            logger,
        }
    }

    pub fn stop_all(&mut self) {
        let mut nodes_map = self.nodes.lock().unwrap();
        let mut node_ids: Vec<NodeID> = Vec::new();
        for (node_id, node) in nodes_map.iter_mut() {
            log::trace!(
                self.logger,
                "sending stop to {}",
                self.names.get(node_id).unwrap(),
            );
            node.send_stop();
            node_ids.push(node_id.clone());
        }
        drop(nodes_map);

        for node_id in node_ids {
            self.handles
                .remove(&node_id)
                .expect("Handle is missing")
                .join()
                .expect("SCPNode join failed");
        }
    }

    pub fn push_value(&self, node_id: &NodeID, value: &str) {
        self.nodes
            .lock()
            .expect("lock failed on nodes_map pushing value")
            .get(node_id)
            .expect("could not find node_id in nodes_map")
            .send_value(value);
    }

    pub fn get_ledger(&self, node_id: &NodeID) -> Vec<Vec<String>> {
        self.shared_data
            .get(node_id)
            .expect("could not find node_id in shared_data_map")
            .lock()
            .expect("lock failed on shared_data getting ledger")
            .ledger
            .clone()
    }

    pub fn get_ledger_size(&self, node_id: &NodeID) -> usize {
        self.shared_data
            .get(node_id)
            .expect("could not find node_id in shared_data_map")
            .lock()
            .expect("lock failed on shared_data getting ledger size")
            .ledger_size()
    }

    pub fn broadcast_msg(
        logger: Logger,
        nodes_map: &Arc<Mutex<HashMap<NodeID, SCPNode>>>,
        peers: &HashSet<NodeID>,
        msg: Msg<String>,
    ) {
        let mut nodes_map = nodes_map
            .lock()
            .expect("lock failed on nodes_map in broadcast");

        log::trace!(logger, "(broadcast) {}", msg);

        let amsg = Arc::new(msg);

        for peer_id in peers {
            nodes_map
                .get_mut(&peer_id)
                .expect("failed to get peer from nodes_map")
                .send_msg(amsg.clone());
        }
    }
}

impl Drop for SCPNetwork {
    fn drop(&mut self) {
        self.stop_all();
    }
}
