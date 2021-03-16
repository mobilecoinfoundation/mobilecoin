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
        // A node should not "peer" with itself. (Maybe this check is unnecessary.)
        for node_config in node_configs {
            let node_id = &node_config.id;
            assert!(!node_config.peers.contains(node_id));
        }

        // NodeID to node name.
        let names: HashMap<NodeID, String> = node_configs
            .iter()
            .map(|node_config| (node_config.id.clone(), node_config.name.clone()))
            .collect();

        let nodes = Arc::new(Mutex::new(HashMap::default()));
        let mut handles = HashMap::default();
        let mut shared_data = HashMap::default();

        for node_config in node_configs {
            let node_id = &node_config.id;
            let (node, join_handle) = {
                let nodes_map = nodes.clone();
                let peers = node_config.peers.clone();

                SCPNode::new(
                    node_config.clone(),
                    test_options,
                    Arc::new(move |logger, msg| {
                        SCPNetwork::broadcast_msg(logger, &nodes_map, &peers, msg)
                    }),
                    0, // Initial slot index
                    logger.clone(),
                )
            };

            handles.insert(node_id.clone(), join_handle);
            shared_data.insert(node_id.clone(), node.shared_data.clone());
            nodes.lock().unwrap().insert(node_id.clone(), node);
        }

        Self {
            handles,
            names,
            nodes,
            shared_data,
            logger,
        }
    }

    /// Stop each node's thread.
    pub fn stop_all(&mut self) {
        log::trace!(self.logger, "stop_all");

        for (_, node) in self.nodes.lock().unwrap().iter_mut() {
            // TODO: may fail if the channel is full or disconnected.
            let _res = node.send_stop();
        }

        for (_node_id, handle) in self.handles.drain() {
            handle.join().unwrap()
        }
    }

    /// Submit a value to a node.
    pub fn submit_value_to_node(&self, value: &str, node_id: &NodeID) {
        // TODO: sending may fail if the channel is full or disconnected.
        let _res = self
            .nodes
            .lock()
            .expect("lock failed on nodes_map pushing value")
            .get(node_id)
            .expect("could not find node_id in nodes_map")
            .send_value(value);
    }

    /// Submit a value to each node in parallel.
    pub fn submit_value_to_nodes(&self, value: &str) {
        let node_ids: Vec<NodeID> = self
            .nodes
            .lock()
            .iter()
            .flat_map(|id_to_node| id_to_node.iter().map(|(node_id, _)| node_id.clone()))
            .collect();

        for node_id in &node_ids {
            self.submit_value_to_node(value.clone(), node_id);
        }
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
        nodes: &Arc<Mutex<HashMap<NodeID, SCPNode>>>,
        peers: &HashSet<NodeID>,
        msg: Msg<String>,
    ) {
        log::trace!(logger, "(broadcast) {}", msg);

        let mut nodes = nodes.lock().unwrap();
        for peer_id in peers {
            // TODO: sending may fail if the channel is full or disconnected.
            let _res = nodes.get_mut(&peer_id).unwrap().send_msg(&msg);
        }
    }
}

impl Drop for SCPNetwork {
    fn drop(&mut self) {
        self.stop_all();
    }
}
