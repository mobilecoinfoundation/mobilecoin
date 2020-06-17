// Copyright (c) 2018-2020 MobileCoin Inc.

// Mesh style network topologies.

// We allow dead code because not all integration tests use all of the common code.
// https://github.com/rust-lang/rust/issues/46379
#![allow(dead_code)]

use crate::mock_network;

use mc_common::{HashSet, NodeID};
use mc_consensus_scp::{QuorumSet, test_utils};

///////////////////////////////////////////////////////////////////////////////
/// Mesh tests
/// (N nodes, each node has all other nodes as it's validators)
///////////////////////////////////////////////////////////////////////////////

/// Constructs a mesh network, where each node has all of it's peers as validators.
pub fn dense_mesh(num_nodes: usize, k: usize) -> mock_network::Network {
    let mut nodes = Vec::<mock_network::NodeOptions>::new();
    for node_index in 0..num_nodes {
        let peers_vector = (0..num_nodes)
            .filter(|other_node_index| other_node_index != &node_index)
            .map(|other_node_index| test_utils::test_node_id(other_node_index as u32))
            .collect::<Vec<NodeID>>();

        nodes.push(mock_network::NodeOptions::new(
            test_utils::test_node_id(node_index as u32),
            peers_vector.iter().cloned().collect::<HashSet<NodeID>>(),
            QuorumSet::new_with_node_ids(k as u32, peers_vector),
        ));
    }

    mock_network::Network::new(format!("m{}k{}", num_nodes, k), nodes)
}
