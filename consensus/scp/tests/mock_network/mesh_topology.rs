// Copyright (c) 2018-2021 The MobileCoin Foundation

// Mesh style network topologies.

// We allow dead code because not all integration tests use all of the common
// code. https://github.com/rust-lang/rust/issues/46379
#![allow(dead_code)]

use crate::mock_network;
use mc_common::NodeID;
use mc_consensus_scp::{test_utils, QuorumSet};
use std::collections::HashSet;

///////////////////////////////////////////////////////////////////////////////
/// Mesh tests
/// (N nodes, each node has all other nodes as it's validators)
///////////////////////////////////////////////////////////////////////////////

/// Constructs a mesh network, where each node has all of it's peers as
/// validators.
pub fn dense_mesh(
    n: usize, // the number of nodes in the network
    k: usize, // the number of nodes that must agree within the network
) -> mock_network::NetworkConfig {
    let mut nodes = Vec::<mock_network::NodeConfig>::new();
    for node_index in 0..n {
        let peers_vector = (0..n)
            .filter(|other_node_index| other_node_index != &node_index)
            .map(|other_node_index| test_utils::test_node_id(other_node_index as u32))
            .collect::<Vec<NodeID>>();

        nodes.push(mock_network::NodeConfig::new(
            format!("m{}", node_index),
            test_utils::test_node_id(node_index as u32),
            peers_vector.iter().cloned().collect::<HashSet<NodeID>>(),
            QuorumSet::new_with_node_ids(k as u32, peers_vector),
        ));
    }

    mock_network::NetworkConfig::new(format!("m{}k{}", n, k), nodes)
}
