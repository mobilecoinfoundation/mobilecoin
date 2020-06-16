// Copyright (c) 2018-2020 MobileCoin Inc.

// Mesh style network topologies.

// We allow dead code because not all integration tests use all of the common code.
// https://github.com/rust-lang/rust/issues/46379
#![allow(dead_code)]

use crate::mock_network;

///////////////////////////////////////////////////////////////////////////////
/// Mesh tests
/// (N nodes, each node has all other nodes as it's validators)
///////////////////////////////////////////////////////////////////////////////

/// Constructs a mesh network, where each node has all of it's peers as validators.
pub fn dense_mesh(num_nodes: usize, k: usize) -> mock_network::Network {
    let mut nodes = Vec::<mock_network::NodeOptions>::new();
    for node_id in 0..num_nodes {
        let other_node_ids: Vec<u32> = (0..num_nodes)
            .filter(|other_node_id| other_node_id != &node_id)
            .map(|other_node_id| other_node_id as u32)
            .collect();

        nodes.push(mock_network::NodeOptions::new(
            other_node_ids.clone(),
            other_node_ids,
            k as u32,
        ));
    }
    mock_network::Network::new(format!("m{}k{}", num_nodes, k), nodes)
}
