// Copyright (c) 2018-2020 MobileCoin Inc.

// Ring style network topologies.

// We allow dead code because not all integration tests use all of the common code.
// https://github.com/rust-lang/rust/issues/46379
#![allow(dead_code)]

use crate::mock_network;

///////////////////////////////////////////////////////////////////////////////
// Cyclic Topology (similar to Figure 4 in the SCP whitepaper)
///////////////////////////////////////////////////////////////////////////////

/// Constructs a cyclic network (e.g. 1->2->3->4->1)
pub fn directed_cycle(num_nodes: usize) -> mock_network::Network {
    let mut nodes = Vec::<mock_network::NodeOptions>::new();
    for node_id in 0..num_nodes {
        let next_node_id: u32 = if node_id + 1 < num_nodes {
            node_id as u32 + 1
        } else {
            0
        };

        let other_node_ids: Vec<u32> = (0..num_nodes)
            .filter(|other_node_id| other_node_id != &node_id)
            .map(|other_node_id| other_node_id as u32)
            .collect();

        nodes.push(mock_network::NodeOptions::new(
            other_node_ids,
            vec![next_node_id],
            1,
        ));
    }
    mock_network::Network::new(format!("cyclic{}", num_nodes), nodes)
}
