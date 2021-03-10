// Copyright (c) 2018-2021 The MobileCoin Foundation

// Ring style network topologies.

// We allow dead code because not all integration tests use all of the common
// code. https://github.com/rust-lang/rust/issues/46379
#![allow(dead_code)]

use crate::mock_network;
use mc_common::NodeID;
use mc_consensus_scp::{test_utils, QuorumSet};
use std::collections::HashSet;

///////////////////////////////////////////////////////////////////////////////
// Cyclic Topology (similar to Figure 4 in the SCP whitepaper)
///////////////////////////////////////////////////////////////////////////////

/// Constructs a cyclic network (e.g. 1->2->3->4->1)
pub fn directed_cycle(num_nodes: usize) -> mock_network::NetworkConfig {
    let mut nodes = Vec::<mock_network::NodeConfig>::new();
    for node_index in 0..num_nodes {
        let next_node_id: NodeID = {
            if node_index + 1 < num_nodes {
                test_utils::test_node_id(node_index as u32 + 1)
            } else {
                test_utils::test_node_id(0)
            }
        };

        let peers_vector = (0..num_nodes)
            .filter(|other_node_index| other_node_index != &node_index)
            .map(|other_node_index| test_utils::test_node_id(other_node_index as u32))
            .collect::<Vec<NodeID>>();

        nodes.push(mock_network::NodeConfig::new(
            format!("c{}", node_index),
            test_utils::test_node_id(node_index as u32),
            peers_vector.iter().cloned().collect::<HashSet<NodeID>>(),
            QuorumSet::new_with_node_ids(1, vec![next_node_id]),
        ));
    }

    mock_network::NetworkConfig::new(format!("cyclic{}", num_nodes), nodes)
}
