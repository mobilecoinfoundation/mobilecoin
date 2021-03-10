// Copyright (c) 2018-2021 The MobileCoin Foundation

// "Metamesh" network topologies.

// A metamesh consists of a set of (n) "organizations", each comprising (m)
// servers. Quorum is configured with hierarchy, such that each node requires
// (k_n) of the organizations to agree, and each organization is considered to
// reach agreement when (k_m) of its constituent servers reach agreement.

// As an example, consider a network with n=3 and m=3, with nodes labeled
// "n-index/m-index"
//
// The quorum set for node "0/0" is as follows:
// ([k_n], ([k_m - 1], 0/1, 0/2]), ([k_m], 1/0, 1/1, 1/2]), ([k_m], 2/0, 2/1,
// 2/2]]) The quorum set for node "1/2" is:
// ([k_n], ([k_m], 0/0, 0/1, 0/2]), ([k_m - 1], 1/0, 1/1]), ([k_m], 2/0, 2/1,
// 2/2]])

// We allow dead code because not all integration tests use all of the common
// code. https://github.com/rust-lang/rust/issues/46379
#![allow(dead_code)]

use crate::mock_network;
use mc_common::NodeID;
use mc_consensus_scp::{test_utils, QuorumSet};
use std::collections::HashSet;

///////////////////////////////////////////////////////////////////////////////
// Metamesh Topology
///////////////////////////////////////////////////////////////////////////////

pub fn metamesh(
    n: usize,   // the number of organizations in the network
    k_n: usize, // the number of orgs that must agree within the network
    m: usize,   // the number of servers in each organization
    k_m: usize, // the number of servers that must agree within the org
) -> mock_network::NetworkConfig {
    let mut nodes = Vec::<mock_network::NodeConfig>::new();

    let org_quorum_sets = (0..n)
        .map(|org_index| {
            QuorumSet::new_with_node_ids(
                k_m as u32,
                (0..m)
                    .map(|server_index| {
                        let node_index = (org_index * m + server_index) as u32;
                        test_utils::test_node_id(node_index)
                    })
                    .collect::<Vec<NodeID>>(),
            )
        })
        .collect::<Vec<QuorumSet>>();

    for org_index in 0..n {
        for server_index in 0..m {
            let node_index = (org_index * m + server_index) as u32;
            let node_id = test_utils::test_node_id(node_index);

            let other_servers_in_this_org = (0..m)
                .filter(|&index| index != server_index)
                .map(|server_index| {
                    let node_index = (org_index * m + server_index) as u32;
                    test_utils::test_node_id(node_index)
                })
                .collect::<Vec<NodeID>>();

            // reduce k by one if possible for this nodes organization
            let k_for_this_org: u32 = if k_m > 1 { k_m as u32 - 1 } else { 1 };
            let inner_quorum_set_for_this_org =
                QuorumSet::new_with_node_ids(k_for_this_org, other_servers_in_this_org);

            let mut inner_quorum_sets_for_other_orgs = org_quorum_sets
                .iter()
                .enumerate()
                .filter(|&(i, _)| i != org_index)
                .map(|(_, qs)| qs)
                .cloned()
                .collect::<Vec<QuorumSet>>();

            let mut inner_quorum_sets = Vec::<QuorumSet>::new();
            inner_quorum_sets.push(inner_quorum_set_for_this_org);
            inner_quorum_sets.append(&mut inner_quorum_sets_for_other_orgs);

            // connect this node to all other nodes
            let peers: HashSet<NodeID> = org_quorum_sets
                .iter()
                .flat_map(|qs| {
                    let mut other_nodes = qs.nodes();
                    other_nodes.remove(&node_id);
                    other_nodes
                })
                .collect::<HashSet<NodeID>>();

            nodes.push(mock_network::NodeConfig::new(
                format!("mm{}-{}", org_index, server_index),
                node_id,
                peers,
                QuorumSet::new_with_inner_sets(k_n as u32, inner_quorum_sets),
            ));
        }
    }

    mock_network::NetworkConfig::new(format!("{}k{}-{}k{}", n, k_n, m, k_m), nodes)
}
