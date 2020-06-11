// Copyright (c) 2018-2020 MobileCoin Inc.

mod mock_network;

use mc_common::{
    logger::{o, test_with_logger, Logger},
    HashMap, HashSet,
    NodeID
};

use mc_consensus_scp::{core_types::{CombineFn, ValidityFn}, quorum_set::QuorumSet, test_utils};
use rand::{rngs::StdRng, Rng, SeedableRng};
use serial_test_derive::serial;
use std::{
    sync::{Arc, Mutex},
    thread::sleep,
    time::{Duration, Instant},
};

/// Hack to skip certain tests (that are currently too slow) from running
fn skip_slow_tests() -> bool {
    std::env::var("SKIP_SLOW_TESTS") == Ok("1".to_string())
}

fn meta_mesh_node_id(org_id: u32, num_servers_per_org: u32, server_id: u32) -> NodeID {
    let node_id = org_id * num_servers_per_org + server_id;
    NodeID(node_id.to_string())
}

/// Constructs a meta-mesh network, in which organizations run clusters of redundant servers
fn new_meta_mesh(
    num_orgs: usize,
    num_servers_per_org: usize,
    k_servers_per_org: u32,
    validity_fn: ValidityFn<String, test_utils::TransactionValidationError>,
    combine_fn: CombineFn<String>,
    logger: Logger,
) -> mock_network::SCPNetwork {
    let mut network = mock_network::SCPNetwork {
        nodes_map: Arc::new(Mutex::new(HashMap::default())),
        thread_handles: HashMap::default(),
        nodes_shared_data: HashMap::default(),
        logger: logger.clone(),
    };

    let org_quorum_sets = (0..num_orgs)
        .map(|org_id| {
            QuorumSet::new_with_node_ids(
                1,
                (0..num_servers_per_org)
                    .map(|server_id| {
                        meta_mesh_node_id(
                            org_id as u32,
                            num_servers_per_org as u32,
                            server_id as u32,
                        )
                    })
                    .collect::<Vec<NodeID>>(),
            )
        })
        .collect::<Vec<QuorumSet>>();

    for org_id in 0..num_orgs {
        for server_id in 0..num_servers_per_org {
            let thread_name = format!(
                "mm-{}-{}-{}-node{}-{}",
                num_orgs, num_servers_per_org, k_servers_per_org, org_id, server_id
            );

            let other_servers_in_this_org = (0..num_servers_per_org)
                .filter(|other_id| other_id != &server_id)
                .map(|server_id| {
                    meta_mesh_node_id(
                        org_id as u32,
                        num_servers_per_org as u32,
                        server_id as u32,
                    )
                })
                .collect::<Vec<NodeID>>();

            let inner_quorum_set_for_our_org =
                QuorumSet::new_with_node_ids(k_servers_per_org, other_servers_in_this_org);

            let mut inner_quorum_sets_for_other_orgs = org_quorum_sets
                .iter()
                .enumerate()
                .filter(|&(i, _)| i != org_id)
                .map(|(_, e)| e)
                .cloned()
                .collect::<Vec<QuorumSet>>();

            let mut inner_quorum_sets = Vec::<QuorumSet>::new();

            inner_quorum_sets.push(inner_quorum_set_for_our_org);
            inner_quorum_sets.append(&mut inner_quorum_sets_for_other_orgs);

            let qs = QuorumSet::new_with_inner_sets(num_orgs as u32, inner_quorum_sets);

            let node_id =
                meta_mesh_node_id(org_id as u32, num_servers_per_org as u32, server_id as u32);

            let peers: HashSet<NodeID> = org_quorum_sets
                .iter()
                .flat_map(|qs| {
                    let mut other_nodes = qs.nodes();
                    other_nodes.remove(&node_id);
                    other_nodes
                })
                .collect::<HashSet<NodeID>>();

            assert!(!peers.contains(&node_id));

            let nodes_map_clone: Arc<Mutex<HashMap<NodeID, SCPNode>>> =
                { Arc::clone(&network.nodes_map) };

            let (node, thread_handle) = mock_network::SCPNode::new(
                thread_name,
                node_id.clone(),
                qs,
                validity_fn.clone(),
                combine_fn.clone(),
                Arc::new(move |logger, msg| {
                    mock_network::SCPNetwork::broadcast_msg(logger, &nodes_map_clone, &peers, msg)
                }),
                logger.new(o!("mc.local_node_id" => node_id.to_string())),
            );

            network
                .thread_handles
                .insert(node_id.clone(), thread_handle);
            network
                .nodes_shared_data
                .insert(node_id.clone(), node.shared_data.clone());
            network
                .nodes_map
                .lock()
                .expect("lock failed on nodes_map inserting node")
                .insert(node_id.clone(), node);
        }
    }
    network
}

/// Performs a consensus test for a metamesh network of `num_orgs * num_servers_per_org` nodes.
fn metamesh_test_helper(
    num_orgs: usize,
    num_servers_per_org: usize,
    k_servers_per_org: u32,
    logger: Logger,
) {
    if num_servers_per_org < 3 || num_servers_per_org as u64 <= k_servers_per_org as u64 {
        return;
    }

    if skip_slow_tests() {
        return;
    }

    let network = new_meta_mesh(
        num_orgs,
        num_servers_per_org,
        k_servers_per_org,
        Arc::new(test_utils::trivial_validity_fn::<String>),
        Arc::new(test_utils::trivial_combine_fn::<String>),
        logger.clone(),
    );

    let network_name = format!(
        "mm{}-{}k{}",
        num_orgs, num_servers_per_org, k_servers_per_org
    );
    mock_network::run_test(network, &network_name, logger.clone());
}

#[test_with_logger]
#[serial]
fn metamesh_2_3(logger: Logger) {
    metamesh_test_helper(2,3,2,logger.clone(),);
}

#[test_with_logger]
#[serial]
fn metamesh_3_3(logger: Logger) {
    metamesh_test_helper(3,3,2,logger.clone(),);
}

#[test_with_logger]
#[serial]
fn metamesh_3_4(logger: Logger) {
    metamesh_test_helper(3,4,3,logger.clone(),);
}