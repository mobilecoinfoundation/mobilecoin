// Copyright (c) 2018-2020 MobileCoin Inc.

mod mock_network;

use mc_common::{
    logger::{log, test_with_logger, Logger},
    HashSet,
};

use mc_consensus_scp::test_utils;
use rand::{rngs::StdRng, Rng, SeedableRng};
use serial_test_derive::serial;
use std::{
    sync::Arc,
    thread::sleep,
    time::{Duration, Instant},
};

/// Hack to skip certain tests (that are currently too slow) from running
fn skip_slow_tests() -> bool {
    std::env::var("SKIP_SLOW_TESTS") == Ok("1".to_string())
}

///////////////////////////////////////////////////////////////////////////////
/// Mesh tests
/// (N nodes, each node has all other nodes as it's validators)
///////////////////////////////////////////////////////////////////////////////

/// Constructs a mesh network, where each node has all of it's peers as validators.
pub fn new_mesh(
    num_nodes: usize,
    k: u32,
    validity_fn: ValidityFn<String, TransactionValidationError>,
    combine_fn: CombineFn<String>,
    logger: Logger,
) -> SCPNetwork {
    let mut node_options = Vec::<NodeOptions>::new();
    for node_id in 0..num_nodes {
        let other_node_ids: Vec<u32> = (0..num_nodes)
            .filter(|other_node_id| other_node_id != &node_id)
            .map(|other_node_id| other_node_id as u32)
            .collect();

        node_options.push(NodeOptions::new(
            format!("m-{}-{}-node{}", num_nodes, k, node_id),
            other_node_ids.clone(),
            other_node_ids,
            k,
        ));
    }

    SCPNetwork::new(node_options, validity_fn, combine_fn, logger)
}

/// Performs a simple consensus test where a network of `num_nodes` nodes is started,
/// and values are submitted only to the middle node.
fn mesh_test_helper(num_nodes: usize, k: u32, logger: Logger) {
    if skip_slow_tests() {
        return;
    }
    assert!(num_nodes >= k as usize);
    let mut rng: StdRng = SeedableRng::from_seed([97u8; 32]);
    let start = Instant::now();

    let network = mock_network::SCPNetwork::new_mesh(
        num_nodes,
        k,
        Arc::new(test_utils::trivial_validity_fn::<String>),
        //                Arc::new(test_utils::get_bounded_combine_fn::<String>(3)),
        Arc::new(test_utils::trivial_combine_fn::<String>),
        logger.clone(),
    );

    // Send a few values, with random timeouts in between
    let mut values = Vec::<String>::new();

    for _i in 0..10 {
        let n = test_utils::test_node_id(rng.gen_range(0, num_nodes as u32));
        for _j in 0..2000 {
            let value = mock_network::random_str(&mut rng, 10);
            network.push_value(&n, &value);
            values.push(value);
        }
        sleep(Duration::from_millis(rng.gen_range(0, 50)));
    }

    // Check that the values got added to the nodes
    for node_num in 0..num_nodes {
        let node_id = test_utils::test_node_id(node_num as u32);

        network.wait_for_total_values(&node_id, values.len(), Duration::from_secs(1200));

        assert_eq!(
            values.iter().cloned().collect::<HashSet<String>>(),
            network
                .get_shared_data(&node_id)
                .get_all_values()
                .iter()
                .cloned()
                .collect::<HashSet<String>>()
        );
    }

    // Check all blocks in the ledger are the same
    let node0_data = network.get_shared_data(&test_utils::test_node_id(0)).ledger;
    assert!(!node0_data.is_empty());

    for node_num in 0..num_nodes {
        let node_data = network
            .get_shared_data(&test_utils::test_node_id(node_num as u32))
            .ledger;
        assert_eq!(node0_data.len(), node_data.len());

        for block_num in 0..node0_data.len() {
            assert_eq!(node0_data.get(block_num), node_data.get(block_num));
        }
    }

    // Done
    log::info!(
        logger,
        "mesh_test_helper num_nodes={} k={}: {:?} (avg {} tx/s)",
        num_nodes,
        k,
        start.elapsed(),
        values.len() as u64 / std::cmp::max(1, start.elapsed().as_secs()),
    );
}

#[test_with_logger]
#[serial]
fn mesh_1(logger: Logger) {
    mesh_test_helper(1, 0, logger);
}

#[test_with_logger]
#[serial]
fn mesh_2_k1(logger: Logger) {
    mesh_test_helper(2, 1, logger);
}

#[test_with_logger]
#[serial]
fn mesh_3_k1(logger: Logger) {
    mesh_test_helper(3, 1, logger);
}

#[test_with_logger]
#[serial]
fn mesh_3_k2(logger: Logger) {
    mesh_test_helper(3, 2, logger);
}

#[test_with_logger]
#[serial]
fn mesh_4_k3(logger: Logger) {
    mesh_test_helper(4, 3, logger);
}

#[test_with_logger]
#[serial]
fn mesh_5_k3(logger: Logger) {
    mesh_test_helper(5, 3, logger);
}

#[test_with_logger]
#[serial]
fn mesh_5_k4(logger: Logger) {
    mesh_test_helper(5, 4, logger);
}

// This is a very slow test :(
#[test_with_logger]
#[serial]
fn mesh_9_k7(logger: Logger) {
    // Since this test is very slow without --release, we skip it for debug builds.
    // See https://stackoverflow.com/questions/39204908/how-to-check-release-debug-builds-using-cfg-in-rust/39205417#39205417
    if cfg!(debug_assertions) {
        return;
    }

    mesh_test_helper(9, 7, logger);
}
