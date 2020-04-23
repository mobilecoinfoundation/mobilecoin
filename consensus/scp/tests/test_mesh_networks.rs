// Copyright (c) 2018-2020 MobileCoin Inc.

// Allow tests marked as ignored to have other attributes that are unused.
#![allow(unused_attributes)]

mod mock_network;

use common::{
    logger::{log, test_with_logger, Logger},
    HashSet,
};

use rand::{rngs::StdRng, Rng, SeedableRng};
use scp::test_utils;
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

///////////////////////////////////////////////////////////////////////////////
// Other network topologies
///////////////////////////////////////////////////////////////////////////////

/// The four-node configuration from Fig. 2 of the Stellar whitepaper.
///
/// The only quorum including node 1 is {1,2,3,4}. However, {2,3,4} is a quorum that excludes node 1.
#[ignore]
#[test_with_logger]
#[serial]
fn stellar_fig2(logger: Logger) {
    let mut rng: StdRng = SeedableRng::from_seed([243u8; 32]);
    let start = Instant::now();

    let v1_id = 0;
    let v2_id = 1;
    let v3_id = 2;
    let v4_id = 3;

    // Q(v1) = {{v1, v2, v3}}
    let v1 = mock_network::NodeOptions::new(
        "Fig2-1".to_string(),
        vec![v2_id, v3_id, v4_id],
        vec![v2_id, v3_id],
        2,
    );

    // Q(v2) = {{v2, v3, v4}}
    let v2 = mock_network::NodeOptions::new(
        "Fig2-2".to_string(),
        vec![v1_id, v3_id, v4_id],
        vec![v3_id, v4_id],
        2,
    );

    // Q(v3) = {{v2, v3, v4}}
    let v3 = mock_network::NodeOptions::new(
        "Fig2-3".to_string(),
        vec![v1_id, v2_id, v4_id],
        vec![v2_id, v4_id],
        2,
    );

    // Q(v4) = {{v2, v3, v4}}
    let v4 = mock_network::NodeOptions::new(
        "Fig2-4".to_string(),
        vec![v1_id, v2_id, v3_id],
        vec![v2_id, v3_id],
        2,
    );

    let num_nodes: u32 = 4;

    let network = mock_network::SCPNetwork::new(
        vec![v1, v2, v3, v4],
        Arc::new(test_utils::trivial_validity_fn::<String>),
        Arc::new(test_utils::trivial_combine_fn::<String>),
        logger.clone(),
    );

    // Send a few values, with random timeouts in between.
    let mut values = Vec::<String>::new();

    for _i in 0..10 {
        let n = test_utils::test_node_id(rng.gen_range(0, num_nodes as u32));
        for _j in 0..1000 {
            let value = format!("{}-{}", n, mock_network::random_str(&mut rng, 10));
            network.push_value(&n, &value);
            values.push(value);
        }
        sleep(Duration::from_millis(rng.gen_range(0, 50)));
    }

    // Check that the values got added to the nodes
    for node_num in 0..num_nodes {
        let node_id = test_utils::test_node_id(node_num);

        network.wait_for_total_values(&node_id, values.len(), Duration::from_secs(600));

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
        "fig2 num_nodes={}: {:?} (avg {} tx/s)",
        num_nodes,
        start.elapsed(),
        (1_000_000 * values.len() as u128) / start.elapsed().as_micros(),
    );
}
