// Copyright (c) 2018-2020 MobileCoin Inc.

mod mock_network;
use mc_common::logger::{test_with_logger, Logger};
use serial_test_derive::serial;

/// Hack to skip certain tests (that are currently too slow) from running
fn skip_slow_tests() -> bool {
    std::env::var("SKIP_SLOW_TESTS") == Ok("1".to_string())
}

///////////////////////////////////////////////////////////////////////////////
/// Mesh tests
/// (N nodes, each node has all other nodes as it's validators)
///////////////////////////////////////////////////////////////////////////////

/// Constructs a mesh network, where each node has all of it's peers as validators.
fn new_mesh(
    num_nodes: usize,
    k: u32,
    test_options: mock_network::TestOptions,
    logger: Logger,
) -> mock_network::SCPNetwork {
    let mut node_options = Vec::<mock_network::NodeOptions>::new();
    for node_id in 0..num_nodes {
        let other_node_ids: Vec<u32> = (0..num_nodes)
            .filter(|other_node_id| other_node_id != &node_id)
            .map(|other_node_id| other_node_id as u32)
            .collect();

        node_options.push(mock_network::NodeOptions::new(
            format!("m-{}-{}-node{}", num_nodes, k, node_id),
            other_node_ids.clone(),
            other_node_ids,
            k,
        ));
    }

    mock_network::SCPNetwork::new(node_options, test_options, logger)
}

/// Performs a consensus test for a mesh network of `num_nodes` nodes.
fn mesh_test_helper(num_nodes: usize, k: u32, logger: Logger) {
    assert!(k <= num_nodes as u32);

    if skip_slow_tests() {
        return;
    }

    let mut test_options = mock_network::TestOptions::new();
    test_options.values_to_submit = 20000;

    let network = new_mesh(num_nodes, k, test_options.clone(), logger.clone());
    let network_name = format!("mesh{}k{}", num_nodes, k);
    mock_network::run_test(network, &network_name, test_options, logger.clone());
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
