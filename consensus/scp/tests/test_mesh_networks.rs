// Copyright (c) 2018-2020 MobileCoin Inc.

mod mock_network;

use mc_common::logger::{test_with_logger, Logger};
use serial_test_derive::serial;

/// Performs a consensus test for a mesh network of `num_nodes` nodes.
fn mesh_test_helper(num_nodes: usize, k: usize, logger: Logger) {
    assert!(k <= num_nodes);

    if num_nodes > 3 && mock_network::skip_slow_tests() {
        return;
    }

    let mut test_options = mock_network::TestOptions::new();
    test_options.values_to_submit = 10000;
    let network = mock_network::mesh_topology::dense_mesh(num_nodes, k);
    mock_network::build_and_test(&network, &test_options, logger.clone());
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
