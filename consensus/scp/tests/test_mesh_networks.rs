// Copyright (c) 2018-2021 The MobileCoin Foundation

mod mock_network;

use mc_common::logger::{test_with_logger, Logger};
use serial_test_derive::serial;

/// Performs a consensus test for a mesh network of (n) nodes.
fn mesh_test_helper(
    n: usize, // the number of nodes in the network
    k: usize, // the number of nodes that must agree within the network
    logger: Logger,
) {
    assert!(k <= n);

    if n > 3 && mock_network::skip_slow_tests() {
        return;
    }

    let mut test_options = mock_network::TestOptions::new();
    test_options.values_to_submit = 10000;
    let network_config = mock_network::mesh_topology::dense_mesh(n, k);
    mock_network::build_and_test(&network_config, &test_options, logger.clone());
}

#[test_with_logger]
#[serial]
fn mesh_1(logger: Logger) {
    mesh_test_helper(1, 0, logger);
}

#[test_with_logger]
#[serial]
fn mesh_2k1(logger: Logger) {
    mesh_test_helper(2, 1, logger);
}

#[test_with_logger]
#[serial]
fn mesh_3k1(logger: Logger) {
    mesh_test_helper(3, 1, logger);
}

#[test_with_logger]
#[serial]
fn mesh_3k2(logger: Logger) {
    mesh_test_helper(3, 2, logger);
}

#[test_with_logger]
#[serial]
fn mesh_4k3(logger: Logger) {
    mesh_test_helper(4, 3, logger);
}

#[test_with_logger]
#[serial]
fn mesh_5k3(logger: Logger) {
    mesh_test_helper(5, 3, logger);
}

#[test_with_logger]
#[serial]
fn mesh_5k4(logger: Logger) {
    mesh_test_helper(5, 4, logger);
}
