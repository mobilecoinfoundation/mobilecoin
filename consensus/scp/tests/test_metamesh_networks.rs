// Copyright (c) 2018-2021 The MobileCoin Foundation

mod mock_network;

use mc_common::logger::{test_with_logger, Logger};
use serial_test_derive::serial;
use std::time::Duration;

/// Performs a consensus test for a metamesh network of `n * m` nodes.
fn metamesh_test_helper(
    n: usize,   // the number of organizations in the network
    k_n: usize, // the number of orgs that must agree within the network
    m: usize,   // the number of servers in each organization
    k_m: usize, // the number of servers that must agree within the org
    logger: Logger,
) {
    assert!(k_n <= n);
    assert!(k_m <= m);

    if (n * m) > 6 && mock_network::skip_slow_tests() {
        return;
    }

    let mut test_options = mock_network::TestOptions::new();

    // metamesh networks require more time to reach consensus!
    test_options.values_to_submit = 1;
    test_options.scp_timebase = Duration::from_millis(100);

    let network_config = mock_network::metamesh_topology::metamesh(n, k_n, m, k_m);
    mock_network::build_and_test(&network_config, &test_options, logger.clone());
}

#[test_with_logger]
#[serial]
fn metamesh_3k2_3k1(logger: Logger) {
    metamesh_test_helper(3, 2, 3, 1, logger.clone());
}

#[test_with_logger]
#[serial]
fn metamesh_3k2_3k2(logger: Logger) {
    metamesh_test_helper(3, 2, 3, 2, logger.clone());
}

#[test_with_logger]
#[serial]
fn metamesh_3k2_4k3(logger: Logger) {
    metamesh_test_helper(3, 2, 4, 3, logger.clone());
}

#[test_with_logger]
#[serial]
fn metamesh_3k2_5k4(logger: Logger) {
    metamesh_test_helper(3, 2, 5, 4, logger.clone());
}
