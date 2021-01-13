// Copyright (c) 2018-2021 The MobileCoin Foundation

mod mock_network;

use mc_common::logger::{test_with_logger, Logger};
use serial_test_derive::serial;

/// Performs a consensus test for a cyclic network of `num_nodes` nodes.
fn cyclic_test_helper(num_nodes: usize, logger: Logger) {
    if num_nodes > 3 && mock_network::skip_slow_tests() {
        return;
    }

    let mut test_options = mock_network::TestOptions::new();
    test_options.values_to_submit = 10000;

    let network_config = mock_network::cyclic_topology::directed_cycle(num_nodes);
    mock_network::build_and_test(&network_config, &test_options, logger.clone());
}

#[test_with_logger]
#[serial]
fn cyclic_1(logger: Logger) {
    cyclic_test_helper(1, logger);
}

#[test_with_logger]
#[serial]
fn cyclic_2(logger: Logger) {
    cyclic_test_helper(2, logger);
}

#[test_with_logger]
#[serial]
fn cyclic_3(logger: Logger) {
    cyclic_test_helper(3, logger);
}

#[test_with_logger]
#[serial]
fn cyclic_4(logger: Logger) {
    cyclic_test_helper(4, logger);
}

#[test_with_logger]
#[serial]
fn cyclic_5(logger: Logger) {
    cyclic_test_helper(5, logger);
}

#[test_with_logger]
#[serial]
fn cyclic_6(logger: Logger) {
    cyclic_test_helper(6, logger);
}
