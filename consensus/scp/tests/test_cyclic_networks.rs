// Copyright (c) 2018-2020 MobileCoin Inc.

mod mock_network;
use mc_common::logger::{test_with_logger, Logger};
use serial_test_derive::serial;

/// Hack to skip certain tests (that are currently too slow) from running
fn skip_slow_tests() -> bool {
    std::env::var("SKIP_SLOW_TESTS") == Ok("1".to_string())
}

///////////////////////////////////////////////////////////////////////////////
// Cyclic tests (similar to Figure 4 in the SCP whitepaper)
///////////////////////////////////////////////////////////////////////////////

/// Constructs a cyclic network (e.g. 1->2->3->4->1)
fn new_cyclic(
    num_nodes: usize,
    test_options: mock_network::TestOptions,
    logger: Logger,
) -> mock_network::SCPNetwork {
    let mut node_options = Vec::<mock_network::NodeOptions>::new();
    for node_id in 0..num_nodes {
        let next_node_id: u32 = if node_id + 1 < num_nodes {
            node_id as u32 + 1
        } else {
            0
        };

        let other_node_ids: Vec<u32> = (0..num_nodes)
            .filter(|other_node_id| other_node_id != &node_id)
            .map(|other_node_id| other_node_id as u32)
            .collect();

        node_options.push(mock_network::NodeOptions::new(
            format!("c-{}-node{}", num_nodes, node_id),
            other_node_ids,
            vec![next_node_id],
            1,
        ));
    }

    mock_network::SCPNetwork::new(node_options, test_options, logger)
}

/// Performs a consensus test for a cyclic network of `num_nodes` nodes.
fn cyclic_test_helper(num_nodes: usize, logger: Logger) {
    if skip_slow_tests() {
        return;
    }

    let mut test_options = mock_network::TestOptions::new();
    test_options.values_to_submit = 10000;

    let network = new_cyclic(num_nodes, test_options.clone(), logger.clone());
    let network_name = format!("cyclic{}", num_nodes);
    mock_network::run_test(network, &network_name, test_options, logger.clone());
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
