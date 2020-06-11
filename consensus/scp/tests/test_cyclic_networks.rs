// Copyright (c) 2018-2020 MobileCoin Inc.

mod mock_network;

use mc_common::{
    logger::{log, test_with_logger, Logger},
    HashSet,
};

use mc_consensus_scp::{core_types::{CombineFn, ValidityFn}, test_utils};
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
// Cyclic tests (similar to Figure 4 in the SCP whitepaper)
///////////////////////////////////////////////////////////////////////////////

/// Constructs a cyclic network (e.g. 1->2->3->4->1)
fn new_cyclic(
    num_nodes: usize,
    validity_fn: ValidityFn<String, test_utils::TransactionValidationError>,
    combine_fn: CombineFn<String>,
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

    mock_network::SCPNetwork::new(node_options, validity_fn, combine_fn, logger)
}

/// Performs a consensus test for a cyclic network of `num_nodes` nodes.
fn cyclic_test_helper(num_nodes: usize, logger: Logger) {
    if num_nodes < 3 {
        return;
    }
    
    if skip_slow_tests() {
        return;
    }
    
    let network = SCPNetwork::new_cyclic(
        num_nodes,
        Arc::new(test_utils::trivial_validity_fn::<String>),
        Arc::new(test_utils::trivial_combine_fn::<String>),
        logger.clone(),
    );

    let network_name = format!("cyclic{}", num_nodes);
    mock_network::run_test(network, values_to_push, logger.clone(), &network_name);
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
