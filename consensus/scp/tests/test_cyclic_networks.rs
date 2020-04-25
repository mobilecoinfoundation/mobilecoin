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
// Cyclic tests (similar to Figure 4 in the SCP whitepaper)
///////////////////////////////////////////////////////////////////////////////

fn cyclic_test_helper(num_nodes: usize, logger: Logger) {
    if skip_slow_tests() {
        return;
    }

    assert!(num_nodes >= 3);
    let mut rng: StdRng = SeedableRng::from_seed([193u8; 32]);
    let start = Instant::now();

    let network = mock_network::SCPNetwork::new_cyclic(
        num_nodes,
        Arc::new(test_utils::trivial_validity_fn::<String>),
        //                Arc::new(test_utils::get_bounded_combine_fn::<String>(200)),
        Arc::new(test_utils::trivial_combine_fn::<String>),
        logger.clone(),
    );

    // Send a few values, with random timeouts in between
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
        let node_id = test_utils::test_node_id(node_num as u32);

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
        "cyclic_test_helper num_nodes={}: {:?} (avg {} tx/s)",
        num_nodes,
        start.elapsed(),
        (1_000_000 * values.len() as u128) / start.elapsed().as_micros(),
    );
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
