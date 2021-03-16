// Copyright (c) 2018-2021 The MobileCoin Foundation

// Thread-based simulation for consensus networks.

use mc_common::{
    logger::{log, Logger},
    NodeID,
};
use std::{
    collections::HashSet,
    time::{Duration, Instant},
};

pub mod cyclic_topology;
pub mod mesh_topology;
pub mod metamesh_topology;
mod node_config;
mod scp_network;
mod scp_node;
mod test_options;

use crate::mock_network::scp_network::SCPNetwork;
pub use node_config::NodeConfig;
pub use test_options::TestOptions;

// Test values are random strings of this length.
const CHARACTERS_PER_VALUE: usize = 10;

/// Support skipping slow tests based on environment variables.
pub fn skip_slow_tests() -> bool {
    std::env::var("SKIP_SLOW_TESTS") == Ok("1".to_string())
}

/// Simulated network configuration.
#[derive(Clone)]
pub struct NetworkConfig {
    /// The name of this network.
    pub name: String,
    /// Configuration for nodes in this network.
    pub nodes: Vec<NodeConfig>,
}

impl NetworkConfig {
    /// Create a new NetworkConfig
    ///
    /// # Arguments
    /// * `name` - Network name
    /// * `nodes` - Configuration for each node in the network
    pub fn new(name: String, nodes: Vec<NodeConfig>) -> Self {
        Self { name, nodes }
    }

    /// The NodeID of each node in the network.
    pub fn node_ids(&self) -> Vec<NodeID> {
        self.nodes.iter().map(|n| n.id.clone()).collect()
    }
}

/// Injects values to a network and waits for completion.
pub fn build_and_test(network_config: &NetworkConfig, test_options: &TestOptions, logger: Logger) {
    let start = Instant::now();
    log::info!(logger, "Network name: {}", network_config.name);
    log::info!(logger, "{}", test_options);

    let network = SCPNetwork::new(&network_config.nodes, test_options, logger.clone());
    let node_ids: Vec<NodeID> = network_config.node_ids();

    // Initially: each node has an empty ledger.
    for node_id in &node_ids {
        assert_eq!(network.get_ledger_size(node_id), 0);
    }

    // Values that each node should eventually write to its ledger.
    let values = get_values(test_options.values_to_submit);

    // Submit values to nodes.
    let mut last_log = Instant::now();
    for (i, value) in values.iter().enumerate() {
        let start = Instant::now();

        if test_options.submit_in_parallel {
            // Submit the value to each node in parallel.
            network.submit_value_to_nodes(value);
        } else {
            // Submit the value to a single node in round-robin order.
            let node_id = &node_ids[i % node_ids.len()];
            network.submit_value_to_node(value, node_id);
        }

        if last_log.elapsed().as_millis() > 999 {
            log::info!(logger, "( testing ) pushed {}/{} values", i, values.len());
            last_log = Instant::now();
        }

        // Throttle the rate at which values are submitted to the network.
        let elapsed_duration = Instant::now().duration_since(start);
        let target_duration = Duration::from_micros(1_000_000 / test_options.submissions_per_sec);
        if let Some(extra_delay) = target_duration.checked_sub(elapsed_duration) {
            std::thread::sleep(extra_delay);
        }
    }

    // All values have been pushed.
    log::info!(
        logger,
        "( testing ) pushed {} values",
        test_options.values_to_submit
    );

    // abort testing if we exceed allowed time
    let deadline = Instant::now() + test_options.allowed_test_time;

    // Check that the values have been externalized by all nodes
    for node_id in node_ids.iter() {
        let mut last_log = Instant::now();
        loop {
            if Instant::now() > deadline {
                log::error!(
                    logger,
                    "( testing ) failed to externalize all values within {} sec at node {}!",
                    test_options.allowed_test_time.as_secs(),
                    network.names.get(node_id).unwrap()
                );
                panic!("test failed due to timeout");
            }

            let num_externalized_values = network.get_ledger_size(&node_id);
            if num_externalized_values >= test_options.values_to_submit {
                // if the validity_fn does not enforce unique values, we can end up
                // with values that appear in multiple slots. This is not a problem
                // provided that all the nodes externalize the same ledger!
                log::info!(
                    logger,
                    "( testing ) externalized {}/{} values at node {}",
                    num_externalized_values,
                    test_options.values_to_submit,
                    network.names.get(node_id).unwrap(),
                );

                if num_externalized_values > test_options.values_to_submit {
                    log::warn!(
                        logger,
                        "( testing ) externalized extra values at node {}",
                        network.names.get(node_id).unwrap(),
                    );
                }

                break;
            }

            if last_log.elapsed().as_millis() > 999 {
                log::info!(
                    logger,
                    "( testing ) externalized {}/{} values at node {}",
                    num_externalized_values,
                    test_options.values_to_submit,
                    network.names.get(node_id).unwrap(),
                );
                last_log = Instant::now();
            }
        }

        // check that all submitted values are externalized at least once
        // duplicate values are possible depending on validity_fn
        let externalized_values_hashset = network
            .get_ledger(&node_id)
            .iter()
            .flatten()
            .cloned()
            .collect::<HashSet<String>>();

        let values_hashset = values.iter().cloned().collect::<HashSet<String>>();

        if values_hashset != externalized_values_hashset {
            let missing_values: HashSet<String> = values_hashset
                .difference(&externalized_values_hashset)
                .cloned()
                .collect();

            let unexpected_values: HashSet<String> = externalized_values_hashset
                .difference(&values_hashset)
                .cloned()
                .collect();

            log::error!(
                logger,
                "node {} externalized wrong values! missing: {:?}, unexpected: {:?}",
                network.names.get(node_id).unwrap(),
                missing_values,
                unexpected_values,
            );
            // panic
            panic!("test failed due to wrong values being externalized");
        }
    }

    // Check that all of the externalized ledgers match block-by-block
    let first_node_ledger = network.get_ledger(&node_ids[0]);
    for node_id in node_ids.iter().skip(1) {
        let other_node_ledger = network.get_ledger(&node_id);

        if first_node_ledger.len() != other_node_ledger.len() {
            log::error!(
                logger,
                "first_node_ledger.len() != other_node_ledger.len() in run_test()"
            );
            // panic
            panic!("test failed due to ledgers having different block count");
        }

        for block_index in 0..first_node_ledger.len() {
            if first_node_ledger.get(block_index) != other_node_ledger.get(block_index) {
                log::error!(
                    logger,
                    "first_node_ledger block differs from other_node_ledger block at block {}",
                    block_index,
                );
                //panic
                panic!("test failed due to ledgers having different block content");
            }
        }
    }

    // Drop the network here so that MESSAGES log statements appear before results.
    drop(network);

    // csv for scripting use
    log::info!(
        logger,
        "test results: {},{},{},{},{},{}",
        network_config.name,
        start.elapsed().as_millis(),
        values.len(),
        test_options.submissions_per_sec,
        test_options.max_slot_proposed_values,
        test_options.scp_timebase.as_millis(),
    );

    // human readable throughput
    log::info!(
        logger,
        "test completed for {}: {:?} (avg {} tx/s)",
        network_config.name,
        start.elapsed(),
        (1_000_000 * values.len() as u128) / start.elapsed().as_micros(),
    );

    // allow log to flush
    std::thread::sleep(test_options.log_flush_delay);
}

/// Randomly generated values, not necessarily unique.
fn get_values(num_values: usize) -> Vec<String> {
    let mut rng = mc_util_test_helper::get_seeded_rng();
    let mut values = Vec::new();
    for _i in 0..num_values {
        let value = mc_util_test_helper::random_str(&mut rng, CHARACTERS_PER_VALUE);
        values.push(value);
    }
    values
}
