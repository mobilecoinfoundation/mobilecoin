// Copyright (c) 2018-2021 The MobileCoin Foundation

// Thread-based simulation for consensus networks.

use mc_common::{
    logger::{log, Logger},
    NodeID,
};
use mc_consensus_scp::{
    core_types::{CombineFn, SlotIndex, ValidityFn},
    msg::Msg,
    node::{Node, ScpNode},
    quorum_set::QuorumSet,
    test_utils,
};
use std::{
    collections::{BTreeSet, HashMap, HashSet},
    sync::{Arc, Mutex},
    thread,
    thread::JoinHandle,
    time::{Duration, Instant},
};

pub mod cyclic_topology;
pub mod mesh_topology;
pub mod metamesh_topology;

// Test values are random strings of this length.
const CHARACTERS_PER_VALUE: usize = 10;

// Controls test parameters
#[derive(Clone)]
pub struct TestOptions {
    /// Values can be submitted to all nodes in parallel (true) or to nodes in
    /// sequential order (false)
    pub submit_in_parallel: bool,

    /// Total number of values to submit. Tests run until all values are
    /// externalized by all nodes. N.B. if the validity fn doesn't enforce
    /// unique values, it's possible a value will appear in multiple places
    /// in the ledger, and that the ledger will contain more than
    /// values_to_submit
    pub values_to_submit: usize,

    /// Approximate rate that values are submitted to nodes. Unless we are
    /// testing slow submission is it better to set this quite high.
    pub submissions_per_sec: u64,

    /// We propose up to this many values from our pending set per slot.
    pub max_slot_proposed_values: usize,

    /// The total allowed testing time before forcing a panic
    pub allowed_test_time: Duration,

    /// wait this long for slog to flush values before ending a test
    pub log_flush_delay: Duration,

    /// This parameter sets the interval for round and ballot timeout.
    /// SCP suggests one second, but threads can run much faster.
    pub scp_timebase: Duration,

    /// The values validity function to use (typically trivial)
    pub validity_fn: ValidityFn<String, test_utils::TransactionValidationError>,

    /// The values combine function to use (typically trivial)
    pub combine_fn: CombineFn<String, test_utils::TransactionValidationError>,
}

impl TestOptions {
    pub fn new() -> Self {
        Self {
            submit_in_parallel: true,
            values_to_submit: 5000,
            submissions_per_sec: 20000,
            max_slot_proposed_values: 100,
            allowed_test_time: Duration::from_secs(300),
            log_flush_delay: Duration::from_millis(50),
            scp_timebase: Duration::from_millis(1000),
            validity_fn: Arc::new(test_utils::trivial_validity_fn::<String>),
            combine_fn: Arc::new(test_utils::get_bounded_combine_fn::<String>(100)),
        }
    }
}

// Describes one simulated node
#[derive(Clone)]
pub struct NodeConfig {
    /// This node's short name
    name: String,

    /// This node's id
    id: NodeID,

    /// The nodes to which this node broadcasts
    peers: HashSet<NodeID>,

    /// This node's quorum set
    quorum_set: QuorumSet,
}

impl NodeConfig {
    pub fn new(name: String, id: NodeID, peers: HashSet<NodeID>, quorum_set: QuorumSet) -> Self {
        Self {
            name,
            id,
            peers,
            quorum_set,
        }
    }
}

// Describes a network of nodes for simulation
#[derive(Clone)]
pub struct NetworkConfig {
    name: String,
    nodes: Vec<NodeConfig>,
}

impl NetworkConfig {
    pub fn new(name: String, nodes: Vec<NodeConfig>) -> Self {
        Self { name, nodes }
    }
}

pub struct SCPNetwork {
    handle_map: HashMap<NodeID, JoinHandle<()>>,
    names_map: HashMap<NodeID, String>,
    nodes_map: Arc<Mutex<HashMap<NodeID, SCPNode>>>,
    shared_data_map: HashMap<NodeID, Arc<Mutex<SCPNodeSharedData>>>,
    logger: Logger,
}

impl SCPNetwork {
    // creates a new network simulation
    pub fn new(network_config: &NetworkConfig, test_options: &TestOptions, logger: Logger) -> Self {
        let mut scp_network = SCPNetwork {
            handle_map: HashMap::default(),
            names_map: HashMap::default(),
            nodes_map: Arc::new(Mutex::new(HashMap::default())),
            shared_data_map: HashMap::default(),
            logger: logger.clone(),
        };

        for node_config in network_config.nodes.iter() {
            assert!(!node_config.peers.contains(&node_config.id));

            let nodes_map_clone = Arc::clone(&scp_network.nodes_map);
            let peers_clone = node_config.peers.clone();

            let (node, join_handle) = SCPNode::new(
                node_config.clone(),
                test_options,
                Arc::new(move |logger, msg| {
                    SCPNetwork::broadcast_msg(logger, &nodes_map_clone, &peers_clone, msg)
                }),
                0, // first slot index
                logger.clone(),
            );
            scp_network
                .handle_map
                .insert(node_config.id.clone(), join_handle);
            scp_network
                .names_map
                .insert(node_config.id.clone(), node_config.name.clone());
            scp_network
                .shared_data_map
                .insert(node_config.id.clone(), node.shared_data.clone());
            scp_network
                .nodes_map
                .lock()
                .expect("lock failed on nodes_map inserting node")
                .insert(node_config.id.clone(), node);
        }

        scp_network
    }

    fn stop_all(&mut self) {
        let mut nodes_map = self
            .nodes_map
            .lock()
            .expect("lock failed on nodes_map in stop_all");
        let mut node_ids: Vec<NodeID> = Vec::new();
        for (node_id, node) in nodes_map.iter_mut() {
            log::trace!(
                self.logger,
                "sending stop to {}",
                self.names_map
                    .get(node_id)
                    .expect("could not find node_id in nodes_map"),
            );
            node.send_stop();
            node_ids.push(node_id.clone());
        }
        drop(nodes_map);

        for node_id in node_ids {
            self.handle_map
                .remove(&node_id)
                .expect("thread handle is missing")
                .join()
                .expect("SCPNode join failed");
        }
    }

    fn push_value(&self, node_id: &NodeID, value: &str) {
        self.nodes_map
            .lock()
            .expect("lock failed on nodes_map pushing value")
            .get(node_id)
            .expect("could not find node_id in nodes_map")
            .send_value(value);
    }

    fn get_ledger(&self, node_id: &NodeID) -> Vec<Vec<String>> {
        self.shared_data_map
            .get(node_id)
            .expect("could not find node_id in shared_data_map")
            .lock()
            .expect("lock failed on shared_data getting ledger")
            .ledger
            .clone()
    }

    fn get_ledger_size(&self, node_id: &NodeID) -> usize {
        self.shared_data_map
            .get(node_id)
            .expect("could not find node_id in shared_data_map")
            .lock()
            .expect("lock failed on shared_data getting ledger size")
            .ledger_size()
    }

    fn broadcast_msg(
        logger: Logger,
        nodes_map: &Arc<Mutex<HashMap<NodeID, SCPNode>>>,
        peers: &HashSet<NodeID>,
        msg: Msg<String>,
    ) {
        let mut nodes_map = nodes_map
            .lock()
            .expect("lock failed on nodes_map in broadcast");

        log::trace!(logger, "(broadcast) {}", msg);

        let amsg = Arc::new(msg);

        for peer_id in peers {
            nodes_map
                .get_mut(&peer_id)
                .expect("failed to get peer from nodes_map")
                .send_msg(amsg.clone());
        }
    }
}

impl Drop for SCPNetwork {
    fn drop(&mut self) {
        self.stop_all();
    }
}

enum SCPNodeTaskMessage {
    Value(String),
    Msg(Arc<Msg<String>>),
    StopTrigger,
}

// Node data shared between threads
#[derive(Clone)]
struct SCPNodeSharedData {
    pub ledger: Vec<Vec<String>>,
}

impl SCPNodeSharedData {
    pub fn ledger_size(&self) -> usize {
        self.ledger.iter().fold(0, |acc, block| acc + block.len())
    }
}

// A simulated validator node
struct SCPNode {
    sender: crossbeam_channel::Sender<SCPNodeTaskMessage>,
    shared_data: Arc<Mutex<SCPNodeSharedData>>,
}

impl SCPNode {
    fn new(
        node_config: NodeConfig,
        test_options: &TestOptions,
        broadcast_msg_fn: Arc<dyn Fn(Logger, Msg<String>) + Sync + Send>,
        current_slot_index: SlotIndex,
        logger: Logger,
    ) -> (Self, JoinHandle<()>) {
        let (sender, receiver) = crossbeam_channel::unbounded();

        let scp_node = Self {
            sender,
            shared_data: Arc::new(Mutex::new(SCPNodeSharedData { ledger: Vec::new() })),
        };

        let mut thread_local_node = Node::new(
            node_config.id.clone(),
            node_config.quorum_set.clone(),
            test_options.validity_fn.clone(),
            test_options.combine_fn.clone(),
            current_slot_index,
            logger.clone(),
        );
        thread_local_node.scp_timebase = test_options.scp_timebase;

        let thread_shared_data = Arc::clone(&scp_node.shared_data);
        let max_slot_proposed_values: usize = test_options.max_slot_proposed_values;

        let mut current_slot: usize = 0;
        let mut total_broadcasts: u32 = 0;

        let join_handle = {
            thread::Builder::new()
                .name(node_config.id.to_string())
                .spawn(move || {
                    // All values that have not yet been externalized.
                    let mut pending_values: Vec<String> = Vec::default();

                    'main_loop: loop {
                        // Compare to byzantine_ledger::tick()
                        // there pending values are proposed before incoming msg is handled
                        let mut incoming_msg_option: Option<Arc<Msg<String>>> = None;

                        // Collect one incoming message using a non-blocking channel read
                        match receiver.try_recv() {
                            Ok(scp_msg) => match scp_msg {
                                // Collect values submitted from the client
                                SCPNodeTaskMessage::Value(value) => {
                                    pending_values.push(value.clone());
                                }

                                // Process an incoming SCP message
                                SCPNodeTaskMessage::Msg(msg) => {
                                    incoming_msg_option = Some(msg);
                                }

                                // Stop the thread
                                SCPNodeTaskMessage::StopTrigger => {
                                    break 'main_loop;
                                }
                            },
                            Err(_) => {
                                // Yield to other threads when we don't get a new message
                                std::thread::yield_now();
                            }
                        };

                        // Propose pending values submitted to our node
                        if !pending_values.is_empty() {
                            let values_to_propose: BTreeSet<String> = pending_values
                                .iter()
                                .take(max_slot_proposed_values)
                                .cloned()
                                .collect();

                            let outgoing_msg: Option<Msg<String>> = thread_local_node
                                .propose_values(values_to_propose)
                                .expect("propose_values() failed");

                            if let Some(outgoing_msg) = outgoing_msg {
                                (broadcast_msg_fn)(logger.clone(), outgoing_msg);
                                total_broadcasts += 1;
                            }
                        }

                        // Process incoming consensus message, which might be for a future slot
                        if let Some(msg) = incoming_msg_option {
                            let outgoing_msg: Option<Msg<String>> = thread_local_node
                                .handle_message(&msg)
                                .expect("handle_message() failed");

                            if let Some(outgoing_msg) = outgoing_msg {
                                (broadcast_msg_fn)(logger.clone(), outgoing_msg);
                                total_broadcasts += 1;
                            }
                        }

                        // Process timeouts (for all slots)
                        let timeout_msgs: Vec<Msg<String>> =
                            thread_local_node.process_timeouts().into_iter().collect();

                        for outgoing_msg in timeout_msgs {
                            (broadcast_msg_fn)(logger.clone(), outgoing_msg);
                            total_broadcasts += 1;
                        }

                        // Check if the current slot is done
                        if let Some(new_block) =
                            thread_local_node.get_externalized_values(current_slot as SlotIndex)
                        {
                            let externalized_values: HashSet<String> =
                                new_block.iter().cloned().collect();

                            // Continue proposing only values that were not externalized.
                            pending_values.retain(|v| !externalized_values.contains(v));

                            let mut locked_shared_data = thread_shared_data
                                .lock()
                                .expect("thread_shared_data lock failed");

                            locked_shared_data.ledger.push(new_block);

                            let ledger_size = locked_shared_data.ledger_size();

                            drop(locked_shared_data);

                            log::trace!(
                                logger,
                                "(  ledger ) node {} slot {} : {} new, {} total, {} pending",
                                node_config.name,
                                current_slot as SlotIndex,
                                externalized_values.len(),
                                ledger_size,
                                pending_values.len(),
                            );

                            current_slot += 1;
                        }
                    }
                    log::info!(
                        logger,
                        "thread results: {},{},{}",
                        node_config.name,
                        total_broadcasts,
                        current_slot,
                    );
                })
                .expect("failed spawning SCPNode thread")
        };

        (scp_node, join_handle)
    }

    /// Push value to this node's consensus task.
    pub fn send_value(&self, value: &str) {
        match self
            .sender
            .try_send(SCPNodeTaskMessage::Value(value.to_owned()))
        {
            Ok(_) => {}
            Err(err) => match err {
                crossbeam_channel::TrySendError::Disconnected(_) => {}
                _ => {
                    panic!("send_value failed: {:?}", err);
                }
            },
        }
    }

    /// Feed message from the network to this node's consensus task.
    pub fn send_msg(&self, msg: Arc<Msg<String>>) {
        match self.sender.try_send(SCPNodeTaskMessage::Msg(msg)) {
            Ok(_) => {}
            Err(err) => match err {
                crossbeam_channel::TrySendError::Disconnected(_) => {}
                _ => {
                    panic!("send_msg failed: {:?}", err);
                }
            },
        }
    }

    pub fn send_stop(&self) {
        match self.sender.try_send(SCPNodeTaskMessage::StopTrigger) {
            Ok(_) => {}
            Err(err) => match err {
                crossbeam_channel::TrySendError::Disconnected(_) => {}
                _ => {
                    panic!("send_stop failed: {:?}", err);
                }
            },
        }
    }
}

///////////////////////////////////////////////////////////////////////////////
/// Test Helpers
///////////////////////////////////////////////////////////////////////////////

/// Support skipping slow tests based on environment variables
pub fn skip_slow_tests() -> bool {
    std::env::var("SKIP_SLOW_TESTS") == Ok("1".to_string())
}

/// Injects values to a network and waits for completion
pub fn build_and_test(network_config: &NetworkConfig, test_options: &TestOptions, logger: Logger) {
    let simulation = SCPNetwork::new(network_config, test_options, logger.clone());

    if test_options.submit_in_parallel {
        log::info!(
            logger,
            "( testing ) begin test for {} with {} values in parallel",
            network_config.name,
            test_options.values_to_submit,
        );
    } else {
        log::info!(
            logger,
            "( testing ) begin test for {} with {} values in sequence",
            network_config.name,
            test_options.values_to_submit,
        );
    }

    let start = Instant::now();

    let mut rng = mc_util_test_helper::get_seeded_rng();
    let mut values = Vec::<String>::with_capacity(test_options.values_to_submit);
    for _i in 0..test_options.values_to_submit {
        let value = mc_util_test_helper::random_str(&mut rng, CHARACTERS_PER_VALUE);
        values.push(value);
    }

    log::info!(
        simulation.logger,
        "( testing ) finished generating {} values",
        test_options.values_to_submit
    );

    // get a vector of the node_ids
    let node_ids: Vec<NodeID> = network_config.nodes.iter().map(|n| n.id.clone()).collect();

    // check that all ledgers start empty
    for n in 0..network_config.nodes.len() {
        assert!(simulation.get_ledger_size(&node_ids[n]) == 0);
    }

    // push values
    let mut last_log = Instant::now();
    for i in 0..test_options.values_to_submit {
        let start = Instant::now();

        if test_options.submit_in_parallel {
            // simulate broadcast of values to all nodes in parallel
            for n in 0..network_config.nodes.len() {
                simulation.push_value(&node_ids[n], &values[i]);
            }
        } else {
            // submit values to nodes in sequence
            let n = i % network_config.nodes.len();
            simulation.push_value(&node_ids[n], &values[i]);
        }

        if last_log.elapsed().as_millis() > 999 {
            log::info!(
                simulation.logger,
                "( testing ) pushed {}/{} values",
                i,
                test_options.values_to_submit
            );
            last_log = Instant::now();
        }

        let elapsed_duration = Instant::now().duration_since(start);
        let target_duration = Duration::from_micros(1_000_000 / test_options.submissions_per_sec);
        if let Some(extra_delay) = target_duration.checked_sub(elapsed_duration) {
            std::thread::sleep(extra_delay);
        }
    }

    // report end of value push
    log::info!(
        simulation.logger,
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
                    simulation.logger,
                    "( testing ) failed to externalize all values within {} sec at node {}!",
                    test_options.allowed_test_time.as_secs(),
                    simulation
                        .names_map
                        .get(node_id)
                        .expect("could not find node_id"),
                );
                // panic
                panic!("test failed due to timeout");
            }

            let num_externalized_values = simulation.get_ledger_size(&node_id);
            if num_externalized_values >= test_options.values_to_submit {
                // if the validity_fn does not enforce unique values, we can end up
                // with values that appear in multiple slots. This is not a problem
                // provided that all the nodes externalize the same ledger!
                log::info!(
                    simulation.logger,
                    "( testing ) externalized {}/{} values at node {}",
                    num_externalized_values,
                    test_options.values_to_submit,
                    simulation
                        .names_map
                        .get(node_id)
                        .expect("could not find node_id"),
                );

                if num_externalized_values > test_options.values_to_submit {
                    log::warn!(
                        simulation.logger,
                        "( testing ) externalized extra values at node {}",
                        simulation
                            .names_map
                            .get(node_id)
                            .expect("could not find node_id"),
                    );
                }

                break;
            }

            if last_log.elapsed().as_millis() > 999 {
                log::info!(
                    simulation.logger,
                    "( testing ) externalized {}/{} values at node {}",
                    num_externalized_values,
                    test_options.values_to_submit,
                    simulation
                        .names_map
                        .get(node_id)
                        .expect("could not find node_id"),
                );
                last_log = Instant::now();
            }
        }

        // check that all submitted values are externalized at least once
        // duplicate values are possible depending on validity_fn
        let externalized_values_hashset = simulation
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
                simulation.logger,
                "node {} externalized wrong values! missing: {:?}, unexpected: {:?}",
                simulation
                    .names_map
                    .get(node_id)
                    .expect("could not find node_id"),
                missing_values,
                unexpected_values,
            );
            // panic
            panic!("test failed due to wrong values being externalized");
        }
    }

    // Check that all of the externalized ledgers match block-by-block
    let first_node_ledger = simulation.get_ledger(&node_ids[0]);
    for node_id in node_ids.iter().skip(1) {
        let other_node_ledger = simulation.get_ledger(&node_id);

        if first_node_ledger.len() != other_node_ledger.len() {
            log::error!(
                simulation.logger,
                "first_node_ledger.len() != other_node_ledger.len() in run_test()"
            );
            // panic
            panic!("test failed due to ledgers having different block count");
        }

        for block_index in 0..first_node_ledger.len() {
            if first_node_ledger.get(block_index) != other_node_ledger.get(block_index) {
                log::error!(
                    simulation.logger,
                    "first_node_ledger block differs from other_node_ledger block at block {}",
                    block_index,
                );
                //panic
                panic!("test failed due to ledgers having different block content");
            }
        }
    }

    // drop the simulation here so that MESSAGES log statements appear before
    // results
    drop(simulation);

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
