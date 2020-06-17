// Copyright (c) 2018-2020 MobileCoin Inc.

// Thread-based simulation for consensus networks.

// We allow dead code because not all integration tests use all of the common code.
// https://github.com/rust-lang/rust/issues/46379
#![allow(dead_code)]

use mc_common::{
    logger::{log, o, Logger},
    HashMap, HashSet, NodeID,
};
use mc_consensus_scp::{
    core_types::{CombineFn, SlotIndex, ValidityFn},
    msg::Msg,
    node::{Node, ScpNode},
    quorum_set::QuorumSet,
    test_utils,
};
use std::{
    collections::BTreeSet,
    iter::FromIterator,
    sync::{Arc, Mutex},
    thread,
    thread::JoinHandle,
    time::{Duration, Instant},
};

pub mod cyclic_topology;
pub mod mesh_topology;
pub mod optimization;

// Test values are random strings of this length.
const CHARACTERS_PER_VALUE: usize = 10;

// Controls test parameters
#[derive(Clone)]
pub struct TestOptions {
    /// Values can be submitted to all nodes in parallel (true) or to nodes in sequential order (false)
    pub submit_in_parallel: bool,

    /// Total number of values to submit. Tests run until all values are externalized by all nodes.
    /// N.B. if the validity fn doesn't enforce unique values, it's possible a value will appear in
    /// multiple places in the ledger, and that the ledger will contain more than values_to_submit
    pub values_to_submit: usize,

    /// Approximate rate that values are submitted to nodes.
    pub submissions_per_sec: u64,

    /// We nominate up to this many values from our pending set per slot.
    pub max_pending_values_to_nominate: usize,

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
    pub combine_fn: CombineFn<String>,
}

impl TestOptions {
    pub fn new() -> Self {
        Self {
            submit_in_parallel: true,
            values_to_submit: 5000,
            submissions_per_sec: 10000,
            max_pending_values_to_nominate: 100,
            allowed_test_time: Duration::from_secs(300),
            log_flush_delay: Duration::from_millis(50),
            scp_timebase: Duration::from_millis(1000),
            validity_fn: Arc::new(test_utils::trivial_validity_fn::<String>),
            combine_fn: Arc::new(test_utils::trivial_combine_fn::<String>),
        }
    }
}

// Describes a network of nodes for simulation
#[derive(Clone)]
pub struct Network {
    name: String,
    nodes: Vec<NodeOptions>,
}

impl Network {
    pub fn new(name: String, nodes: Vec<NodeOptions>) -> Self {
        Self { name, nodes }
    }
}

// Describes one simulated node
#[derive(Clone)]
pub struct NodeOptions {
    peers: Vec<u32>,
    validators: Vec<u32>,
    k: u32,
}

impl NodeOptions {
    pub fn new(peers: Vec<u32>, validators: Vec<u32>, k: u32) -> Self {
        Self {
            peers,
            validators,
            k,
        }
    }
}

pub struct SimulatedNetwork {
    nodes_map: Arc<Mutex<HashMap<NodeID, SimulatedNode>>>,
    thread_handles: HashMap<NodeID, Option<JoinHandle<()>>>,
    nodes_shared_data: HashMap<NodeID, Arc<Mutex<SimulatedNodeSharedData>>>,
    logger: Logger,
}

impl SimulatedNetwork {
    // creates a new network simulation
    pub fn new(network: &Network, test_options: &TestOptions, logger: Logger) -> Self {
        let mut simulation = SimulatedNetwork {
            nodes_map: Arc::new(Mutex::new(HashMap::default())),
            thread_handles: HashMap::default(),
            nodes_shared_data: HashMap::default(),
            logger: logger.clone(),
        };

        for (node_index, options_for_this_node) in network.nodes.iter().enumerate() {
            let validators = options_for_this_node
                .validators
                .iter()
                .map(|node_index| test_utils::test_node_id(*node_index as u32))
                .collect::<Vec<NodeID>>();

            let qs = QuorumSet::new_with_node_ids(options_for_this_node.k, validators);

            let peers = options_for_this_node
                .peers
                .iter()
                .map(|node_index| test_utils::test_node_id(*node_index as u32))
                .collect::<HashSet<NodeID>>();

            let node_id = test_utils::test_node_id(node_index as u32);

            assert!(!peers.contains(&node_id));

            let nodes_map_clone: Arc<Mutex<HashMap<NodeID, SimulatedNode>>> =
                { Arc::clone(&simulation.nodes_map) };

            let thread_name_for_this_node = format!("{}-{}", network.name, node_index);

            let (node, thread_handle) = SimulatedNode::new(
                thread_name_for_this_node,
                node_id.clone(),
                qs,
                test_options,
                Arc::new(move |logger, msg| {
                    SimulatedNetwork::broadcast_msg(logger, &nodes_map_clone, &peers, msg)
                }),
                logger.new(o!("mc.local_node_id" => node_id.to_string())),
            );
            simulation
                .thread_handles
                .insert(node_id.clone(), thread_handle);
            simulation
                .nodes_shared_data
                .insert(node_id.clone(), node.shared_data.clone());
            simulation
                .nodes_map
                .lock()
                .expect("lock failed on nodes_map inserting node")
                .insert(node_id.clone(), node);
        }

        simulation
    }

    fn stop_all(&mut self) {
        let mut nodes_map = self
            .nodes_map
            .lock()
            .expect("lock failed on nodes_map in stop_all");
        let num_nodes = nodes_map.len();
        for node_num in 0..num_nodes {
            nodes_map
                .get_mut(&test_utils::test_node_id(node_num as u32))
                .expect("could not find node_id in nodes_map")
                .send_stop();
        }
        drop(nodes_map);

        // now join the threads
        for node_num in 0..num_nodes {
            let node_id = &test_utils::test_node_id(node_num as u32);
            self.thread_handles
                .remove(node_id)
                .expect("failed to get handle option from thread_handles")
                .expect("thread handle is missing")
                .join()
                .expect("SimulatedNode join failed");
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
        self.nodes_shared_data
            .get(node_id)
            .expect("could not find node_id in nodes_shared_data")
            .lock()
            .expect("lock failed on shared_data getting ledger")
            .ledger
            .clone()
    }

    fn get_ledger_size(&self, node_id: &NodeID) -> usize {
        self.nodes_shared_data
            .get(node_id)
            .expect("could not find node_id in nodes_shared_data")
            .lock()
            .expect("lock failed on shared_data getting ledger size")
            .ledger_size()
    }

    fn broadcast_msg(
        logger: Logger,
        nodes_map: &Arc<Mutex<HashMap<NodeID, SimulatedNode>>>,
        peers: &HashSet<NodeID>,
        msg: Msg<String>,
    ) {
        let mut nodes_map = nodes_map
            .lock()
            .expect("lock failed on nodes_map in broadcast");

        log::trace!(logger, "(broadcast) {}", msg.to_display());

        let amsg = Arc::new(msg);

        for peer_id in peers {
            nodes_map
                .get_mut(&peer_id)
                .expect("failed to get peer from nodes_map")
                .send_msg(amsg.clone());
        }
    }
}

impl Drop for SimulatedNetwork {
    fn drop(&mut self) {
        self.stop_all();
    }
}

enum SimulatedNodeTaskMessage {
    Value(String),
    Msg(Arc<Msg<String>>),
    StopTrigger,
}

// Node data shared between threads
#[derive(Clone)]
struct SimulatedNodeSharedData {
    pub ledger: Vec<Vec<String>>,
}

impl SimulatedNodeSharedData {
    pub fn ledger_size(&self) -> usize {
        self.ledger.iter().fold(0, |acc, block| acc + block.len())
    }
}

// A simulated validator node
struct SimulatedNode {
    sender: crossbeam_channel::Sender<SimulatedNodeTaskMessage>,
    shared_data: Arc<Mutex<SimulatedNodeSharedData>>,
}

impl SimulatedNode {
    fn new(
        thread_name: String,
        node_id: NodeID,
        quorum_set: QuorumSet,
        test_options: &TestOptions,
        broadcast_msg_fn: Arc<dyn Fn(Logger, Msg<String>) + Sync + Send>,
        logger: Logger,
    ) -> (Self, Option<JoinHandle<()>>) {
        let (sender, receiver) = crossbeam_channel::unbounded();

        let simulated_node = Self {
            sender,
            shared_data: Arc::new(Mutex::new(SimulatedNodeSharedData { ledger: Vec::new() })),
        };

        let mut thread_local_node = Node::new(
            node_id.clone(),
            quorum_set,
            test_options.validity_fn.clone(),
            test_options.combine_fn.clone(),
            logger.clone(),
        );
        thread_local_node.scp_timebase = test_options.scp_timebase;

        let thread_shared_data = Arc::clone(&simulated_node.shared_data);

        // See byzantine_ledger.rs#L626
        let max_pending_values_to_nominate: usize = test_options.max_pending_values_to_nominate;
        let mut slot_nominated_values: HashSet<String> = HashSet::default();

        let mut current_slot: usize = 0;
        let mut total_broadcasts: u32 = 0;

        let thread_handle = Some(
            thread::Builder::new()
                .name(thread_name)
                .spawn(move || {
                    // All values that have not yet been externalized.
                    let mut pending_values: HashSet<String> = HashSet::default();

                    'main_loop: loop {
                        // See byzantine_ledger.rs#L546 - nominate before handling consensus msg
                        let mut incoming_msgs = Vec::<Arc<Msg<String>>>::with_capacity(1);

                        // Collect one incoming message using a non-blocking channel read
                        match receiver.try_recv() {
                            Ok(scp_msg) => match scp_msg {
                                // Collect values submitted from the client
                                SimulatedNodeTaskMessage::Value(value) => {
                                    pending_values.insert(value.clone());
                                }

                                // Process an incoming SCP message
                                SimulatedNodeTaskMessage::Msg(msg) => {
                                    incoming_msgs.push(msg);
                                }

                                // Stop the thread
                                SimulatedNodeTaskMessage::StopTrigger => {
                                    break 'main_loop;
                                }
                            },
                            Err(_) => {
                                // Yield to other threads when we don't get a new message
                                std::thread::yield_now();
                            }
                        };

                        // Nominate pending values submitted to our node
                        if (slot_nominated_values.len() < max_pending_values_to_nominate)
                            && !pending_values.is_empty()
                        {
                            let mut values: Vec<String> = pending_values.iter().cloned().collect();
                            values.sort();
                            values.truncate(max_pending_values_to_nominate);

                            // mc_common::HashSet does not support extend because of our enclave-safe HasherBuilder
                            let mut values_to_nominate: HashSet<String> =
                                values.iter().cloned().collect();

                            for v in slot_nominated_values.iter() {
                                values_to_nominate.remove(v);
                            }

                            if !values_to_nominate.is_empty() {
                                for v in values_to_nominate.iter() {
                                    slot_nominated_values.insert(v.clone());
                                }

                                let outgoing_msg: Option<Msg<String>> =
                                    thread_local_node
                                        .nominate(
                                            current_slot as SlotIndex,
                                            BTreeSet::from_iter(values_to_nominate),
                                        )
                                        .expect("nominate() failed");

                                if let Some(outgoing_msg) = outgoing_msg {
                                    (broadcast_msg_fn)(logger.clone(), outgoing_msg);
                                    total_broadcasts += 1;
                                }
                            }
                        }

                        // Process incoming consensus message, which might be for a future slot
                        for msg in incoming_msgs.iter() {
                            let outgoing_msg: Option<Msg<String>> =
                                thread_local_node.handle(msg).expect("handle_msg() failed");

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
                        let new_block:Vec<String> =
                            thread_local_node.get_externalized_values(current_slot as SlotIndex);

                        if !new_block.is_empty() {
                            // stop nominating the values we've externalized
                            for v in &new_block {
                                pending_values.remove(v);
                            }

                            let new_block_length = new_block.len();

                            let mut locked_shared_data = thread_shared_data
                                .lock()
                                .expect("thread_shared_data lock failed");

                            locked_shared_data.ledger.push(new_block);

                            let ledger_size = locked_shared_data.ledger_size();

                            drop(locked_shared_data);

                            log::trace!(
                                logger,
                                "(  ledger ) node {} slot {} : {} new, {} total, {} pending",
                                node_id,
                                current_slot as SlotIndex,
                                new_block_length,
                                ledger_size,
                                pending_values.len(),
                            );

                            current_slot += 1;
                            slot_nominated_values = HashSet::default();
                        }
                    }
                    log::info!(
                        logger,
                        "thread results: {},{},{}",
                        node_id,
                        total_broadcasts,
                        current_slot,
                    );
                })
                .expect("failed spawning SimulatedNode thread"),
        );

        (simulated_node, thread_handle)
    }

    /// Push value to this node's consensus task.
    pub fn send_value(&self, value: &str) {
        match self
            .sender
            .try_send(SimulatedNodeTaskMessage::Value(value.to_owned()))
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
        match self.sender.try_send(SimulatedNodeTaskMessage::Msg(msg)) {
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
        match self.sender.try_send(SimulatedNodeTaskMessage::StopTrigger) {
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
pub fn build_and_test(network: &Network, test_options: &TestOptions, logger: Logger) {
    let simulation = SimulatedNetwork::new(network, test_options, logger.clone());

    if test_options.submit_in_parallel {
        log::info!(
            logger,
            "( testing ) begin test for {} with {} values in parallel",
            network.name,
            test_options.values_to_submit,
        );
    } else {
        log::info!(
            logger,
            "( testing ) begin test for {} with {} values in sequence",
            network.name,
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

    let num_nodes: usize = {
        simulation
            .nodes_map
            .lock()
            .expect("lock failed on nodes_map getting length")
            .len()
    };

    // pre-compute node_ids
    let mut node_ids = Vec::<NodeID>::with_capacity(num_nodes);
    for n in 0..num_nodes {
        node_ids.push(test_utils::test_node_id(n as u32));
    }

    // check that all ledgers start empty
    for node_id in node_ids.iter() {
        assert!(simulation.get_ledger_size(&node_id) == 0);
    }

    // push values
    let mut last_log = Instant::now();
    for i in 0..test_options.values_to_submit {
        let start = Instant::now();

        if test_options.submit_in_parallel {
            // simulate broadcast of values to all nodes in parallel
            for n in 0..num_nodes {
                simulation.push_value(&node_ids[n], &values[i]);
            }
        } else {
            // submit values to nodes in sequence
            let n = i % num_nodes;
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
                    node_id,
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
                    node_id
                );

                if num_externalized_values > test_options.values_to_submit {
                    log::warn!(
                        simulation.logger,
                        "( testing ) externalized extra values at node {}",
                        node_id
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
                    node_id
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
                node_id,
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

    // drop the simulation here so that MESSAGES log statements appear before results
    drop(simulation);

    // csv for scripting use
    log::info!(
        logger,
        "test results: {},{},{},{},{},{}",
        network.name,
        start.elapsed().as_millis(),
        values.len(),
        test_options.submissions_per_sec,
        test_options.max_pending_values_to_nominate,
        test_options.scp_timebase.as_millis(),
    );

    // human readable throughput
    log::info!(
        logger,
        "test completed for {}: {:?} (avg {} tx/s)",
        network.name,
        start.elapsed(),
        (1_000_000 * values.len() as u128) / start.elapsed().as_micros(),
    );

    // allow log to flush
    std::thread::sleep(test_options.log_flush_delay);
}
