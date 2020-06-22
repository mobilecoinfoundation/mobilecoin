// Copyright (c) 2018-2020 MobileCoin Inc.

use mc_common::{
    logger::{log, o, Logger},
    HashMap, HashSet, NodeID,
};
use mc_consensus_scp::{
    core_types::{CombineFn, SlotIndex, ValidityFn},
    msg::Msg,
    node::{Node, ScpNode},
    quorum_set::{QuorumSet,QuorumSetMember},
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

use pest::parser::Parser;
use pest_derive::Parser;

/// Helper for parsing quorum sets from string representations using "pest"
/// Used in crate tests.
#[derive(Parser)]
#[grammar = "quorum_set_parser.pest"]
pub struct QuorumSetParser;

// Controls test parameters
#[derive(Clone)]
pub struct TestOptions {
    /// Values can be submitted to all nodes in parallel (true) or to nodes in sequential order (false)
    pub submit_in_parallel: bool,

    /// Total number of values to submit. Tests run until all values are externalized by all nodes.
    pub values_to_submit: usize,

    /// Approximate rate that values are submitted to nodes.
    pub submissions_per_sec: u64,

    /// We allow only a single proposal per slot, with up to this many values.
    pub max_values_per_slot: usize,

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
            values_to_submit: 1000,
            submissions_per_sec: 500,
            max_values_per_slot: 100,
            allowed_test_time: Duration::from_secs(300),
            log_flush_delay: Duration::from_millis(50),
            scp_timebase: Duration::from_millis(1000),
            validity_fn: Arc::new(test_utils::trivial_validity_fn::<String>),
            combine_fn: Arc::new(test_utils::trivial_combine_fn::<String>),
        }
    }
}

pub struct NodeOptions {
    thread_name: String,
    peers: Vec<u32>,
    validators: Vec<u32>,
    k: u32,
}

impl NodeOptions {
    pub fn new(thread_name: String, peers: Vec<u32>, validators: Vec<u32>, k: u32) -> Self {
        Self {
            thread_name,
            peers,
            validators,
            k,
        }
    }
}

pub struct SCPNetwork {
    nodes_map: Arc<Mutex<HashMap<NodeID, SCPNode>>>,
    thread_handles: HashMap<NodeID, Option<JoinHandle<()>>>,
    nodes_shared_data: HashMap<NodeID, Arc<Mutex<SCPNodeSharedData>>>,
    logger: Logger,
}

impl SCPNetwork {
    // creates a network based on node_options
    pub fn new(node_options: Vec<NodeOptions>, test_options: TestOptions, logger: Logger) -> Self {
        let mut network = SCPNetwork {
            nodes_map: Arc::new(Mutex::new(HashMap::default())),
            thread_handles: HashMap::default(),
            nodes_shared_data: HashMap::default(),
            logger: logger.clone(),
        };

        for (node_id, options_for_this_node) in node_options.iter().enumerate() {
            let validators = options_for_this_node
                .validators
                .iter()
                .map(|id| test_utils::test_node_id(*id as u32))
                .collect::<Vec<NodeID>>();

            let qs = QuorumSet::new_with_node_ids(options_for_this_node.k, validators);

            let peers = options_for_this_node
                .peers
                .iter()
                .map(|id| test_utils::test_node_id(*id as u32))
                .collect::<HashSet<NodeID>>();

            let node_id = test_utils::test_node_id(node_id as u32);

            assert!(!peers.contains(&node_id));

            let nodes_map_clone: Arc<Mutex<HashMap<NodeID, SCPNode>>> =
                { Arc::clone(&network.nodes_map) };

            let (node, thread_handle) = SCPNode::new(
                options_for_this_node.thread_name.clone(),
                node_id.clone(),
                qs,
                test_options.clone(),
                Arc::new(move |logger, msg| {
                    SCPNetwork::broadcast_msg(logger, &nodes_map_clone, &peers, msg)
                }),
                logger.new(o!("mc.local_node_id" => node_id.to_string())),
            );
            network
                .thread_handles
                .insert(node_id.clone(), thread_handle);
            network
                .nodes_shared_data
                .insert(node_id.clone(), node.shared_data.clone());
            network
                .nodes_map
                .lock()
                .expect("lock failed on nodes_map inserting node")
                .insert(node_id.clone(), node);
        }

        network
    }

    pub fn stop_all(&mut self) {
        let mut nodes_map = self
            .nodes_map
            .lock()
            .expect("lock failed on nodes_map in stop_all");
        let num_nodes = nodes_map.len();
        for node_num in 0..num_nodes {
            nodes_map
                .get_mut(&test_utils::test_node_id(node_num as u32))
                .expect("failed to get node from nodes_map")
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
                .expect("SCPNode join failed");
        }
    }

    pub fn push_value(&self, node_id: &NodeID, value: &str) {
        let node: &SCPNode = {
            &self
                .nodes_map
                .lock()
                .expect("lock failed on nodes_map getting node")[node_id]
        };
        node.send_value(value);
    }

    pub fn get_shared_data(&self, node_id: &NodeID) -> SCPNodeSharedData {
        self.nodes_shared_data[node_id]
            .lock()
            .expect("lock failed on shared_data getting clone")
            .clone()
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

        log::trace!(logger, "(broadcast) {}", msg.to_display(),);

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

// Data that's shared between tests and the node's thread
#[derive(Clone)]
pub struct SCPNodeSharedData {
    pub ledger: Vec<Vec<String>>,
}

impl SCPNodeSharedData {
    pub fn get_all_values(&self) -> Vec<String> {
        let mut ledger_copy = Vec::new();
        for block in self.ledger.iter() {
            ledger_copy.extend(block.clone())
        }
        ledger_copy
    }

    pub fn total_values(&self) -> usize {
        self.ledger.iter().fold(0, |acc, block| acc + block.len())
    }
}

struct SCPNode {
    local_node: Arc<Mutex<Node<String, test_utils::TransactionValidationError>>>,
    sender: crossbeam_channel::Sender<SCPNodeTaskMessage>,
    shared_data: Arc<Mutex<SCPNodeSharedData>>,
}

impl SCPNode {
    fn new(
        thread_name: String,
        node_id: NodeID,
        quorum_set: QuorumSet,
        test_options: TestOptions,
        broadcast_msg_fn: Arc<dyn Fn(Logger, Msg<String>) + Sync + Send>,
        logger: Logger,
    ) -> (Self, Option<JoinHandle<()>>) {
        let (sender, receiver) = crossbeam_channel::unbounded();
        let local_node = Arc::new(Mutex::new(Node::new(
            node_id.clone(),
            quorum_set,
            test_options.validity_fn.clone(),
            test_options.combine_fn.clone(),
            logger.clone(),
        )));

        local_node
            .lock()
            .expect("lock failed on local node setting scp_timebase_millis")
            .scp_timebase = test_options.scp_timebase;

        let node = Self {
            local_node,
            sender,
            shared_data: Arc::new(Mutex::new(SCPNodeSharedData { ledger: Vec::new() })),
        };

        let thread_shared_data = Arc::clone(&node.shared_data);
        let thread_local_node = Arc::clone(&node.local_node);

        // See byzantine_ledger.rs. Each slot nominates at most MAX_PENDING_VALUES_TO_NOMINATE values.
        let mut nominated_values: usize = 0;
        let mut current_slot: usize = 0;
        let mut total_broadcasts: u32 = 0;

        let thread_handle = Some(
            thread::Builder::new()
                .name(thread_name)
                .spawn(move || {
                    // All values that have not yet been externalized.
                    let mut pending_values: HashSet<String> = HashSet::default();

                    'main_loop: loop {
                        // Collect and process any messages we have received
                        let mut incoming_msgs = Vec::<Arc<Msg<String>>>::new();

                        // Handle one incoming message based on it's type
                        match receiver.try_recv() {
                            // non-blocking read
                            Ok(scp_msg) => match scp_msg {
                                // Value submitted by a client
                                SCPNodeTaskMessage::Value(value) => {
                                    // Maintain invariant that pending_values contains all values
                                    // that have not yet been externalized.
                                    pending_values.insert(value.clone());
                                }

                                // SCP Statement
                                SCPNodeTaskMessage::Msg(msg) => {
                                    // Collect.
                                    incoming_msgs.push(msg);
                                }

                                // Request to stop thread
                                SCPNodeTaskMessage::StopTrigger => {
                                    break 'main_loop;
                                }
                            },
                            Err(_) => {
                                // Yield to other threads when we don't get a new message
                                // This improves performance significantly.
                                std::thread::yield_now();
                            }
                        };

                        let incoming_msgs_count = incoming_msgs.len();

                        if !(incoming_msgs_count == 0 || incoming_msgs_count == 1) {
                            log::error!(logger, "incoming_msgs_count > 1");
                            // panic
                            assert!(incoming_msgs_count == 0 || incoming_msgs_count == 1);
                        }

                        // Process values submitted to our node
                        if (nominated_values < test_options.max_values_per_slot)
                            && !pending_values.is_empty()
                        {
                            let mut vals = pending_values.iter().cloned().collect::<Vec<String>>();
                            vals.sort();
                            vals.truncate(test_options.max_values_per_slot - nominated_values);
                            nominated_values += vals.len();

                            let outgoing_msg: Option<Msg<String>> = {
                                thread_local_node
                                    .lock()
                                    .expect("lock failed on node nominating value")
                                    .nominate(current_slot as SlotIndex, BTreeSet::from_iter(vals))
                                    .expect("node.nominate() failed")
                            };

                            if let Some(outgoing_msg) = outgoing_msg {
                                (broadcast_msg_fn)(logger.clone(), outgoing_msg);
                                total_broadcasts += 1;
                            }
                        }

                        // Process the incoming messages and re-broadcast to network
                        for msg in incoming_msgs.iter() {
                            let outgoing_msg: Option<Msg<String>> = {
                                thread_local_node
                                    .lock()
                                    .expect("lock failed on node nominating value")
                                    .handle(msg)
                                    .expect("node.handle_msg() failed")
                            };

                            if let Some(outgoing_msg) = outgoing_msg {
                                (broadcast_msg_fn)(logger.clone(), outgoing_msg);
                                total_broadcasts += 1;
                            }
                        }

                        // Process timeouts (for all slots)
                        let timeout_msgs: Vec<Msg<String>> = {
                            thread_local_node
                                .lock()
                                .expect("lock failed on node processing timeouts in thread")
                                .process_timeouts()
                                .into_iter()
                                .collect()
                        };

                        for outgoing_msg in timeout_msgs {
                            (broadcast_msg_fn)(logger.clone(), outgoing_msg);
                            total_broadcasts += 1;
                        }

                        // See if we're done with the current slot
                        let ext_vals: Vec<String> = {
                            thread_local_node
                                .lock()
                                .expect("lock failed on node getting ext_vals in thread")
                                .get_externalized_values(current_slot as SlotIndex)
                        };

                        if !ext_vals.is_empty() {
                            // Stop proposing/nominating any values that we have externalized

                            let externalized_values_as_set: HashSet<String> =
                                ext_vals.iter().cloned().collect();

                            let remaining_values: HashSet<String> = pending_values
                                .difference(&externalized_values_as_set)
                                .cloned()
                                .collect();

                            let last_slot_values = ext_vals.len();

                            let mut shared_data = thread_shared_data
                                .lock()
                                .expect("lock failed on shared_data in thread");
                            shared_data.ledger.push(ext_vals);
                            let total_values = shared_data.total_values();

                            log::trace!(
                                logger,
                                "(  ledger ) node {} slot {} : {} new, {} total, {} pending",
                                node_id,
                                current_slot as SlotIndex,
                                last_slot_values,
                                total_values,
                                remaining_values.len(),
                            );

                            pending_values = remaining_values;
                            current_slot += 1;
                            nominated_values = 0;
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
                .expect("failed spawning SCPNode thread"),
        );

        (node, thread_handle)
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
/// Test Helper
///////////////////////////////////////////////////////////////////////////////

/// Injects values to a network and waits for completion
pub fn run_test(network: SCPNetwork, network_name: &str, options: TestOptions, logger: Logger) {
    if options.submit_in_parallel {
        log::info!(
            logger,
            "( testing ) begin test for {} with {} values in parallel",
            network_name,
            options.values_to_submit,
        );
    } else {
        log::info!(
            logger,
            "( testing ) begin test for {} with {} values in sequence",
            network_name,
            options.values_to_submit,
        );
    }

    let start = Instant::now();

    let mut rng = mc_util_test_helper::get_seeded_rng();
    let mut values = Vec::<String>::with_capacity(options.values_to_submit);
    for _i in 0..options.values_to_submit {
        let value = mc_util_test_helper::random_str(&mut rng, 20);
        values.push(value);
    }

    log::info!(
        network.logger,
        "( testing ) finished generating {} values",
        options.values_to_submit
    );

    let num_nodes: usize = {
        network
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

    let mut last_log = Instant::now();
    let mut pushed_values = 0;
    for i in 0..options.values_to_submit {
        let start = Instant::now();

        if options.submit_in_parallel {
            // simulate broadcast of values to all nodes in parallel
            for n in 0..num_nodes {
                network.push_value(&node_ids[n], &values[i]);
            }
        } else {
            // submit values to nodes in sequence
            let n = i % num_nodes;
            network.push_value(&node_ids[n], &values[i]);
        }

        if last_log.elapsed().as_millis() > 999 {
            log::info!(
                network.logger,
                "( testing ) pushed {}/{} values",
                i,
                options.values_to_submit
            );
            last_log = Instant::now();
        }

        let elapsed_duration = Instant::now().duration_since(start);
        let target_duration = Duration::from_micros(1_000_000 / options.submissions_per_sec);
        if let Some(extra_delay) = target_duration.checked_sub(elapsed_duration) {
            std::thread::sleep(extra_delay);
        }

        pushed_values += 1;
    }

    // report end of value push
    log::info!(
        network.logger,
        "( testing ) pushed {}/{} values",
        pushed_values,
        options.values_to_submit
    );

    // abort testing if we exceed allowed time
    let deadline = Instant::now() + options.allowed_test_time;

    // Check that the values got added to the nodes
    for n in 0..num_nodes as u32 {
        // Wait for test_node_id(n) to externalize all values
        let node_id = test_utils::test_node_id(n);
        let mut prev_num_values = 0;
        let mut last_log = Instant::now();
        loop {
            if Instant::now() > deadline {
                log::error!(
                    network.logger,
                    "( testing ) failed to externalize all values within {} sec at node {}!",
                    options.allowed_test_time.as_secs(),
                    node_id,
                );
                // panic
                panic!("TEST FAILED DUE TO TIMEOUT");
            }

            let cur_num_values = network.get_shared_data(&node_id).total_values();
            if cur_num_values >= values.len() {
                log::info!(
                    network.logger,
                    "( testing ) externalized {}/{} values at node {}",
                    cur_num_values,
                    values.len(),
                    node_id
                );
                break;
            }

            if prev_num_values != cur_num_values {
                assert!(cur_num_values > prev_num_values);
                prev_num_values = cur_num_values;
            }

            if last_log.elapsed().as_millis() > 999 {
                log::info!(
                    network.logger,
                    "( testing ) externalized {}/{} values at node {}",
                    cur_num_values,
                    values.len(),
                    node_id
                );
                last_log = Instant::now();
            }
        }

        let all_values_are_correct = {
            values.iter().cloned().collect::<HashSet<String>>()
                == network
                    .get_shared_data(&node_id)
                    .get_all_values()
                    .iter()
                    .cloned()
                    .collect::<HashSet<String>>()
        };

        if !all_values_are_correct {
            log::error!(
                network.logger,
                "( testing ) node {} externalized wrong values!",
                node_id
            );
            // panic
            assert!(all_values_are_correct);
        }
    }

    // Check all blocks in the ledger are the same
    let node0_data = network.get_shared_data(&test_utils::test_node_id(0)).ledger;
    if node0_data.is_empty() {
        log::error!(network.logger, "node0_data is empty in run_test()");
        // panic
        assert!(!node0_data.is_empty());
    }

    for node_num in 0..num_nodes {
        let node_data = network
            .get_shared_data(&test_utils::test_node_id(node_num as u32))
            .ledger;

        if node0_data.len() != node_data.len() {
            log::error!(
                network.logger,
                "node0_data.len() != node_data.len() in run_test()"
            );
            // panic
            assert_eq!(node0_data.len(), node_data.len());
        }

        for block_num in 0..node0_data.len() {
            if node0_data.get(block_num) != node_data.get(block_num) {
                log::error!(
                    network.logger,
                    "node0_data.get(block_num) != node_data.get(block_num) in run_test()"
                );
                //panic
                assert_eq!(node0_data.get(block_num), node_data.get(block_num));
            }
        }
    }

    // drop the network here so that MESSAGES log statements appear before results
    drop(network);

    // csv for scripting use
    log::info!(
        logger,
        "test results: {},{},{},{},{},{}",
        network_name,
        start.elapsed().as_millis(),
        values.len(),
        options.submissions_per_sec,
        options.max_values_per_slot,
        options.scp_timebase.as_millis(),
    );

    // human readable throughput
    log::info!(
        logger,
        "test completed for {}: {:?} (avg {} tx/s)",
        network_name,
        start.elapsed(),
        (1_000_000 * values.len() as u128) / start.elapsed().as_micros(),
    );

    // allow log to flush
    std::thread::sleep(options.log_flush_delay);
}

///////////////////////////////////////////////////////////////////////////////
/// QuorumSet Parsing
///////////////////////////////////////////////////////////////////////////////

/// Generates a QuorumSet<u32> from a string using pest parser
pub fn qs_u32_from_string(
    quorum_set_string: &str,
) -> Result<QuorumSet<u32>, pest::error::Error<Rule>> {
    let inner_rules = QuorumSetParser::parse(Rule::quorum_set, quorum_set_string)?
        .next()
        .unwrap()
        .into_inner();
    let mut quorum_set: QuorumSet<u32> = QuorumSet::empty();
    for pair in inner_rules {
        match pair.as_rule() {
            Rule::empty_set => {
                return Ok(quorum_set);
            }
            Rule::threshold => {
                let threshold_string = pair.into_inner().next().unwrap().as_str();
                quorum_set.threshold = str::parse(threshold_string).unwrap();
            }
            Rule::members => {
                for member in pair.into_inner() {
                    match member.as_rule() {
                        Rule::node => {
                            let node: u32 = str::parse::<u32>(member.as_str()).unwrap();
                            quorum_set.members.push(QuorumSetMember::Node(node));
                        }
                        Rule::quorum_set => {
                            let inner_set = qs_u32_from_string(member.as_str())?;
                            quorum_set
                                .members
                                .push(QuorumSetMember::InnerSet(inner_set));
                        }
                        _ => panic!("unexpected rule!"),
                    }
                }
            }
            _ => panic!("unexpected rule!"),
        }
    }
    Ok(quorum_set)
}

/// Generates a QuorumSet<NodeID> from a string using pest parser
pub fn qs_from_string(
    quorum_set_string: &str,
) -> Result<QuorumSet<NodeID>, pest::error::Error<Rule>> {
    let inner_rules = QuorumSetParser::parse(Rule::quorum_set, quorum_set_string)?
        .next()
        .unwrap()
        .into_inner();
    let mut quorum_set: QuorumSet<NodeID> = QuorumSet::empty();
    for pair in inner_rules {
        match pair.as_rule() {
            Rule::empty_set => {
                return Ok(quorum_set);
            }
            Rule::threshold => {
                let threshold_string = pair.into_inner().next().unwrap().as_str();
                quorum_set.threshold = str::parse(threshold_string).unwrap();
            }
            Rule::members => {
                for member in pair.into_inner() {
                    match member.as_rule() {
                        Rule::node => {
                            let node: u32 = str::parse::<u32>(member.as_str()).unwrap();
                            let node_id = test_utils::test_node_id(node);
                            quorum_set.members.push(QuorumSetMember::Node(node_id));
                        }
                        Rule::quorum_set => {
                            let inner_set = qs_from_string(member.as_str())?;
                            quorum_set
                                .members
                                .push(QuorumSetMember::InnerSet(inner_set));
                        }
                        _ => panic!("unexpected rule!"),
                    }
                }
            }
            _ => panic!("unexpected rule!"),
        }
    }
    Ok(quorum_set)
}

/// creates a easy-to-read string from a QuorumSet<u32>
pub fn qs_u32_to_string(quorum_set: &QuorumSet<u32>) -> String {
    let mut quorum_set_string = format!("([{}]", quorum_set.threshold);
    for member in quorum_set.members.iter() {
        match member {
            QuorumSetMember::Node(node) => {
                quorum_set_string.push_str(&format!(",{}", node));
            }
            QuorumSetMember::InnerSet(inner_set) => {
                quorum_set_string.push(',');
                quorum_set_string.push_str(&qs_u32_to_string(inner_set));
            }
        }
    }
    quorum_set_string.push(')');
    quorum_set_string
}

/// creates a easy-to-read string from a QuorumSet<NodeID>
pub fn qs_to_string(quorum_set: &QuorumSet<NodeID>) -> String {
    // assign indexes to nodes - this prob. makes assumptions about the sort order of
    // NodeIDs created by test_utils::test_node_id
    let mut nodes_vector: Vec<NodeID> = quorum_set.nodes().into_iter().collect();
    nodes_vector.sort();
    let mut quorum_set_string = format!("([{}]", quorum_set.threshold);
    for member in quorum_set.members.iter() {
        match member {
            QuorumSetMember::Node(node_id) => {
                // lookup index for this node
                let u32_id:u32 = nodes_vector.iter().position(|id| id == node_id).unwrap() as u32;
                quorum_set_string.push_str(&format!(",{}", u32_id));
            }
            QuorumSetMember::InnerSet(inner_set) => {
                quorum_set_string.push(',');
                quorum_set_string.push_str(&qs_to_string(inner_set));
            }
        }
    }
    quorum_set_string.push(')');
    quorum_set_string
}

#[cfg(test)]
mod quorum_set_parser_tests {
    use super::*;

    #[test]
    fn test_quorum_set_parser_succeeds() {
        let empty_qs: QuorumSet<u32> = QuorumSet::empty();
        assert_eq!(qs_u32_to_string(&empty_qs), "([0])");

        let empty_qs_string = "([0])".to_owned();
        assert_eq!(
            qs_u32_from_string(&empty_qs_string).expect("failed to parse"),
            empty_qs
        );

        let str1 = "([1],0)".to_owned();
        let qs_str1 = qs_u32_from_string(&str1).expect("failed to parse");
        assert_eq!(1, qs_str1.threshold);
        assert_eq!(1, qs_str1.members.len());
        let node: u32 = match qs_str1.members[0] {
            QuorumSetMember::Node(node) => node,
            _ => panic!("unexpected inner set!"),
        };
        assert_eq!(0, node);

        let qs1 = qs_u32_from_string("([1], 1, 2)").expect("failed to parse");
        let qs2 = qs_u32_from_string("([1], 2, 1)").expect("failed to parse");
        assert_eq!(qs1, qs2);

        let qs_string_with_spaces = "([3],1, 2,3, 4,([2],5, 6,([1],8,7)))".to_owned();
        let qs3 = qs_u32_from_string(&qs_string_with_spaces).expect("failed to parse");
        let canonical_string = qs_u32_to_string(&qs3);
        assert_eq!(
            qs3,
            qs_u32_from_string(&canonical_string).expect("failed to parse")
        );

        let qs_string_reordered = "([3],  4, 3,2, 1,([2], 5, ([1],8,7), 6))".to_owned();
        let qs4 = qs_u32_from_string(&qs_string_reordered).expect("failed to parse");
        assert_eq!(qs3, qs4);

        let qs5 = qs_u32_from_string("([1], ([1],1,2), ([1],3,4) )").expect("failed to parse");
        let qs6 = qs_u32_from_string("([1], ([1],4,3), ([1],2,1) )").expect("failed to parse");
        assert_eq!(qs5, qs6);
    }

    #[test]
    #[should_panic]
    fn test_quorum_set_parser_fails() {
        let bad_qs_string = "([3],1, [5], 2,3, 4,([2],5, 6,([1],8,7)))".to_owned();
        let _qs = qs_u32_from_string(&bad_qs_string).expect("failed to parse");
    }
}

