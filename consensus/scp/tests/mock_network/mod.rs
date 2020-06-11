// Copyright (c) 2018-2020 MobileCoin Inc.

use mc_common::{
    logger::{log, o, Logger},
    HashMap, HashSet, NodeID,
};
use mc_consensus_scp::{
    core_types::{CombineFn, SlotIndex, ValidityFn},
    msg::Msg,
    node::{Node, ScpNode},
    quorum_set::QuorumSet,
    test_utils::{test_node_id, TransactionValidationError},
};
use rand::{rngs::StdRng, RngCore};
use std::{
    collections::BTreeSet,
    iter::FromIterator,
    sync::{Arc, Mutex},
    thread,
    thread::JoinHandle,
    time::{Duration, Instant},
};

/// Values can be submitted to all nodes in parallel (true) or to nodes in sequential order (false)
const SUBMIT_VALUES_IN_PARALLEL: bool = true;

/// Total number of values to submit. Tests run until all values are externalized by all nodes.
const VALUES_TO_PUSH: u32 = 2000;

/// Approximate rate that values are submitted to nodes.
const VALUES_PER_SEC: u64 = 2000;

/// The total allowed testing time
const MAX_TEST_TIME_SEC: u64 = 200;

/// wait this long for slog to flush values
const LOG_FLUSH_DELAY_MILLIS: u64 = 500;

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
    pub fn new(
        node_options: Vec<NodeOptions>,
        validity_fn: ValidityFn<String, TransactionValidationError>,
        combine_fn: CombineFn<String>,
        logger: Logger,
    ) -> Self {
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
                .map(|id| test_node_id(*id as u32))
                .collect::<Vec<NodeID>>();

            let qs = QuorumSet::new_with_node_ids(options_for_this_node.k, validators);

            let peers = options_for_this_node
                .peers
                .iter()
                .map(|id| test_node_id(*id as u32))
                .collect::<HashSet<NodeID>>();

            let node_id = test_node_id(node_id as u32);

            assert!(!peers.contains(&node_id));

            let nodes_map_clone: Arc<Mutex<HashMap<NodeID, SCPNode>>> =
                { Arc::clone(&network.nodes_map) };

            let (node, thread_handle) = SCPNode::new(
                options_for_this_node.thread_name.clone(),
                node_id.clone(),
                qs,
                validity_fn.clone(),
                combine_fn.clone(),
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
                .get_mut(&test_node_id(node_num as u32))
                .expect("failed to get node from nodes_map")
                .send_stop();
        }
        drop(nodes_map);

        // now join the threads
        for node_num in 0..num_nodes {
            let node_id = &test_node_id(node_num as u32);
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

    /// Wait for this node's ledger to grow to a specific block height
    #[allow(dead_code)]
    pub fn wait_for_block_height(&self, node_id: &NodeID, block_height: usize, max_wait: Duration) {
        let deadline = Instant::now() + max_wait;
        while Instant::now() < deadline {
            let cur_block_height = self.get_shared_data(node_id).ledger.len();
            if cur_block_height >= block_height {
                return;
            }

            thread::sleep(Duration::from_millis(10));
        }

        let cur_block_height = self.get_shared_data(node_id).ledger.len();

        panic!(
            "{:?}: timeout while waiting for block height {} (currently at {})",
            node_id, block_height, cur_block_height
        );
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

        log::trace!(
            logger,
            "(broadcast) node {:3} slot {:3} : {:?}",
            msg.sender_id,
            msg.slot_index,
            msg.topic
        );

        let amsg = Arc::new(msg);

        for responder_id in peers {
            nodes_map
                .get_mut(&responder_id)
                .expect("failed to get peer from nodes_map")
                .send_msg(amsg.clone());
        }
    }

    /// Wait for this node's ledger to grow to a specific size
    pub fn wait_for_total_values(
        &self,
        node_id: &NodeID,
        values_to_collect: usize,
        max_wait: Duration,
    ) {
        let mut deadline = Instant::now() + max_wait;
        let mut prev_num_values = 0;
        let mut last_log = Instant::now();

        while Instant::now() < deadline {
            let cur_num_values = self.get_shared_data(node_id).total_values();
            if cur_num_values >= values_to_collect {
                log::trace!(
                    self.logger,
                    "( testing ) node {:3}          : {:5} values ... WAIT COMPLETE!",
                    node_id,
                    values_to_collect,
                );
                return;
            }

            // As long as we keep seeing new values get added, reset our timeout.
            if prev_num_values != cur_num_values {
                assert!(cur_num_values > prev_num_values);
                prev_num_values = cur_num_values;
                deadline = Instant::now() + max_wait;
            }

            thread::sleep(Duration::from_millis(10));

            if last_log.elapsed().as_secs() > 1 {
                log::info!(
                    self.logger,
                    "Got {}/{} values from Node {}",
                    cur_num_values,
                    values_to_collect,
                    node_id
                );
                last_log = Instant::now();
            }
        }

        let cur_num_values = self.get_shared_data(node_id).total_values();
        panic!(
            "{:?}: timeout while waiting for {} total values (currently at {})",
            node_id, values_to_collect, cur_num_values
        );
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
    local_node: Arc<Mutex<Node<String, TransactionValidationError>>>,
    sender: crossbeam_channel::Sender<SCPNodeTaskMessage>,
    shared_data: Arc<Mutex<SCPNodeSharedData>>,
}

impl SCPNode {
    pub fn new(
        thread_name: String,
        node_id: NodeID,
        quorum_set: QuorumSet,
        validity_fn: ValidityFn<String, TransactionValidationError>,
        combine_fn: CombineFn<String>,
        broadcast_msg_fn: Arc<dyn Fn(Logger, Msg<String>) + Sync + Send>,
        logger: Logger,
    ) -> (Self, Option<JoinHandle<()>>) {
        let (sender, receiver) = crossbeam_channel::unbounded();
        let local_node = Arc::new(Mutex::new(Node::new(
            node_id.clone(),
            quorum_set,
            validity_fn.clone(),
            combine_fn.clone(),
            logger.clone(),
        )));

        let node = Self {
            local_node,
            sender,
            shared_data: Arc::new(Mutex::new(SCPNodeSharedData { ledger: Vec::new() })),
        };

        let thread_shared_data = Arc::clone(&node.shared_data);
        let thread_local_node = Arc::clone(&node.local_node);
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

                        for msg in receiver.try_iter() {
                            // Handle message based on it's type
                            match msg {
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
                            };
                        }

                        // Process values submitted to our node
                        if !pending_values.is_empty() {
                            let vals = pending_values
                                              .iter()
                                              .cloned()
                                              .collect::<Vec<String>>();

                            let outgoing_msg : Option<Msg<String>> = {
                                thread_local_node
                                .lock()
                                .expect("lock failed on node nominating value")
                                .nominate(
                                    current_slot as SlotIndex,
                                    BTreeSet::from_iter(vals),
                                )
                                .expect("node.nominate() failed")
                            };

                            if let Some(outgoing_msg) = outgoing_msg {
                                (broadcast_msg_fn)(logger.clone(), outgoing_msg);
                                total_broadcasts += 1;
                            }
                        }

                        // Process the incoming messages and re-broadcast to network
                        for msg in incoming_msgs.iter() {
                            let outgoing_msg : Option<Msg<String>> = {
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

                        // Process timeouts
                        let timeout_msgs : Vec<Msg<String>> = {
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
                        let ext_vals : Vec<String> = {
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

                            log::debug!(
                                logger,
                                "{}: Slot {} ended with {} externalized values and {} pending values.",
                                node_id,
                                total_values,
                                last_slot_values,
                                remaining_values.len(),
                            );

                            pending_values = remaining_values;
                            current_slot += 1;
                        }
                    }

                    // Wait
                    thread::sleep(Duration::from_millis(10 as u64));
                }
            ).expect("failed spawning SCPNode"));

        (node, thread_handle)
    }

    /// Push value to this node's consensus task.
    pub fn send_value(&self, value: &str) {
        match self
            .sender
            .try_send(SCPNodeTaskMessage::Value(value.to_string()))
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

/// Injects values to a network and waits for completion
pub fn run_test(mut network: SCPNetwork, network_name: &str, logger: Logger) {

    if SUBMIT_VALUES_IN_PARALLEL {
        log::info!(
            logger,
            "( testing ) begin test for {} with {} values in parallel",
            network_name,
            VALUES_TO_PUSH
        );
    } else {
        log::info!(
            logger,
            "( testing ) begin test for {} with {} values in sequence",
            network_name,
            VALUES_TO_PUSH
        );
    }

    let start = Instant::now();

    let mut rng = test_helper::get_seeded_rng();

    let mut values = Vec::<String>::new();

    let num_nodes: usize = {
        network
            .nodes_map
            .lock()
            .expect("lock failed on nodes_map getting length")
            .len()
    };

    for i in 0..VALUES_TO_PUSH {
        let value = test_helper::random_str(&mut rng, 20);

        if SUBMIT_VALUES_IN_PARALLEL {
            // simulate broadcast of values to all nodes in parallel
            for n in 0..num_nodes as u32 {
                network.push_value(&test_node_id(n), &value);
            }
        } else {
            // submit values to nodes in sequence
            let n = i % (num_nodes as u32);
            network.push_value(&test_node_id(n), &value);
        }

        values.push(value);
        std::thread::sleep(Duration::from_micros(1_000_000 / VALUES_PER_SEC));
    }

    // report end of value push
    log::info!(
        logger,
        "( testing ) finished pushing values to {}",
        network_name,
    );

    // Check that the values got added to the nodes
    for node_num in 0..num_nodes {
        let node_id = test_node_id(node_num as u32);

        network.wait_for_total_values(
            &node_id,
            values.len(),
            Duration::from_secs(MAX_TEST_TIME_SEC),
        );

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
            log::error!(network.logger, "wrong values externalized!",);
            assert!(all_values_are_correct); // exit
        }

        // report end of value push
        log::info!(
            network.logger,
            "( testing ) node {} finished with {:5} values",
            node_id,
            VALUES_TO_PUSH,
        );
    }

    // Check all blocks in the ledger are the same
    let node0_data = network.get_shared_data(&test_node_id(0)).ledger;

    if !(node0_data.len() > 0) {
        log::error!(
            network.logger,
            "failing 'node0_data.len() > 0' in run_test()"
        );
    }
    assert!(node0_data.len() > 0);

    for node_num in 0..num_nodes {
        let node_data = network
            .get_shared_data(&test_node_id(node_num as u32))
            .ledger;

        if node0_data.len() != node_data.len() {
            log::error!(
                network.logger,
                "failing 'node0_data.len() == node_data.len()' in run_test()"
            );
        }
        assert_eq!(node0_data.len(), node_data.len());

        for block_num in 0..node0_data.len() {
            if node0_data.get(block_num) != node_data.get(block_num) {
                log::error!(
                    network.logger,
                    "failing 'node0_data.get(block_num) == node_data.get(block_num)' in run_test()"
                );
            }
            assert_eq!(node0_data.get(block_num), node_data.get(block_num));
        }
    }

    // stop the threads
    network.stop_all();

    log::info!(
        logger,
        "RESULTS,{},{},{},{}",
        network_name,
        start.elapsed().as_millis(),
        VALUES_TO_PUSH,
        VALUES_PER_SEC,
    );
    
    // allow log to flush
    std::thread::sleep(Duration::from_millis(LOG_FLUSH_DELAY_MILLIS)); 
}

pub fn random_str(rng: &mut StdRng, len: usize) -> String {
    const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ\
                            abcdefghijklmnopqrstuvwxyz\
                            0123456789";

    let output: String = (0..len)
        .map(|_| {
            let idx = (rng.next_u64() % CHARSET.len() as u64) as usize;
            char::from(CHARSET[idx])
        })
        .collect();

    output
}
