// Copyright (c) 2018-2020 MobileCoin Inc.
#![allow(unused_attributes)]
//TODO -- which attribute is unused???

use common::{
    logger::{log, o, test_with_logger, Logger},
    HashMap, HashSet, NodeID,
};
use rand::{rngs::StdRng, Rng, RngCore, SeedableRng};
use scp::{
    core_types::{CombineFn, SlotIndex, ValidityFn},
    msg::Msg,
    node::{Node, ScpNode},
    quorum_set::QuorumSet,
    test_utils,
    test_utils::{test_node_id, TransactionValidationError},
};
use serial_test_derive::serial;
use std::{
    collections::BTreeSet,
    iter::FromIterator,
    sync::{Arc, Mutex},
    thread,
    thread::JoinHandle,
    time::{Duration, Instant},
};

#[derive(Debug)]
struct NodeOptions {
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

struct SCPNetwork {
    nodes_map: Arc<Mutex<HashMap<NodeID, SCPNode>>>,
    thread_handles: HashMap<NodeID, Option<JoinHandle<()>>>,
    nodes_shared_data: HashMap<NodeID, Arc<Mutex<SCPNodeSharedData>>>,
    logger: Logger,
}

impl SCPNetwork {
    /// Constructs a mesh network, where each node has all of it's peers as validators.
    pub fn new_mesh(
        num_nodes: usize,
        k: u32,
        validity_fn: ValidityFn<String, TransactionValidationError>,
        combine_fn: CombineFn<String>,
        logger: Logger,
    ) -> Self {
        let mut node_options = Vec::<NodeOptions>::new();
        for node_id in 0..num_nodes {
            let other_node_ids: Vec<u32> = (0..num_nodes)
                .filter(|other_node_id| other_node_id != &node_id)
                .map(|other_node_id| other_node_id as u32)
                .collect();

            node_options.push(NodeOptions::new(
                format!("m{}-{}-SCPNode{}", num_nodes, k, node_id),
                other_node_ids.clone(),
                other_node_ids.clone(),
                k,
            ));
        }

        Self::new(node_options, validity_fn, combine_fn, logger)
    }

    /// Constructs a cyclic network (e.g. 1->2->3->4->1)
    pub fn new_cyclic(
        num_nodes: usize,
        validity_fn: ValidityFn<String, TransactionValidationError>,
        combine_fn: CombineFn<String>,
        logger: Logger,
    ) -> Self {
        let mut node_options = Vec::<NodeOptions>::new();
        for node_id in 0..num_nodes {
            let next_node_id: u32 = if node_id + 1 < num_nodes {
                node_id as u32 + 1
            } else {
                0
            };

            // TODO: Currently nodes do not relay messages, so each node needs to broadcast to the
            // entire network
            let other_node_ids: Vec<u32> = (0..num_nodes)
                .filter(|other_node_id| other_node_id != &node_id)
                .map(|other_node_id| other_node_id as u32)
                .collect();

            node_options.push(NodeOptions::new(
                format!("c{}-SCPNode{}", num_nodes, node_id),
                other_node_ids,
                vec![next_node_id],
                1,
            ));
        }

        Self::new(node_options, validity_fn, combine_fn, logger)
    }

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

            let peers = options_for_this_node
                .peers
                .iter()
                .map(|id| test_node_id(*id as u32))
                .collect::<HashSet<NodeID>>();

            let qs = QuorumSet::new_with_node_ids(options_for_this_node.k, validators);

            let node_id = test_node_id(node_id as u32);

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

#[derive(Debug)]
enum SCPNodeTaskMessage {
    Value(String),
    Msg(Arc<Msg<String>>),
    StopTrigger,
}

// Data that's shared between tests and the node's thread
#[derive(Clone, Debug)]
struct SCPNodeSharedData {
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

/// Hack to skip certain tests (that are currently too slow) from running
fn skip_slow_tests() -> bool {
    std::env::var("SKIP_SLOW_TESTS") == Ok("1".to_string())
}

///////////////////////////////////////////////////////////////////////////////
/// Mesh tests
/// (N nodes, each node has all other nodes as it's validators)
///////////////////////////////////////////////////////////////////////////////

/// Performs a simple consensus test where a network of `num_nodes` nodes is started,
/// and values are submitted only to the middle node.
fn mesh_test_helper(num_nodes: usize, k: u32, logger: Logger) {
    if skip_slow_tests() {
        return;
    }
    assert!(num_nodes >= k as usize);
    let mut rng: StdRng = SeedableRng::from_seed([97u8; 32]);
    let start = Instant::now();

    let network = SCPNetwork::new_mesh(
        num_nodes,
        k,
        Arc::new(test_utils::trivial_validity_fn::<String>),
        //                Arc::new(test_utils::get_bounded_combine_fn::<String>(3)),
        Arc::new(test_utils::trivial_combine_fn::<String>),
        logger.clone(),
    );

    // Send a few values, with random timeouts in between
    let mut values = Vec::<String>::new();

    for _i in 0..10 {
        let n = test_node_id(rng.gen_range(0, num_nodes as u32));
        for _j in 0..2000 {
            let value = random_str(&mut rng, 10);
            network.push_value(&n, &value);
            values.push(value);
        }
        thread::sleep(Duration::from_millis(rng.gen_range(0, 50)));
    }

    // Check that the values got added to the nodes
    for node_num in 0..num_nodes {
        let node_id = test_node_id(node_num as u32);

        network.wait_for_total_values(&node_id, values.len(), Duration::from_secs(1200));

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
    let node0_data = network.get_shared_data(&test_node_id(0)).ledger;
    assert!(!node0_data.is_empty());

    for node_num in 0..num_nodes {
        let node_data = network
            .get_shared_data(&test_node_id(node_num as u32))
            .ledger;
        assert_eq!(node0_data.len(), node_data.len());

        for block_num in 0..node0_data.len() {
            assert_eq!(node0_data.get(block_num), node_data.get(block_num));
        }
    }

    // Done
    log::info!(
        logger,
        "mesh_test_helper num_nodes={} k={}: {:?} (avg {} tx/s)",
        num_nodes,
        k,
        start.elapsed(),
        values.len() as u64 / std::cmp::max(1, start.elapsed().as_secs()),
    );
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

#[test_with_logger]
#[serial]
fn mesh_1(logger: Logger) {
    mesh_test_helper(1, 0, logger);
}

#[test_with_logger]
#[serial]
fn mesh_2_k1(logger: Logger) {
    mesh_test_helper(2, 1, logger);
}

#[test_with_logger]
#[serial]
fn mesh_3_k1(logger: Logger) {
    mesh_test_helper(3, 1, logger);
}

#[test_with_logger]
#[serial]
fn mesh_3_k2(logger: Logger) {
    mesh_test_helper(3, 2, logger);
}

#[test_with_logger]
#[serial]
fn mesh_4_k3(logger: Logger) {
    mesh_test_helper(4, 3, logger);
}

#[test_with_logger]
#[serial]
fn mesh_5_k3(logger: Logger) {
    mesh_test_helper(5, 3, logger);
}

#[test_with_logger]
#[serial]
fn mesh_5_k4(logger: Logger) {
    mesh_test_helper(5, 4, logger);
}

// This is a very slow test :(
#[test_with_logger]
#[serial]
fn mesh_9_k7(logger: Logger) {
    // Since this test is very slow without --release, we skip it for debug builds.
    // See https://stackoverflow.com/questions/39204908/how-to-check-release-debug-builds-using-cfg-in-rust/39205417#39205417
    if cfg!(debug_assertions) {
        return;
    }

    mesh_test_helper(9, 7, logger);
}

///////////////////////////////////////////////////////////////////////////////
// Cyclic tests (similar to Fig4 in the SCP Whitepaper)
///////////////////////////////////////////////////////////////////////////////

fn cyclic_test_helper(num_nodes: usize, logger: Logger) {
    if skip_slow_tests() {
        return;
    }

    assert!(num_nodes >= 3);
    let mut rng: StdRng = SeedableRng::from_seed([193u8; 32]);
    let start = Instant::now();

    let network = SCPNetwork::new_cyclic(
        num_nodes,
        Arc::new(test_utils::trivial_validity_fn::<String>),
        //                Arc::new(test_utils::get_bounded_combine_fn::<String>(200)),
        Arc::new(test_utils::trivial_combine_fn::<String>),
        logger.clone(),
    );

    // Send a few values, with random timeouts in between
    let mut values = Vec::<String>::new();

    for _i in 0..10 {
        let n = test_node_id(rng.gen_range(0, num_nodes as u32));
        for _j in 0..1000 {
            let value = format!("{}-{}", n, random_str(&mut rng, 10));
            network.push_value(&n, &value);
            values.push(value);
        }
        thread::sleep(Duration::from_millis(rng.gen_range(0, 50)));
    }

    // Check that the values got added to the nodes
    for node_num in 0..num_nodes {
        let node_id = test_node_id(node_num as u32);

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
    let node0_data = network.get_shared_data(&test_node_id(0)).ledger;
    assert!(!node0_data.is_empty());

    for node_num in 0..num_nodes {
        let node_data = network
            .get_shared_data(&test_node_id(node_num as u32))
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

///////////////////////////////////////////////////////////////////////////////
// Other network topologies
///////////////////////////////////////////////////////////////////////////////

#[ignore]
#[test_with_logger]
#[serial]
/// The four-node configuration from Fig. 2 of the Stellar whitepaper.
///
/// The only quorum including node 1 is {1,2,3,4}. However, {2,3,4} is a quorum that excludes node 1.
fn stellar_fig2(logger: Logger) {
    let mut rng: StdRng = SeedableRng::from_seed([243u8; 32]);
    let start = Instant::now();

    let v1_id = 0;
    let v2_id = 1;
    let v3_id = 2;
    let v4_id = 3;

    // Q(v1) = {{v1, v2, v3}}
    let v1 = NodeOptions::new(
        "Fig2-1".to_string(),
        vec![v2_id, v3_id, v4_id],
        vec![v2_id, v3_id],
        2,
    );

    // Q(v2) = {{v2, v3, v4}}
    let v2 = NodeOptions::new(
        "Fig2-2".to_string(),
        vec![v1_id, v3_id, v4_id],
        vec![v3_id, v4_id],
        2,
    );

    // Q(v3) = {{v2, v3, v4}}
    let v3 = NodeOptions::new(
        "Fig2-3".to_string(),
        vec![v1_id, v2_id, v4_id],
        vec![v2_id, v4_id],
        2,
    );

    // Q(v4) = {{v2, v3, v4}}
    let v4 = NodeOptions::new(
        "Fig2-4".to_string(),
        vec![v1_id, v2_id, v3_id],
        vec![v2_id, v3_id],
        2,
    );

    let num_nodes: u32 = 4;

    let network = SCPNetwork::new(
        vec![v1, v2, v3, v4],
        Arc::new(test_utils::trivial_validity_fn::<String>),
        Arc::new(test_utils::trivial_combine_fn::<String>),
        logger.clone(),
    );

    // Send a few values, with random timeouts in between.
    let mut values = Vec::<String>::new();

    for _i in 0..10 {
        let n = test_node_id(rng.gen_range(0, num_nodes as u32));
        for _j in 0..1000 {
            let value = format!("{}-{}", n, random_str(&mut rng, 10));
            network.push_value(&n, &value);
            values.push(value);
        }
        thread::sleep(Duration::from_millis(rng.gen_range(0, 50)));
    }

    // Check that the values got added to the nodes
    for node_num in 0..num_nodes {
        let node_id = test_node_id(node_num);

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
    let node0_data = network.get_shared_data(&test_node_id(0)).ledger;
    assert!(!node0_data.is_empty());

    for node_num in 0..num_nodes {
        let node_data = network
            .get_shared_data(&test_node_id(node_num as u32))
            .ledger;
        assert_eq!(node0_data.len(), node_data.len());

        for block_num in 0..node0_data.len() {
            assert_eq!(node0_data.get(block_num), node_data.get(block_num));
        }
    }

    // Done
    log::info!(
        logger,
        "fig2 num_nodes={}: {:?} (avg {} tx/s)",
        num_nodes,
        start.elapsed(),
        (1_000_000 * values.len() as u128) / start.elapsed().as_micros(),
    );
}
