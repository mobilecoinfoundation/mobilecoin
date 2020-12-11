//! A simulated SCP node.

use crate::mock_network::{NodeConfig, TestOptions};
use mc_common::logger::{log, Logger};
use mc_consensus_scp::{Msg, Node, ScpNode, SlotIndex};
use std::{
    collections::{BTreeSet, HashSet},
    sync::{Arc, Mutex},
    thread,
    thread::JoinHandle,
};

pub enum SCPNodeTaskMessage {
    Value(String),
    Msg(Arc<Msg<String>>),
    StopTrigger,
}

// Node data shared between threads
#[derive(Clone)]
pub struct SCPNodeSharedData {
    pub ledger: Vec<Vec<String>>,
}

impl SCPNodeSharedData {
    pub fn ledger_size(&self) -> usize {
        self.ledger.iter().fold(0, |acc, block| acc + block.len())
    }
}

// A simulated SCP node.
pub struct SCPNode {
    pub sender: crossbeam_channel::Sender<SCPNodeTaskMessage>,
    pub shared_data: Arc<Mutex<SCPNodeSharedData>>,
}

impl SCPNode {
    pub fn new(
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
