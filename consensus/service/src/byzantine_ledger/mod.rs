// Copyright (c) 2018-2020 MobileCoin Inc.

//! A Federated, Byzantine Fault-Tolerant Ledger.
//!
//! Orchestrates running single-slot consensus, or performing ledger sync with peers.

mod ledger_sync_state;
mod task_message;
mod worker;

use crate::{
    byzantine_ledger::{task_message::TaskMessage, worker::ByzantineLedgerWorker},
    counters,
    tx_manager::{TxManager, UntrustedInterfaces},
};
use mc_common::{logger::Logger, NodeID, ResponderId};
use mc_connection::{BlockchainConnection, ConnectionManager};
use mc_consensus_enclave::ConsensusEnclaveProxy;
use mc_consensus_scp::{scp_log::LoggingScpNode, Msg, Node, QuorumSet, ScpNode};
use mc_crypto_keys::Ed25519Pair;
use mc_ledger_db::Ledger;
use mc_peers::{
    Broadcast, ConsensusConnection, ConsensusMsg, ThreadedBroadcaster, VerifiedConsensusMsg,
};
use mc_transaction_core::tx::TxHash;
use mc_util_metered_channel::Sender;
use std::{
    path::PathBuf,
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc, Mutex,
    },
    thread,
    thread::JoinHandle,
    time::{Duration, Instant},
};

/// Time we're allowed to stay behind before we initiate catchup.
/// This reduces the amount of unnecessary catchups due to minor network issues.
pub const IS_BEHIND_GRACE_PERIOD: Duration = Duration::from_secs(10);

/// Maximum number of pending values to hand over to `scp` at each slot.
/// This is currently capped due to pending values not being capped and an outstanding issue of
/// `scp` performing more expensive and exhaustive validation than is sometimes required.
pub const MAX_PENDING_VALUES_TO_NOMINATE: usize = 100;

pub struct ByzantineLedger {
    sender: Sender<TaskMessage>,
    thread_handle: Option<JoinHandle<()>>,
    is_behind: Arc<AtomicBool>,
    highest_peer_block: Arc<AtomicU64>,
    highest_outgoing_consensus_msg: Arc<Mutex<Option<ConsensusMsg>>>,
}

impl ByzantineLedger {
    pub fn new<
        E: ConsensusEnclaveProxy,
        PC: BlockchainConnection + ConsensusConnection + 'static,
        L: Ledger + Sync + 'static,
        UI: UntrustedInterfaces + Send + Sync + 'static,
    >(
        node_id: NodeID,
        quorum_set: QuorumSet,
        peer_manager: ConnectionManager<PC>,
        ledger: L,
        tx_manager: TxManager<E, UI>,
        broadcaster: Arc<Mutex<ThreadedBroadcaster>>,
        msg_signer_key: Arc<Ed25519Pair>,
        tx_source_urls: Vec<String>,
        opt_scp_debug_dump_dir: Option<PathBuf>,
        logger: Logger,
    ) -> Self {
        let (sender, receiver) =
            mc_util_metered_channel::unbounded(&counters::BYZANTINE_LEDGER_MESSAGE_QUEUE_SIZE);
        let tx_manager_validate = tx_manager.clone();
        let tx_manager_combine = tx_manager.clone();
        let scp_node = Node::new(
            node_id.clone(),
            quorum_set.clone(),
            Arc::new(move |tx_hash| tx_manager_validate.validate_tx_by_hash(tx_hash)),
            Arc::new(move |tx_hashes| tx_manager_combine.combine_txs_by_hash(tx_hashes)),
            logger.clone(),
        );
        let wrapped_scp_node: Box<dyn ScpNode<TxHash>> = if let Some(path) = opt_scp_debug_dump_dir
        {
            Box::new(
                LoggingScpNode::new(scp_node, path, logger.clone())
                    .expect("Failed creating LoggingScpNode"),
            )
        } else {
            Box::new(scp_node)
        };

        let highest_outgoing_consensus_msg = Arc::new(Mutex::new(None));

        let mut node = Self {
            sender,
            thread_handle: None,
            is_behind: Arc::new(AtomicBool::new(false)),
            highest_peer_block: Arc::new(AtomicU64::new(0)),
            highest_outgoing_consensus_msg: highest_outgoing_consensus_msg.clone(),
        };

        // Helper function to broadcast an SCP message, as well as keep track of the highest
        // message we issued. This is necessary for the implementation of the
        // `get_highest_scp_message`.
        let send_scp_message_ledger = ledger.clone();
        let send_scp_message_broadcaster = broadcaster.clone();
        let send_scp_message_node_id = node_id.clone();
        let send_scp_message = move |scp_msg: Msg<TxHash>| {
            // We do not expect failure to happen here since if we are attempting to send a
            // consensus message for a given slot, we expect the previous block to exist (block not
            // found is currently the only possible failure scenario for `from_scp_msg`).
            let consensus_msg = ConsensusMsg::from_scp_msg(
                &send_scp_message_ledger,
                scp_msg.clone(),
                msg_signer_key.as_ref(),
            )
            .unwrap_or_else(|_| panic!("failed creating consensus msg from {:?}", scp_msg));

            // Broadcast the message to our peers.
            {
                let mut broadcaster = send_scp_message_broadcaster.lock().expect("mutex poisoned");
                broadcaster.broadcast_consensus_msg(
                    &consensus_msg,
                    &send_scp_message_node_id.responder_id,
                );
            }

            let mut inner = highest_outgoing_consensus_msg
                .lock()
                .expect("lock poisoned");
            if let Some(highest_msg) = &*inner {
                // Store message if it's for a newer slot, or newer topic.
                // Node id (our local node) and quorum set (our local quorum set) are constant.
                if consensus_msg.scp_msg.slot_index > highest_msg.scp_msg.slot_index
                    || consensus_msg.scp_msg.topic > highest_msg.scp_msg.topic
                {
                    *inner = Some(consensus_msg);
                }
            } else {
                *inner = Some(consensus_msg);
            }
        };

        // Start worker thread
        let thread_is_behind = node.is_behind.clone();
        let thread_highest_peer_block = node.highest_peer_block.clone();
        let thread_handle = Some(
            thread::Builder::new()
                .name(format!("ByzantineLedger{:?}", node_id))
                .spawn(move || {
                    ByzantineLedgerWorker::start(
                        node_id,
                        quorum_set,
                        receiver,
                        wrapped_scp_node,
                        thread_is_behind,
                        thread_highest_peer_block,
                        send_scp_message,
                        ledger,
                        peer_manager,
                        tx_manager,
                        broadcaster,
                        tx_source_urls,
                        logger,
                    );
                })
                .expect("failed spawning ByzantineLedger"),
        );

        node.thread_handle = thread_handle;
        node
    }

    /// Push value to this node's consensus task.
    pub fn push_values(&self, values: Vec<TxHash>, received_at: Option<Instant>) {
        self.sender
            .send(TaskMessage::Values(received_at, values))
            .expect("Could not send values");
    }

    /// Feed message from the network to this node's consensus task.
    pub fn handle_consensus_msg(
        &self,
        consensus_msg: VerifiedConsensusMsg,
        from_responder_id: ResponderId,
    ) {
        self.sender
            .send(TaskMessage::ConsensusMsg(consensus_msg, from_responder_id))
            .expect("Could not send consensus msg");
    }

    pub fn stop(&mut self) {
        let _ = self.sender.send(TaskMessage::StopTrigger);
        self.join();
    }

    pub fn join(&mut self) {
        if let Some(thread) = self.thread_handle.take() {
            thread.join().expect("ByzantineLedger join failed");
        }
    }

    /// Check if the node is currently behind it's peers.
    pub fn is_behind(&self) -> bool {
        self.is_behind.load(Ordering::SeqCst)
    }

    /// Get the highest scp message this node has issued.
    pub fn get_highest_scp_message(&self) -> Option<ConsensusMsg> {
        self.highest_outgoing_consensus_msg
            .lock()
            .expect("mutex poisoned")
            .clone()
    }

    /// Get the highest block agreed upon by peers.
    pub fn highest_peer_block(&self) -> u64 {
        self.highest_peer_block.load(Ordering::SeqCst)
    }
}

impl Drop for ByzantineLedger {
    fn drop(&mut self) {
        self.stop()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::validators::DefaultTxManagerUntrustedInterfaces;
    use hex;
    use mc_common::logger::test_with_logger;
    use mc_consensus_enclave_mock::ConsensusServiceMockEnclave;
    use mc_consensus_scp::{core_types::Ballot, msg::*, SlotIndex};
    use mc_crypto_keys::{DistinguishedEncoding, Ed25519Private};
    use mc_ledger_db::Ledger;
    use mc_peers_test_utils::MockPeerConnection;
    use mc_transaction_core_test_utils::{
        create_ledger, create_transaction, initialize_ledger, AccountKey,
    };
    use mc_util_from_random::FromRandom;
    use mc_util_uri::{ConnectionUri, ConsensusPeerUri as PeerUri};
    use rand::{rngs::StdRng, SeedableRng};
    use rand_hc::Hc128Rng as FixedRng;
    use std::{
        collections::BTreeSet,
        convert::TryInto,
        iter::FromIterator,
        str::FromStr,
        sync::{Arc, Mutex},
        time::Instant,
    };

    fn test_peer_uri(node_id: u32, pubkey: String) -> PeerUri {
        PeerUri::from_str(&format!(
            "mcp://node{}.test.mobilecoin.com/?consensus-msg-key={}",
            node_id, pubkey,
        ))
        .expect("Could not construct uri")
    }

    fn test_node_id(uri: PeerUri, msg_signer_key: &Ed25519Pair) -> NodeID {
        NodeID {
            responder_id: uri.responder_id().unwrap(),
            public_key: msg_signer_key.public_key(),
        }
    }

    // Initially, ByzantineLedger should emit the normal SCPStatements from single-slot consensus.
    #[test_with_logger]
    fn test_single_slot_consensus(logger: Logger) {
        // Set up `local_node`.
        let trivial_quorum_set = QuorumSet::empty();

        let mut seeded_rng: FixedRng = SeedableRng::from_seed([0u8; 32]);

        let node_a_signer_key = Ed25519Pair::from_random(&mut seeded_rng);
        let node_a_uri = test_peer_uri(22, hex::encode(&node_a_signer_key.public_key()));
        let node_a = (
            test_node_id(node_a_uri.clone(), &node_a_signer_key),
            trivial_quorum_set.clone(),
        );

        let node_b_signer_key = Ed25519Pair::from_random(&mut seeded_rng);
        let node_b_uri = test_peer_uri(33, hex::encode(&node_b_signer_key.public_key()));
        let node_b = (
            test_node_id(node_b_uri.clone(), &node_b_signer_key),
            trivial_quorum_set.clone(),
        );

        let node_c_signer_key = Ed25519Pair::from_random(&mut seeded_rng);
        let node_c_uri = test_peer_uri(44, hex::encode(&node_c_signer_key.public_key()));
        let _node_c = (
            test_node_id(node_c_uri.clone(), &node_c_signer_key),
            trivial_quorum_set,
        );

        let local_secret_key = Ed25519Private::try_from_der(
            &base64::decode("MC4CAQAwBQYDK2VwBCIEIC50QXQll2Y9qxztvmsUgcBBIxkmk7EQjxzQTa926bKo")
                .unwrap()
                .as_slice(),
        )
        .unwrap();
        let local_signer_key = Arc::new(Ed25519Pair::from(local_secret_key));

        let local_node_uri = test_peer_uri(11, hex::encode(&local_signer_key.public_key()));
        let local_node_id = local_node_uri.node_id().unwrap();
        let local_quorum_set =
            QuorumSet::new_with_node_ids(2, vec![node_a.0.clone(), node_b.0.clone()]);

        let mut rng: StdRng = SeedableRng::from_seed([77u8; 32]);
        let mut ledger = create_ledger();
        let sender = AccountKey::random(&mut rng);
        let num_blocks = 1;
        initialize_ledger(&mut ledger, num_blocks, &sender, &mut rng);

        // A mock peer that collects messages sent to it.
        let mock_peer =
            MockPeerConnection::new(node_a_uri, local_node_id.clone(), ledger.clone(), 10);

        // We use this later to examine the messages received by this peer.
        let mock_peer_state = mock_peer.state.clone();

        // Set up peer_manager.
        let peer_manager = ConnectionManager::new(
            vec![
                mock_peer,
                MockPeerConnection::new(node_b_uri, local_node_id.clone(), ledger.clone(), 10),
            ],
            logger.clone(),
        );

        let broadcaster = Arc::new(Mutex::new(ThreadedBroadcaster::new(
            &peer_manager,
            &mc_peers::ThreadedBroadcasterFibonacciRetryPolicy::default(),
            logger.clone(),
        )));

        let enclave = ConsensusServiceMockEnclave::default();
        let tx_manager = TxManager::new(
            enclave.clone(),
            DefaultTxManagerUntrustedInterfaces::new(ledger.clone()),
            logger.clone(),
        );

        let byzantine_ledger = ByzantineLedger::new(
            local_node_id.clone(),
            local_quorum_set.clone(),
            peer_manager,
            ledger.clone(),
            tx_manager.clone(),
            broadcaster,
            local_signer_key.clone(),
            Vec::new(),
            None,
            logger.clone(),
        );

        // Initially, there should be no messages to the network.
        {
            assert_eq!(
                mock_peer_state
                    .lock()
                    .expect("Could not lock mock peer state")
                    .msgs
                    .len(),
                0
            );
        }

        // Generate and submit transactions.
        let mut transactions = {
            let block_contents = ledger.get_block_contents(0).unwrap();

            let recipient = AccountKey::random(&mut rng);
            let tx1 = create_transaction(
                &mut ledger,
                &block_contents.outputs[0],
                &sender,
                &recipient.default_subaddress(),
                10,
                &mut rng,
            );

            let recipient = AccountKey::random(&mut rng);
            let tx2 = create_transaction(
                &mut ledger,
                &block_contents.outputs[1],
                &sender,
                &recipient.default_subaddress(),
                10,
                &mut rng,
            );

            let recipient = AccountKey::random(&mut rng);
            let tx3 = create_transaction(
                &mut ledger,
                &block_contents.outputs[2],
                &sender,
                &recipient.default_subaddress(),
                10,
                &mut rng,
            );

            vec![tx1, tx2, tx3]
        };

        let client_tx_zero = transactions.pop().unwrap();
        let client_tx_one = transactions.pop().unwrap();
        let client_tx_two = transactions.pop().unwrap();

        let hash_tx_zero = *tx_manager
            .insert_proposed_tx(ConsensusServiceMockEnclave::tx_to_tx_context(
                &client_tx_zero,
            ))
            .unwrap()
            .tx_hash();

        let hash_tx_one = *tx_manager
            .insert_proposed_tx(ConsensusServiceMockEnclave::tx_to_tx_context(
                &client_tx_one,
            ))
            .unwrap()
            .tx_hash();

        let hash_tx_two = *tx_manager
            .insert_proposed_tx(ConsensusServiceMockEnclave::tx_to_tx_context(
                &client_tx_two,
            ))
            .unwrap()
            .tx_hash();

        byzantine_ledger.push_values(
            vec![hash_tx_zero, hash_tx_one, hash_tx_two],
            Some(Instant::now()),
        );

        let slot_index = num_blocks as SlotIndex;

        // After some time, this node should nominate its client values.
        let expected_msg = ConsensusMsg::from_scp_msg(
            &ledger,
            Msg::new(
                local_node_id.clone(),
                local_quorum_set.clone(),
                slot_index,
                Topic::Nominate(NominatePayload {
                    X: BTreeSet::from_iter(vec![hash_tx_zero, hash_tx_one, hash_tx_two]),
                    Y: BTreeSet::default(),
                }),
            ),
            &local_signer_key,
        )
        .unwrap();

        let deadline = Instant::now() + Duration::from_secs(60);
        while Instant::now() < deadline {
            {
                if mock_peer_state
                    .lock()
                    .expect("Could not lock mock peer state")
                    .msgs
                    .contains(&expected_msg)
                {
                    break;
                }
            }

            thread::sleep(Duration::from_millis(100 as u64));
        }

        {
            let msgs = &mock_peer_state
                .lock()
                .expect("Could not lock mock peer state")
                .msgs;
            assert!(
                msgs.contains(&expected_msg),
                "Nominate msg not found. msgs={:#?}",
                msgs,
            );
        }

        // Push ballot statements from node_a and node_b so that consensus is reached.
        byzantine_ledger.handle_consensus_msg(
            ConsensusMsg::from_scp_msg(
                &ledger,
                Msg::new(
                    node_a.0.clone(),
                    node_a.1.clone(),
                    slot_index,
                    Topic::Commit(CommitPayload {
                        B: Ballot::new(100, &[hash_tx_zero, hash_tx_one, hash_tx_two]),
                        PN: 77,
                        CN: 55,
                        HN: 66,
                    }),
                ),
                &node_a_signer_key,
            )
            .unwrap()
            .try_into()
            .unwrap(),
            node_a.0.responder_id.clone(),
        );

        byzantine_ledger.handle_consensus_msg(
            ConsensusMsg::from_scp_msg(
                &ledger,
                Msg::new(
                    node_b.0.clone(),
                    node_b.1,
                    slot_index,
                    Topic::Commit(CommitPayload {
                        B: Ballot::new(100, &[hash_tx_zero, hash_tx_one, hash_tx_two]),
                        PN: 77,
                        CN: 55,
                        HN: 66,
                    }),
                ),
                &node_b_signer_key,
            )
            .unwrap()
            .try_into()
            .unwrap(),
            node_a.0.responder_id,
        );

        // TODO MC-1055 write a test for this
        // Byzantine ledger should ignore a message whose signature does not verify
        // let mut bad_msg = ConsensusMsg::from_scp_msg(
        //     &ledger,
        //     Msg::new(
        //         node_c.0.clone(),
        //         node_c.1,
        //         slot_index,
        //         Topic::Commit(CommitPayload {
        //             B: Ballot::new(100, &[hash_tx_zero, hash_tx_one]),
        //             PN: 77,
        //             CN: 55,
        //             HN: 66,
        //         }),
        //     ),
        //     &node_c_signer_key,
        // )
        // .unwrap();
        // bad_msg.scp_msg.slot_index = 80;
        // byzantine_ledger.handle_consensus_msg(bad_msg, node_c.0.responder_id);

        // After some time, this node should emit some statements and write a new block to its ledger.
        let deadline = Instant::now() + Duration::from_secs(60);
        while Instant::now() < deadline {
            let num_blocks_after = ledger.num_blocks().unwrap();
            if num_blocks_after > num_blocks {
                break;
            }

            thread::sleep(Duration::from_millis(100 as u64));
        }

        let mut emitted_msgs = mock_peer_state
            .lock()
            .expect("Could not lock peer state")
            .msgs
            .clone();
        assert!(!emitted_msgs.is_empty());
        assert_eq!(
            emitted_msgs.pop_back().unwrap(),
            ConsensusMsg::from_scp_msg(
                &ledger,
                Msg::new(
                    local_node_id,
                    local_quorum_set,
                    slot_index,
                    Topic::Externalize(ExternalizePayload {
                        C: Ballot::new(55, &[hash_tx_zero, hash_tx_one, hash_tx_two,]),
                        HN: 66,
                    }),
                ),
                &local_signer_key
            )
            .unwrap(),
        );

        // The local ledger should now contain a new block.
        let num_blocks_after = ledger.num_blocks().unwrap();
        assert_eq!(num_blocks + 1, num_blocks_after);

        // The block should have a valid signature.
        let block = ledger.get_block(num_blocks).unwrap();
        let signature = ledger.get_block_signature(num_blocks).unwrap();

        let signature_verification_result = signature.verify(&block);
        assert!(signature_verification_result.is_ok());
    }

    #[test]
    #[ignore]
    // ByzantineLedger should sync its ledger with its peers, and then emit the normal SCPStatements from single-slot consensus.
    fn test_ledger_sync() {
        unimplemented!()
    }
}
