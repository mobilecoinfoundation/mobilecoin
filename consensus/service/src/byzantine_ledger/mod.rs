// Copyright (c) 2018-2022 The MobileCoin Foundation

//! A Federated, Byzantine Fault-Tolerant Ledger.
//!
//! Orchestrates running single-slot consensus, or performing ledger sync with
//! peers.

mod ledger_sync_state;
mod pending_values;
mod task_message;
mod worker;

use crate::{
    byzantine_ledger::{task_message::TaskMessage, worker::ByzantineLedgerWorker},
    counters,
    mint_tx_manager::{MintTxManager, MintTxManagerError},
    tx_manager::{TxManager, TxManagerError},
};
use displaydoc::Display;
use mc_common::{logger::Logger, NodeID, ResponderId};
use mc_connection::{BlockchainConnection, ConnectionManager};
use mc_consensus_enclave::ConsensusEnclave;
use mc_consensus_scp::{scp_log::LoggingScpNode, Node, QuorumSet, ScpNode};
use mc_crypto_keys::Ed25519Pair;
use mc_ledger_db::Ledger;
use mc_ledger_sync::{LedgerSyncService, ReqwestTransactionsFetcher};
use mc_peers::{
    Broadcast, ConsensusConnection, ConsensusMsg, ConsensusValue, VerifiedConsensusMsg,
};
use mc_transaction_core::mint::constants::{MAX_MINT_CONFIG_TXS_PER_BLOCK, MAX_MINT_TXS_PER_BLOCK};
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
/// This is currently capped due to pending values not being capped and an
/// outstanding issue of `scp` performing more expensive and exhaustive
/// validation than is sometimes required.
pub const MAX_PENDING_VALUES_TO_NOMINATE: usize = 100;

pub struct ByzantineLedger {
    // Handle to a worker thread.
    worker_handle: Option<JoinHandle<()>>,

    // Sender-end of the worker's task queue.
    task_sender: Sender<TaskMessage>,

    // True if this node is behind its peers. (Set by the worker)
    is_behind: Arc<AtomicBool>,

    // The highest block index that the network appears to agree on. (Set by the worker)
    highest_peer_block: Arc<AtomicU64>,

    // Highest consensus message issued by this node. (Set by the worker)
    highest_issued_msg: Arc<Mutex<Option<ConsensusMsg>>>,
}

/// An error type for mc-consensus-scp validation/combine callbacks.
#[derive(Clone, Debug, Display)]
enum UnifiedNodeError {
    /// TxManager: {0}
    TxManager(TxManagerError),

    /// MintTxManager: {0}
    MintTxManager(MintTxManagerError),
}

impl From<TxManagerError> for UnifiedNodeError {
    fn from(src: TxManagerError) -> Self {
        Self::TxManager(src)
    }
}

impl From<MintTxManagerError> for UnifiedNodeError {
    fn from(src: MintTxManagerError) -> Self {
        Self::MintTxManager(src)
    }
}

impl ByzantineLedger {
    /// Create a new ByzantineLedger
    ///
    /// # Arguments
    /// * `node_id` - The local node's ID.
    /// * `quorum_set` - The local node's quorum set.
    /// * `enclave` - Consensus enclave.
    /// * `peer_manager` - PeerManager
    /// * `ledger` - The local node's ledger.
    /// * `tx_manager` - TxManager
    /// * `mint_tx_manager` - MintTxManager
    /// * `broadcaster` - Broadcaster
    /// * `msg_signer_key` - Signs consensus messages issued by this node.
    /// * `tx_source_urls` - Source URLs for fetching block contents.
    /// * `scp_debug_dir` - If Some, debugging info will be written in this
    ///   directory.
    /// * `logger` - Logger.
    pub fn new<
        PC: BlockchainConnection + ConsensusConnection + 'static,
        L: Ledger + Clone + Sync + 'static,
        TXM: TxManager + Send + Sync + 'static,
        MTXM: MintTxManager + Send + Sync + 'static,
        E: ConsensusEnclave + Send + Sync + 'static,
    >(
        node_id: NodeID,
        quorum_set: QuorumSet,
        enclave: E,
        peer_manager: ConnectionManager<PC>,
        ledger: L,
        tx_manager: Arc<TXM>,
        mint_tx_manager: Arc<MTXM>,
        broadcaster: Arc<Mutex<dyn Broadcast>>,
        msg_signer_key: Arc<Ed25519Pair>,
        tx_source_urls: Vec<String>,
        scp_debug_dir: Option<PathBuf>,
        logger: Logger,
    ) -> Self {
        // TODO: this should be passed in as an argument.
        let scp_node: Box<dyn ScpNode<ConsensusValue>> = {
            let tx_manager_validate = tx_manager.clone();
            let tx_manager_combine = tx_manager.clone();
            let mint_tx_manager_validate = mint_tx_manager.clone();
            let mint_tx_manager_combine = mint_tx_manager.clone();
            let current_slot_index = ledger.num_blocks().unwrap();
            let node = Node::new(
                node_id.clone(),
                quorum_set,
                // Validation callback
                Arc::new(move |scp_value| match scp_value {
                    ConsensusValue::TxHash(tx_hash) => tx_manager_validate
                        .validate(tx_hash)
                        .map_err(UnifiedNodeError::from),

                    ConsensusValue::MintConfigTx(mint_config_tx) => mint_tx_manager_validate
                        .validate_mint_config_tx(mint_config_tx)
                        .map_err(UnifiedNodeError::from),

                    ConsensusValue::MintTx(mint_tx) => mint_tx_manager_validate
                        .validate_mint_tx(mint_tx)
                        .map_err(UnifiedNodeError::from),
                }),
                // Combine callback
                Arc::new(move |scp_values| {
                    let mut tx_hashes = Vec::new();
                    let mut mint_config_txs = Vec::new();
                    let mut mint_txs = Vec::new();

                    for value in scp_values {
                        match value {
                            ConsensusValue::TxHash(tx_hash) => tx_hashes.push(*tx_hash),
                            ConsensusValue::MintConfigTx(mint_config_tx) => {
                                mint_config_txs.push(mint_config_tx.clone());
                            }
                            ConsensusValue::MintTx(mint_tx) => {
                                mint_txs.push(mint_tx.clone());
                            }
                        }
                    }
                    let tx_hashes = tx_manager_combine.combine(&tx_hashes[..])?;
                    let tx_hashes_iter = tx_hashes.into_iter().map(ConsensusValue::TxHash);

                    let mint_config_txs = mint_tx_manager_combine.combine_mint_config_txs(
                        &mint_config_txs[..],
                        MAX_MINT_CONFIG_TXS_PER_BLOCK,
                    )?;
                    let mint_config_txs_iter = mint_config_txs
                        .into_iter()
                        .map(ConsensusValue::MintConfigTx);

                    let mint_txs = mint_tx_manager_combine
                        .combine_mint_txs(&mint_txs[..], MAX_MINT_TXS_PER_BLOCK)?;
                    let mint_txs_iter = mint_txs.into_iter().map(ConsensusValue::MintTx);

                    Ok(tx_hashes_iter
                        .chain(mint_config_txs_iter)
                        .chain(mint_txs_iter)
                        .collect())
                }),
                current_slot_index,
                logger.clone(),
            );

            match scp_debug_dir {
                None => Box::new(node),
                Some(path) => Box::new(
                    LoggingScpNode::new(node, path, logger.clone())
                        .expect("Failed creating LoggingScpNode"),
                ),
            }
        };

        // The worker's task queue.
        let (task_sender, task_receiver) =
            mc_util_metered_channel::unbounded(&counters::BYZANTINE_LEDGER_MESSAGE_QUEUE_SIZE);

        // Mutable state shared with the worker thread.
        let is_behind = Arc::new(AtomicBool::new(false));
        let highest_peer_block = Arc::new(AtomicU64::new(0));
        let highest_issued_msg = Arc::new(Mutex::new(Option::<ConsensusMsg>::None));

        // Start worker thread
        let worker_handle = {
            let ledger_sync_service = LedgerSyncService::new(
                ledger.clone(),
                peer_manager.clone(),
                ReqwestTransactionsFetcher::new(tx_source_urls, logger.clone()).unwrap(), /* Unwrap? */
                logger.clone(),
            );

            let mut worker = ByzantineLedgerWorker::new(
                enclave,
                scp_node,
                msg_signer_key,
                ledger,
                ledger_sync_service,
                peer_manager,
                tx_manager,
                mint_tx_manager,
                broadcaster.clone(),
                task_receiver,
                is_behind.clone(),
                highest_peer_block.clone(),
                highest_issued_msg.clone(),
                logger,
            );

            Some(
                thread::Builder::new()
                    .name(format!("ByzantineLedger{:?}", &node_id))
                    .spawn(move || loop {
                        if !worker.tick() {
                            break;
                        }
                        thread::sleep(Duration::from_millis(10));
                    })
                    .expect("failed spawning ByzantineLedger"),
            )
        };

        Self {
            worker_handle,
            task_sender,
            is_behind,
            highest_peer_block,
            highest_issued_msg,
        }
    }

    /// Handle transactions submitted by clients.
    pub fn push_values(&self, values: Vec<ConsensusValue>, received_at: Option<Instant>) {
        self.task_sender
            .send(TaskMessage::Values(received_at, values))
            .expect("Could not send values");
    }

    /// Handle consensus messages received from the network.
    pub fn handle_consensus_msg(
        &self,
        consensus_msg: VerifiedConsensusMsg,
        from_responder_id: ResponderId,
    ) {
        self.task_sender
            .send(TaskMessage::ConsensusMsg(consensus_msg, from_responder_id))
            .expect("Could not send consensus msg");
    }

    pub fn stop(&mut self) {
        let _ = self.task_sender.send(TaskMessage::StopTrigger);
        self.join();
    }

    pub fn join(&mut self) {
        if let Some(thread) = self.worker_handle.take() {
            thread.join().expect("ByzantineLedger join failed");
        }
    }

    /// Check if the node is currently behind it's peers.
    pub fn is_behind(&self) -> bool {
        self.is_behind.load(Ordering::SeqCst)
    }

    /// Get the highest scp message this node has issued.
    pub fn get_highest_issued_message(&self) -> Option<ConsensusMsg> {
        self.highest_issued_msg
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
    use crate::{
        mint_tx_manager::{MintTxManagerImpl, MockMintTxManager},
        tx_manager::{MockTxManager, TxManagerImpl},
        validators::DefaultTxManagerUntrustedInterfaces,
    };
    use mc_blockchain_types::{Block, BlockContents, BlockVersion};
    use mc_common::logger::test_with_logger;
    use mc_consensus_enclave_mock::ConsensusServiceMockEnclave;
    use mc_consensus_scp::{core_types::Ballot, msg::*, SlotIndex};
    use mc_crypto_keys::{DistinguishedEncoding, Ed25519Private};
    use mc_ledger_db::Ledger;
    use mc_peers::{MockBroadcast, ThreadedBroadcaster};
    use mc_peers_test_utils::{test_peer_uri_with_key, MockPeerConnection};
    use mc_transaction_core::TokenId;
    use mc_transaction_core_test_utils::{
        create_ledger, create_mint_config_tx_and_signers, create_mint_tx, create_transaction,
        initialize_ledger, mint_config_tx_to_validated, AccountKey,
    };
    use mc_util_from_random::FromRandom;
    use mc_util_uri::{ConnectionUri, ConsensusPeerUri};
    use rand::{rngs::StdRng, SeedableRng};
    use serial_test::serial;
    use std::{
        collections::BTreeSet,
        sync::{Arc, Mutex},
        time::Instant,
    };

    // Run these tests with a particular block version
    const BLOCK_VERSION: BlockVersion = BlockVersion::ZERO;

    // Get the local node's NodeID and message signer key.
    pub fn get_local_node_config(node_id: u32) -> (NodeID, ConsensusPeerUri, Arc<Ed25519Pair>) {
        let secret_key = Ed25519Private::try_from_der(
            base64::decode("MC4CAQAwBQYDK2VwBCIEIC50QXQll2Y9qxztvmsUgcBBIxkmk7EQjxzQTa926bKo")
                .unwrap()
                .as_slice(),
        )
        .unwrap();
        let signer_key = Ed25519Pair::from(secret_key);
        let node_uri = test_peer_uri_with_key(node_id, &signer_key.public_key());
        let node_id = node_uri.node_id().unwrap();

        (node_id, node_uri, Arc::new(signer_key))
    }

    #[derive(Clone)]
    pub struct PeerConfig {
        pub id: NodeID,
        pub uri: ConsensusPeerUri,
        pub quorum_set: QuorumSet,
        pub signer_key: Arc<Ed25519Pair>,
    }

    impl PeerConfig {
        fn new(
            id: NodeID,
            uri: ConsensusPeerUri,
            quorum_set: QuorumSet,
            signer_key: Ed25519Pair,
        ) -> Self {
            Self {
                id,
                uri,
                quorum_set,
                signer_key: Arc::new(signer_key),
            }
        }
    }

    // Get the peers' configurations.
    pub fn get_peers(peer_ids: &[u32], rng: &mut StdRng) -> Vec<PeerConfig> {
        peer_ids
            .iter()
            .map(|peer_id| {
                let signer_key = Ed25519Pair::from_random(rng);
                let uri = test_peer_uri_with_key(*peer_id, &signer_key.public_key());
                let node_id = NodeID {
                    responder_id: uri.responder_id().unwrap(),
                    public_key: signer_key.public_key(),
                };
                let quorum_set = QuorumSet::empty();
                PeerConfig::new(node_id, uri, quorum_set, signer_key)
            })
            .collect()
    }

    #[test_with_logger]
    #[serial(counters)]
    fn test_is_behind(logger: Logger) {
        let mut rng: StdRng = SeedableRng::from_seed([216u8; 32]);

        // Other nodes.
        let peers = get_peers(&[11, 22, 33], &mut rng);

        // Local node.
        let (local_node_id, _local_node_uri, msg_signer_key) = get_local_node_config(11);

        // Local node's quorum set.
        let local_quorum_set =
            QuorumSet::new_with_node_ids(2, vec![peers[0].id.clone(), peers[1].id.clone()]);

        // Local node's Ledger.
        let mut ledger = create_ledger();
        let sender = AccountKey::random(&mut rng);
        let num_blocks = 1;
        initialize_ledger(BLOCK_VERSION, &mut ledger, num_blocks, &sender, &mut rng);

        // Mock enclave.
        let enclave = ConsensusServiceMockEnclave::default();
        enclave.blockchain_config.lock().unwrap().block_version = BLOCK_VERSION;

        // Mock peer_manager
        let peer_manager = ConnectionManager::new(
            vec![
                MockPeerConnection::new(
                    peers[0].uri.clone(),
                    local_node_id.clone(),
                    ledger.clone(),
                    10,
                ),
                MockPeerConnection::new(
                    peers[1].uri.clone(),
                    local_node_id.clone(),
                    ledger.clone(),
                    10,
                ),
            ],
            logger.clone(),
        );

        // Mock tx_manager
        let tx_manager = Arc::new(MockTxManager::new());

        // Mock mint_tx_manager
        let mint_tx_manager = Arc::new(MockMintTxManager::new());

        // Mock broadcaster
        let broadcaster = Arc::new(Mutex::new(MockBroadcast::new()));

        let byzantine_ledger = ByzantineLedger::new(
            local_node_id,
            local_quorum_set,
            enclave,
            peer_manager,
            ledger.clone(),
            tx_manager,
            mint_tx_manager,
            broadcaster,
            msg_signer_key,
            Vec::new(),
            None,
            logger.clone(),
        );

        // Initially, byzantine_ledger is not behind.
        assert!(!byzantine_ledger.is_behind());
    }

    // Initially, ByzantineLedger should emit the normal SCPStatements from
    // single-slot consensus.
    #[test_with_logger]
    #[serial(counters)]
    fn test_single_slot_consensus(logger: Logger) {
        let mut rng: StdRng = SeedableRng::from_seed([209u8; 32]);

        // Other nodes.
        let peers = get_peers(&[22, 33, 44], &mut rng);

        let node_a = peers[0].clone();
        let node_b = peers[1].clone();

        // Local node.
        let (local_node_id, _, local_signer_key) = get_local_node_config(11);

        // Local node's quorum set.
        let local_quorum_set =
            QuorumSet::new_with_node_ids(2, vec![node_a.id.clone(), node_b.id.clone()]);

        // Local node's Ledger.
        let mut ledger = create_ledger();
        let sender = AccountKey::random(&mut rng);
        let num_blocks = 1;
        initialize_ledger(BLOCK_VERSION, &mut ledger, num_blocks, &sender, &mut rng);

        // Mock peer_manager
        let mock_peer = MockPeerConnection::new(
            node_a.uri.clone(),
            local_node_id.clone(),
            ledger.clone(),
            10,
        );

        // We use this later to examine the messages received by this peer.
        let mock_peer_state = mock_peer.state.clone();

        // Set up peer_manager.
        let peer_manager = ConnectionManager::new(
            vec![
                mock_peer,
                MockPeerConnection::new(
                    node_b.uri.clone(),
                    local_node_id.clone(),
                    ledger.clone(),
                    10,
                ),
            ],
            logger.clone(),
        );

        let broadcaster = Arc::new(Mutex::new(ThreadedBroadcaster::new(
            &peer_manager,
            &mc_peers::ThreadedBroadcasterFibonacciRetryPolicy::default(),
            logger.clone(),
        )));

        let enclave = ConsensusServiceMockEnclave::default();
        enclave.blockchain_config.lock().unwrap().block_version = BLOCK_VERSION;

        let tx_manager = Arc::new(TxManagerImpl::new(
            enclave.clone(),
            DefaultTxManagerUntrustedInterfaces::new(ledger.clone()),
            logger.clone(),
        ));

        let mint_tx_manager = Arc::new(MintTxManagerImpl::new(
            ledger.clone(),
            BLOCK_VERSION,
            Default::default(),
            logger.clone(),
        ));

        let byzantine_ledger = ByzantineLedger::new(
            local_node_id.clone(),
            local_quorum_set.clone(),
            enclave,
            peer_manager,
            ledger.clone(),
            tx_manager.clone(),
            mint_tx_manager,
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
                BLOCK_VERSION,
                &mut ledger,
                &block_contents.outputs[0],
                &sender,
                &recipient.default_subaddress(),
                10,
                &mut rng,
            );

            let recipient = AccountKey::random(&mut rng);
            let tx2 = create_transaction(
                BLOCK_VERSION,
                &mut ledger,
                &block_contents.outputs[1],
                &sender,
                &recipient.default_subaddress(),
                10,
                &mut rng,
            );

            let recipient = AccountKey::random(&mut rng);
            let tx3 = create_transaction(
                BLOCK_VERSION,
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

        let hash_tx_zero: ConsensusValue = tx_manager
            .insert(ConsensusServiceMockEnclave::tx_to_tx_context(
                &client_tx_zero,
            ))
            .unwrap()
            .into();

        let hash_tx_one: ConsensusValue = tx_manager
            .insert(ConsensusServiceMockEnclave::tx_to_tx_context(
                &client_tx_one,
            ))
            .unwrap()
            .into();

        let hash_tx_two: ConsensusValue = tx_manager
            .insert(ConsensusServiceMockEnclave::tx_to_tx_context(
                &client_tx_two,
            ))
            .unwrap()
            .into();

        byzantine_ledger.push_values(
            vec![
                hash_tx_zero.clone(),
                hash_tx_one.clone(),
                hash_tx_two.clone(),
            ],
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
                    X: BTreeSet::from_iter(vec![
                        hash_tx_zero.clone(),
                        hash_tx_one.clone(),
                        hash_tx_two.clone(),
                    ]),
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

            thread::sleep(Duration::from_millis(100_u64));
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
                    node_a.id.clone(),
                    node_a.quorum_set.clone(),
                    slot_index,
                    Topic::Commit(CommitPayload {
                        B: Ballot::new(
                            100,
                            &[
                                hash_tx_zero.clone(),
                                hash_tx_one.clone(),
                                hash_tx_two.clone(),
                            ],
                        ),
                        PN: 77,
                        CN: 55,
                        HN: 66,
                    }),
                ),
                &node_a.signer_key,
            )
            .unwrap()
            .try_into()
            .unwrap(),
            node_a.id.responder_id.clone(),
        );

        byzantine_ledger.handle_consensus_msg(
            ConsensusMsg::from_scp_msg(
                &ledger,
                Msg::new(
                    node_b.id.clone(),
                    node_b.quorum_set.clone(),
                    slot_index,
                    Topic::Commit(CommitPayload {
                        B: Ballot::new(
                            100,
                            &[
                                hash_tx_zero.clone(),
                                hash_tx_one.clone(),
                                hash_tx_two.clone(),
                            ],
                        ),
                        PN: 77,
                        CN: 55,
                        HN: 66,
                    }),
                ),
                &node_b.signer_key,
            )
            .unwrap()
            .try_into()
            .unwrap(),
            node_a.id.responder_id,
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

        // After some time, this node should emit some statements and write a new block
        // to its ledger.
        let deadline = Instant::now() + Duration::from_secs(60);
        while Instant::now() < deadline {
            let num_blocks_after = ledger.num_blocks().unwrap();
            if num_blocks_after > num_blocks {
                break;
            }

            thread::sleep(Duration::from_millis(100_u64));
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
    // ByzantineLedger should sync its ledger with its peers, and then emit the
    // normal SCPStatements from single-slot consensus.
    fn test_ledger_sync() {
        unimplemented!()
    }

    // ByzantineLedger should emit the normal SCPStatements from
    // single-slot consensus that contains mint txs.
    #[test_with_logger]
    #[serial(counters)]
    fn test_single_slot_consensus_on_mint_txs(logger: Logger) {
        let mut rng: StdRng = SeedableRng::from_seed([209u8; 32]);

        // Other nodes.
        let peers = get_peers(&[22, 33, 44], &mut rng);

        let node_a = peers[0].clone();
        let node_b = peers[1].clone();

        // Local node.
        let (local_node_id, _, local_signer_key) = get_local_node_config(11);

        // Local node's quorum set.
        let local_quorum_set =
            QuorumSet::new_with_node_ids(2, vec![node_a.id.clone(), node_b.id.clone()]);

        // Local node's Ledger.
        let mut ledger = create_ledger();
        let sender = AccountKey::random(&mut rng);
        initialize_ledger(BLOCK_VERSION, &mut ledger, 1, &sender, &mut rng);

        // Generate a mint config and put it in the ledger so that validation of MintTxs
        // can take place.
        let token_id1 = TokenId::from(1);
        let (mint_config_tx1, signers1) = create_mint_config_tx_and_signers(token_id1, &mut rng);

        let parent_block = ledger.get_block(ledger.num_blocks().unwrap() - 1).unwrap();

        let block_contents = BlockContents {
            validated_mint_config_txs: vec![mint_config_tx_to_validated(&mint_config_tx1)],
            ..Default::default()
        };
        let block = Block::new_with_parent(
            BlockVersion::MAX,
            &parent_block,
            &Default::default(),
            &block_contents,
        );

        ledger.append_block(&block, &block_contents, None).unwrap();

        // Mock peer_manager
        let mock_peer = MockPeerConnection::new(
            node_a.uri.clone(),
            local_node_id.clone(),
            ledger.clone(),
            10,
        );

        // We use this later to examine the messages received by this peer.
        let mock_peer_state = mock_peer.state.clone();

        // Set up peer_manager.
        let peer_manager = ConnectionManager::new(
            vec![
                mock_peer,
                MockPeerConnection::new(
                    node_b.uri.clone(),
                    local_node_id.clone(),
                    ledger.clone(),
                    10,
                ),
            ],
            logger.clone(),
        );

        let broadcaster = Arc::new(Mutex::new(ThreadedBroadcaster::new(
            &peer_manager,
            &mc_peers::ThreadedBroadcasterFibonacciRetryPolicy::default(),
            logger.clone(),
        )));

        let enclave = ConsensusServiceMockEnclave::default();
        enclave.blockchain_config.lock().unwrap().block_version = BlockVersion::MAX;

        let tx_manager = Arc::new(TxManagerImpl::new(
            enclave.clone(),
            DefaultTxManagerUntrustedInterfaces::new(ledger.clone()),
            logger.clone(),
        ));

        let mint_tx_manager = Arc::new(MintTxManagerImpl::new(
            ledger.clone(),
            BlockVersion::MAX,
            Default::default(),
            logger.clone(),
        ));

        let byzantine_ledger = ByzantineLedger::new(
            local_node_id.clone(),
            local_quorum_set.clone(),
            enclave,
            peer_manager,
            ledger.clone(),
            tx_manager,
            mint_tx_manager,
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
        let tx1 = create_mint_tx(
            token_id1,
            &[Ed25519Pair::from(signers1[0].private_key())],
            10,
            &mut rng,
        );
        let tx2 = create_mint_tx(
            token_id1,
            &[Ed25519Pair::from(signers1[0].private_key())],
            20,
            &mut rng,
        );
        let tx3 = create_mint_tx(
            token_id1,
            &[Ed25519Pair::from(signers1[0].private_key())],
            30,
            &mut rng,
        );

        byzantine_ledger.push_values(
            vec![
                ConsensusValue::MintTx(tx1.clone()),
                ConsensusValue::MintTx(tx2.clone()),
                ConsensusValue::MintTx(tx3.clone()),
            ],
            Some(Instant::now()),
        );

        let num_blocks = ledger.num_blocks().unwrap();
        let slot_index = num_blocks as SlotIndex;

        // After some time, this node should nominate its client values.
        let expected_msg = ConsensusMsg::from_scp_msg(
            &ledger,
            Msg::new(
                local_node_id.clone(),
                local_quorum_set.clone(),
                slot_index,
                Topic::Nominate(NominatePayload {
                    X: BTreeSet::from_iter(vec![
                        ConsensusValue::MintTx(tx1.clone()),
                        ConsensusValue::MintTx(tx2.clone()),
                        ConsensusValue::MintTx(tx3.clone()),
                    ]),
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

            thread::sleep(Duration::from_millis(100_u64));
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
                    node_a.id.clone(),
                    node_a.quorum_set.clone(),
                    slot_index,
                    Topic::Commit(CommitPayload {
                        B: Ballot::new(
                            100,
                            &[
                                ConsensusValue::MintTx(tx1.clone()),
                                ConsensusValue::MintTx(tx2.clone()),
                                ConsensusValue::MintTx(tx3.clone()),
                            ],
                        ),
                        PN: 77,
                        CN: 55,
                        HN: 66,
                    }),
                ),
                &node_a.signer_key,
            )
            .unwrap()
            .try_into()
            .unwrap(),
            node_a.id.responder_id.clone(),
        );

        byzantine_ledger.handle_consensus_msg(
            ConsensusMsg::from_scp_msg(
                &ledger,
                Msg::new(
                    node_b.id.clone(),
                    node_b.quorum_set.clone(),
                    slot_index,
                    Topic::Commit(CommitPayload {
                        B: Ballot::new(
                            100,
                            &[
                                ConsensusValue::MintTx(tx1.clone()),
                                ConsensusValue::MintTx(tx2.clone()),
                                ConsensusValue::MintTx(tx3.clone()),
                            ],
                        ),
                        PN: 77,
                        CN: 55,
                        HN: 66,
                    }),
                ),
                &node_b.signer_key,
            )
            .unwrap()
            .try_into()
            .unwrap(),
            node_a.id.responder_id,
        );

        // After some time, this node should emit some statements and write a new block
        // to its ledger.
        let deadline = Instant::now() + Duration::from_secs(60);
        while Instant::now() < deadline {
            let num_blocks_after = ledger.num_blocks().unwrap();
            if num_blocks_after > num_blocks {
                break;
            }

            thread::sleep(Duration::from_millis(100_u64));
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
                        C: Ballot::new(
                            55,
                            &[
                                ConsensusValue::MintTx(tx1),
                                ConsensusValue::MintTx(tx2),
                                ConsensusValue::MintTx(tx3),
                            ]
                        ),
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
}
