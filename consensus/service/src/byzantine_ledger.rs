// Copyright (c) 2018-2020 MobileCoin Inc.

//! A Federated, Byzantine Fault-Tolerant Ledger.
//!
//! Orchestrates running single-slot consensus, or performing ledger sync with peers.

use crate::{
    counters,
    tx_manager::{TxManager, TxManagerError, UntrustedInterfaces},
};
use mc_common::{
    logger::{log, Logger},
    HashMap, NodeID, ResponderId,
};
use mc_connection::{BlockchainConnection, ConnectionManager};
use mc_consensus_enclave::ConsensusEnclaveProxy;
use mc_consensus_scp::{
    scp_log::LoggingScpNode, slot::Phase, Msg, Node, QuorumSet, ScpNode, SlotIndex,
};
use mc_crypto_keys::Ed25519Pair;
use mc_ledger_db::Ledger;
use mc_ledger_sync::{
    LedgerSyncService, NetworkState, ReqwestTransactionsFetcher, SCPNetworkState,
};
use mc_peers::{
    ConsensusConnection, ConsensusMsg, RetryableConsensusConnection, ThreadedBroadcaster,
    VerifiedConsensusMsg,
};
use mc_transaction_core::{tx::TxHash, BlockID};
use mc_util_metered_channel::{self, Receiver, Sender};
use rayon::{iter::ParallelIterator, prelude::IntoParallelIterator};
use retry::delay::Fibonacci;
use std::{
    cmp::min,
    collections::{btree_map::Entry::Vacant, BTreeMap, BTreeSet},
    iter::FromIterator,
    path::PathBuf,
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc, Mutex,
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

/// Time we're allowed to stay behind before we initiate catchup.
/// This reduces the amount of unnecessary catchups due to minor network issues.
const IS_BEHIND_GRACE_PERIOD: Duration = Duration::from_secs(10);

/// Maximum number of pending values to hand over to `scp` at each slot.
/// This is currently capped due to pending values not being capped and an outstanding issue of
/// `scp` performing more expensive and exhaustive validation than is sometimes required.
const MAX_PENDING_VALUES_TO_NOMINATE: usize = 100;

#[derive(Debug)]
enum ByzantineLedgerTaskMessage {
    /// A tuple of (timestamp, list of client-submitted values). The timestamp refers to when the
    /// list was added to the queue, and is used to tracking how long it takes to process each
    /// value.
    Values(Option<Instant>, Vec<TxHash>),

    /// SCP Statement.
    ConsensusMsg(VerifiedConsensusMsg, ResponderId),

    /// Stop trigger, used for notifying the worker thread to terminate.
    StopTrigger,
}

pub struct ByzantineLedger {
    sender: Sender<ByzantineLedgerTaskMessage>,
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
        tx_manager: TxManager<E, L, UI>,
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
                    &send_scp_message_node_id.responder_id,
                    &consensus_msg,
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
                    ByzantineLedgerThread::start(
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
            .send(ByzantineLedgerTaskMessage::Values(received_at, values))
            .expect("Could not send values");
    }

    /// Feed message from the network to this node's consensus task.
    pub fn handle_consensus_msg(
        &self,
        consensus_msg: VerifiedConsensusMsg,
        from_responder_id: ResponderId,
    ) {
        self.sender
            .send(ByzantineLedgerTaskMessage::ConsensusMsg(
                consensus_msg,
                from_responder_id,
            ))
            .expect("Could not send consensus msg");
    }

    pub fn stop(&mut self) {
        let _ = self.sender.send(ByzantineLedgerTaskMessage::StopTrigger);
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

#[derive(Clone, Eq, PartialEq)]
enum LedgerSyncState {
    /// Local ledger is in sync with the network.
    InSync,

    /// Local ledger is behind the network, but we're allowing for some time before starting catch
    /// up in case we are just about to receive SCP messages that would bring us back in sync.
    /// The `Instant` argument is when we entered this state, and is used to check when this grace
    /// period has been exceeded.
    MaybeBehind(Instant),

    /// We are behind the network and need to perform catchup.
    IsBehind {
        // Time when we should attempt to sync.
        attempt_sync_at: Instant,

        // Number of attempts made so far,
        num_sync_attempts: u64,
    },
}

struct ByzantineLedgerThread<
    E: ConsensusEnclaveProxy,
    F: Fn(Msg<TxHash>),
    L: Ledger + 'static,
    PC: BlockchainConnection + ConsensusConnection + 'static,
    UI: UntrustedInterfaces = crate::validators::DefaultTxManagerUntrustedInterfaces<L>,
> {
    receiver: Receiver<ByzantineLedgerTaskMessage>,
    scp: Box<dyn ScpNode<TxHash>>,
    is_behind: Arc<AtomicBool>,
    highest_peer_block: Arc<AtomicU64>,
    send_scp_message: F,
    ledger: L,
    peer_manager: ConnectionManager<PC>,
    tx_manager: TxManager<E, L, UI>,
    broadcaster: Arc<Mutex<ThreadedBroadcaster>>,
    logger: Logger,

    // Current slot (the one that is not yet in the ledger / the one currently being worked on).
    cur_slot: SlotIndex,

    // Previous block id
    prev_block_id: BlockID,

    // Map of slot index -> pending scp messages we need to process.
    pending_consensus_msgs: HashMap<SlotIndex, Vec<(VerifiedConsensusMsg, ResponderId)>>,

    // Pending values we're trying to push. We need to store them as a vec so we can process values
    // on a first-come first-served basis. However, we want to be able to:
    // 1) Efficiently see if we already have a given value and ignore duplicates
    // 2) Track how long each value took to externalize.
    // To accomplish both of this goals we store, in addition to the queue of pending values, a
    // BTreeMap that maps a value to when we first encountered it. Note that we only store a
    // timestamp for values that were handed to us directly from a client. We skip tracking
    // processing times for relayed values since we want to track the time from when the network
    // first saw a value, and not when a specific node saw it.
    pending_values: Vec<TxHash>,
    pending_values_map: BTreeMap<TxHash, Option<Instant>>,

    // Do we need to nominate anything?
    need_nominate: bool,

    // Network state, used to track if we've fallen behind.
    network_state: SCPNetworkState,

    // Ledger sync service
    ledger_sync_service: LedgerSyncService<L, PC, ReqwestTransactionsFetcher>,

    // Ledger sync state.
    ledger_sync_state: LedgerSyncState,
}

impl<
        E: ConsensusEnclaveProxy,
        F: Fn(Msg<TxHash>),
        L: Ledger + 'static,
        PC: BlockchainConnection + ConsensusConnection + 'static,
        UI: UntrustedInterfaces + Send + 'static,
    > ByzantineLedgerThread<E, F, L, PC, UI>
{
    pub fn start(
        node_id: NodeID,
        quorum_set: QuorumSet,
        receiver: Receiver<ByzantineLedgerTaskMessage>,
        scp: Box<dyn ScpNode<TxHash>>,
        is_behind: Arc<AtomicBool>,
        highest_peer_block: Arc<AtomicU64>,
        send_scp_message: F,
        ledger: L,
        peer_manager: ConnectionManager<PC>,
        tx_manager: TxManager<E, L, UI>,
        broadcaster: Arc<Mutex<ThreadedBroadcaster>>,
        tx_source_urls: Vec<String>,
        logger: Logger,
    ) {
        let cur_slot = ledger.num_blocks().unwrap();
        let prev_block_id = ledger.get_block(cur_slot - 1).unwrap().id;

        let transactions_fetcher = ReqwestTransactionsFetcher::new(tx_source_urls, logger.clone())
            .unwrap_or_else(|e| panic!("Failed creating transaction fetcher: {:?}", e));

        let ledger_sync_service = LedgerSyncService::new(
            ledger.clone(),
            peer_manager.clone(),
            transactions_fetcher,
            logger.clone(),
        );

        let network_state = SCPNetworkState::new(node_id, quorum_set, logger.clone());

        let mut instance = Self {
            receiver,
            scp,
            is_behind,
            highest_peer_block,
            send_scp_message,
            ledger,
            tx_manager,
            broadcaster,
            peer_manager,
            logger,

            cur_slot,
            prev_block_id,
            pending_consensus_msgs: HashMap::default(),
            pending_values: Vec::new(),
            pending_values_map: BTreeMap::default(),
            need_nominate: false,
            network_state,
            ledger_sync_service,
            ledger_sync_state: LedgerSyncState::InSync,
        };

        loop {
            if !instance.tick() {
                break;
            }

            thread::sleep(Duration::from_millis(10 as u64));
        }
    }

    // The place where all the consensus work is actually done.
    // Returns true until stop is requested.
    fn tick(&mut self) -> bool {
        // Sanity check.
        assert_eq!(self.pending_values.len(), self.pending_values_map.len());

        // Process external requests sent to us through the interface channel.
        if !self.process_external_requests() {
            return false;
        }

        // See if network state thinks we're behind.
        let sync_service_is_behind = self.ledger_sync_service.is_behind(&self.network_state);

        if let Some(peer_block) = self.network_state.highest_block_index_on_network() {
            self.highest_peer_block.store(peer_block, Ordering::SeqCst);
        }
        match (self.ledger_sync_state.clone(), sync_service_is_behind) {
            // Fully in sync, nothing to do.
            (LedgerSyncState::InSync, false) => {}

            // Sync service reports we're behind and we are just finding out about it now.
            (LedgerSyncState::InSync, true) => {
                log::info!(self.logger, "sync_service reported we are behind, we're at slot {} and network state is {:?}", self.cur_slot, self.network_state.peer_to_current_slot());
                self.ledger_sync_state = LedgerSyncState::MaybeBehind(Instant::now());
            }

            // Sync wervice reports we're behind and we're maybe behind, see if enough time has
            // passed to move to IsBehind.
            (LedgerSyncState::MaybeBehind(behind_since), true) => {
                let is_behind_duration = Instant::now() - behind_since;
                if is_behind_duration > IS_BEHIND_GRACE_PERIOD {
                    log::warn!(
                        self.logger,
                        "sync_service reports we are behind, and we are past the grace period on slot {}!",
                        self.cur_slot,
                    );
                    counters::CATCHUP_INITIATED.inc();
                    self.is_behind.store(true, Ordering::SeqCst);
                    self.ledger_sync_state = LedgerSyncState::IsBehind {
                        attempt_sync_at: Instant::now(),
                        num_sync_attempts: 0,
                    };

                    // Continue on the next tick.
                    return true;
                }
            }

            // We think we might be behind but sync service reports we're good.
            (LedgerSyncState::MaybeBehind(_), false) => {
                self.ledger_sync_state = LedgerSyncState::InSync;
                log::info!(
                    self.logger,
                    "sync_service reported we're maybe behind but we caught up!"
                );
            }

            // We think we're behind and sync service confirms that, attempt to sync.
            (
                LedgerSyncState::IsBehind {
                    attempt_sync_at,
                    num_sync_attempts,
                },
                true,
            ) => {
                // See if it's time to attempt syncing.
                let now = Instant::now();
                if attempt_sync_at > now {
                    // Not yet. Continue on to the next tick and then try again. We sleep here to
                    // throttle the event loop as it won't be doing anything until we reach the next
                    // attempt_sync_at milestone.
                    log::trace!(
                        self.logger,
                        "sync_service reported we're behind, but deadline {:?} not reached yet (attempt {})!",
                        attempt_sync_at,
                        num_sync_attempts,
                    );

                    thread::sleep(Duration::from_secs(1));
                    return true;
                }

                log::info!(
                    self.logger,
                    "sync_service reported we're behind, attempting catchup (attempt {})!",
                    num_sync_attempts,
                );

                // Attempt incremental catch-up.
                let blocks_per_attempt = 100;
                if let Err(err) = self
                    .ledger_sync_service
                    .attempt_ledger_sync(&self.network_state, blocks_per_attempt)
                {
                    log::warn!(self.logger, "Could not sync ledger: {:?}", err);

                    // The next time we attempt to sync is a linear back-off based on how many
                    // attempts we've done so far, capped at 60 seconds.
                    let next_sync_at = now + Duration::from_secs(min(num_sync_attempts + 1, 60));
                    self.ledger_sync_state = LedgerSyncState::IsBehind {
                        attempt_sync_at: next_sync_at,
                        num_sync_attempts: num_sync_attempts + 1,
                    };
                } else {
                    // We successfully synced a chunk of blocks, so reset our attempts to zero for the next chunk.
                    self.ledger_sync_state = LedgerSyncState::IsBehind {
                        attempt_sync_at,
                        num_sync_attempts: 0,
                    };
                }

                // Continue on the next tick.
                return true;
            }

            // We think we're behind but sync service indicates we're back to being in sync.
            (LedgerSyncState::IsBehind { .. }, false) => {
                log::info!(self.logger, "sync_service reports we are no longer behind!");

                // Reset scp state.
                self.scp.clear_pending_slots();

                // Clear any pending values that might no longer be valid.
                let tx_manager = self.tx_manager.clone();
                self.pending_values
                    .retain(|tx_hash| tx_manager.validate_tx_by_hash(tx_hash).is_ok());

                // Re-construct the BTreeMap with the remaining values, using the old timestamps.
                let mut new_pending_values_map = BTreeMap::new();
                for val in self.pending_values.iter() {
                    new_pending_values_map.insert(*val, *self.pending_values_map.get(val).unwrap());
                }
                self.pending_values_map = new_pending_values_map;

                // Nominate if needed.
                if !self.pending_values.is_empty() {
                    self.need_nominate = true;
                }

                // Update state.
                self.is_behind.store(false, Ordering::SeqCst);
                self.ledger_sync_state = LedgerSyncState::InSync;
                self.cur_slot = self.ledger.num_blocks().unwrap();
                self.prev_block_id = self.ledger.get_block(self.cur_slot - 1).unwrap().id;

                // Clear old entries from pending_consensus_msgs
                let cur_slot = self.cur_slot;
                self.pending_consensus_msgs
                    .retain(|&slot_index, _| slot_index >= cur_slot);
            }
        };

        // Sanity - code here should never run if we're behind.
        assert!(!self.is_behind.load(Ordering::SeqCst));
        if let LedgerSyncState::IsBehind { .. } = &self.ledger_sync_state {
            unreachable!();
        }

        // Nominate values for current slot.
        self.nominate_pending_values();

        // Process any queues consensus messages.
        self.process_consensus_msgs_for_cur_slot();

        // Process SCP timeouts.
        for outgoing_msg in self.scp.process_timeouts().into_iter() {
            (self.send_scp_message)(outgoing_msg);
        }

        // See if we're done with the current slot.
        self.attempt_complete_cur_slot();

        // Update metrics.
        self.update_cur_metrics();

        true
    }

    fn process_external_requests(&mut self) -> bool {
        for task_msg in self.receiver.try_iter() {
            // Handle message based on it's type
            match task_msg {
                // Values submitted by a client
                ByzantineLedgerTaskMessage::Values(timestamp, new_values) => {
                    // Collect.
                    for value in new_values {
                        // If we don't already know of this value, add it to the pending list and
                        // map.
                        if let Vacant(entry) = self.pending_values_map.entry(value) {
                            entry.insert(timestamp);
                            self.pending_values.push(value);
                            self.need_nominate = true;
                        }
                    }
                }

                // SCP Statement
                ByzantineLedgerTaskMessage::ConsensusMsg(consensus_msg, from_responder_id) => {
                    // Only look at messages that are not for past slots.
                    if consensus_msg.scp_msg().slot_index >= self.cur_slot {
                        // Feed network state. The sync service needs this
                        // to be able to tell if we fell behind based on the slot values.
                        // Block ID checking is skipped here, since if we fell behind
                        // we are not going to have blocks to compare to.
                        self.network_state.push(consensus_msg.scp_msg().clone());

                        // Collect.
                        let entry = self
                            .pending_consensus_msgs
                            .entry(consensus_msg.scp_msg().slot_index)
                            .or_insert(Vec::new());
                        entry.push((consensus_msg, from_responder_id));
                    }
                }

                // Request to stop thread
                ByzantineLedgerTaskMessage::StopTrigger => {
                    return false;
                }
            };
        }
        true
    }

    fn nominate_pending_values(&mut self) {
        if !self.need_nominate {
            return;
        }

        assert!(!self.pending_values.is_empty());

        let msg_opt = self
            .scp
            .propose_values(
                self.cur_slot,
                BTreeSet::from_iter(
                    self.pending_values
                        .iter()
                        .take(MAX_PENDING_VALUES_TO_NOMINATE)
                        .cloned(),
                ),
            )
            .expect("nominate failed");

        if let Some(msg) = msg_opt {
            (self.send_scp_message)(msg)
        }

        self.need_nominate = false;
    }

    fn process_consensus_msgs_for_cur_slot(&mut self) {
        if let Some(consensus_msgs) = self.pending_consensus_msgs.remove(&self.cur_slot) {
            for (consensus_msg, from_responder_id) in consensus_msgs {
                let (scp_msg, their_prev_block_id) =
                    (consensus_msg.scp_msg(), consensus_msg.prev_block_id());

                if self.prev_block_id != *their_prev_block_id {
                    log::warn!(self.logger, "Received message {:?} that refers to an invalid block id {:?} != {:?} (cur_slot = {})",
                    scp_msg, their_prev_block_id, self.prev_block_id, self.cur_slot);
                }

                if !self.fetch_missing_txs(scp_msg, &from_responder_id) {
                    continue;
                }

                // Broadcast this message to the rest of the network.
                self.broadcaster
                    .lock()
                    .expect("mutex poisoned")
                    .broadcast_consensus_msg(&from_responder_id, consensus_msg.as_ref());

                // Unclear if this helps with anything, so it is disabled for now.
                /*
                // See if this message has any values to incorporate into our pending
                // values. This is safe since we only grab values we think are
                // potentially valid.
                let mut grabbed = 0;
                if let Some(voted_or_accepted_nominated) = scp_msg.votes_or_accepts_nominated() {
                    for value in voted_or_accepted_nominated {
                        if !self.pending_values_map.contains(&value) && self.tx_cache.validate_tx_by_hash(&value).is_ok() {
                            self.pending_values.insert(value.clone());
                            self.pending_values_map.insert(value, Instant::now()? not sure if this is reasonable);
                            grabbed += 1;
                        }
                    }
                }

                if grabbed > 0 {
                    log::debug!(self.logger, "Grabbed {} extra pending values from SCP traffic", grabbed);
                }
                */

                // Pass message to the scp layer.
                match self.scp.handle(scp_msg) {
                    Ok(msg_opt) => {
                        if let Some(msg) = msg_opt {
                            (self.send_scp_message)(msg);
                        }
                    }
                    Err(err) => {
                        log::error!(
                            self.logger,
                            "Failed handling message {:?}: {:?}",
                            scp_msg,
                            err
                        );
                    }
                }
            }
        }
    }

    fn attempt_complete_cur_slot(&mut self) {
        // See if we have externalized values for the current slot.
        let ext_vals = self.scp.get_externalized_values(self.cur_slot);
        if ext_vals.is_empty() {
            return;
        }

        // Update pending value processing time metrics.
        for ext_val in ext_vals.iter() {
            if let Some(Some(timestamp)) = self.pending_values_map.get(ext_val) {
                let duration = Instant::now().saturating_duration_since(*timestamp);
                counters::PENDING_VALUE_PROCESSING_TIME.observe(duration.as_secs_f64());
            }
        }

        // Maintain the invariant that pending_values only contains valid values that were not externalized.
        self.pending_values
            .retain(|tx_hash| !ext_vals.contains(tx_hash));

        log::info!(
            self.logger,
            "Slot {} ended with {} externalized values and {} pending values.",
            self.cur_slot,
            ext_vals.len(),
            self.pending_values.len(),
        );

        // Write to ledger.
        {
            let (block, block_contents, signature) = self
                .tx_manager
                .tx_hashes_to_block(&ext_vals)
                .unwrap_or_else(|e| panic!("Failed to build block from {:?}: {:?}", ext_vals, e));

            log::info!(
                self.logger,
                "Appending block {} to ledger (sig: {}, tx_hashes: {:?}).",
                block.index,
                signature,
                ext_vals,
            );

            self.ledger
                .append_block(&block, &block_contents, Some(&signature))
                .expect("failed appending block");

            counters::TX_EXTERNALIZED_COUNT.inc_by(ext_vals.len() as i64);
        }

        // Sanity check + update current slot.
        let cur_slot = self.ledger.num_blocks().expect("num blocks failed") as SlotIndex;

        assert_eq!(cur_slot, self.cur_slot + 1);

        self.cur_slot = cur_slot;
        self.prev_block_id = self.ledger.get_block(cur_slot - 1).unwrap().id;

        // Evacuate transactions that are no longer valid based on their
        // tombstone block.
        let purged_hashes = self.tx_manager.evacuate_expired(cur_slot);

        counters::TX_CACHE_NUM_ENTRIES.set(self.tx_manager.num_entries() as i64);

        // Drop pending values that are no longer considered valid.
        let tx_manager = self.tx_manager.clone();
        self.pending_values.retain(|tx_hash| {
            !purged_hashes.contains(tx_hash) && tx_manager.validate_tx_by_hash(tx_hash).is_ok()
        });

        // Re-construct the BTreeMap with the remaining values, using the old timestamps.
        let mut new_pending_values_map = BTreeMap::new();
        for val in self.pending_values.iter() {
            new_pending_values_map.insert(*val, *self.pending_values_map.get(val).unwrap());
        }
        self.pending_values_map = new_pending_values_map;

        log::info!(
            self.logger,
            "number of pending values post cleanup: {} ({} expired)",
            self.pending_values.len(),
            purged_hashes.len(),
        );

        // Prev slot metrics.
        counters::PREV_SLOT_NUMBER.set((cur_slot - 1) as i64);
        counters::PREV_SLOT_ENDED_AT.set(chrono::Utc::now().timestamp_millis());
        counters::PREV_SLOT_NUM_EXT_VALS.set(ext_vals.len() as i64);
        counters::PREV_NUM_PENDING_VALUES.set(self.pending_values.len() as i64);

        // If we have any pending values, we'd like to issue a nominate statement on the next
        // tick.
        if !self.pending_values.is_empty() {
            self.need_nominate = true;
        }

        // If we think we're behind, reset us back to InSync since we made progress. If we're still
        // behind this will result in restarting the grace period timer, which is the desired
        // behavior. This protects us from a node that is slightly behind it's peers but has queued
        // up all the SCP statements it needs to make progress and catch up.
        if self.ledger_sync_state != LedgerSyncState::InSync {
            log::info!(self.logger, "sync_service reported we're behind, but we just externalized a slot. resetting to InSync");
            self.ledger_sync_state = LedgerSyncState::InSync;
        }
    }

    fn fetch_missing_txs(
        &mut self,
        scp_msg: &Msg<TxHash>,
        from_responder_id: &ResponderId,
    ) -> bool {
        // Get txs for all the hashes we are missing. This will eventually be replaced with
        // an enclave call, since the message is going to be encrypted (MC-74).
        let tx_hashes = scp_msg.values();

        let mut all_missing_hashes = self.tx_manager.missing_hashes(&tx_hashes);

        // Get the connection we'll be working with
        let conn = match self.peer_manager.conn(from_responder_id) {
            Some(conn) => conn,
            None => {
                log::error!(
                    self.logger,
                    "Unable to get connection for peer {}",
                    from_responder_id
                );
                return false;
            }
        };

        loop {
            if all_missing_hashes.is_empty() {
                break;
            }

            // Fetch up to 100 transactions (~1MB if each tx is 10k)
            let missing_hashes: Vec<TxHash> = all_missing_hashes
                .drain(0..std::cmp::min(100, all_missing_hashes.len()))
                .collect();

            log::debug!(
                self.logger,
                "attempting to resolve missing tx hashes ({}, left with {}): {:?}",
                missing_hashes.len(),
                all_missing_hashes.len(),
                missing_hashes,
            );

            match conn.fetch_txs(&missing_hashes, Fibonacci::from_millis(100).take(10)) {
                Ok(tx_contexts) => {
                    if tx_contexts.len() != missing_hashes.len() {
                        log::error!(
                            self.logger,
                            "Failed resolving transactions {:?} from {}: expected {}, got {}. local num blocks: {}. msg slot is {}",
                            missing_hashes,
                            from_responder_id,
                            missing_hashes.len(),
                            tx_contexts.len(),
                            self.ledger.num_blocks().unwrap(),
                            scp_msg.slot_index,
                        );
                        return false;
                    }
                    tx_contexts.into_par_iter().for_each_with(
                        (self.tx_manager.clone(), self.logger.clone()),
                        move |(tx_manager, logger), tx_context| {
                            match tx_manager.insert_proposed_tx(tx_context) {
                                Ok(_) | Err(TxManagerError::AlreadyInCache) => {}
                                Err(err) => {
                                    // Not currently logging the malformed transaction to save a
                                    // `.clone()`. We'll see if this ever happens.
                                    log::crit!(
                                        logger,
                                        "Received malformed transaction from node {}: {:?}",
                                        from_responder_id,
                                        err,
                                    );
                                }
                            }
                        },
                    );
                }
                Err(err) => {
                    log::error!(
                        self.logger,
                        "Failed resolving transactions {:?} from {}: {:?}",
                        missing_hashes,
                        from_responder_id,
                        err
                    );
                    return false;
                }
            }
        }

        true
    }

    fn update_cur_metrics(&mut self) {
        let slot_metrics = self.scp.get_slot_metrics(self.cur_slot);
        counters::CUR_NUM_PENDING_VALUES.set(self.pending_values.len() as i64);
        counters::CUR_SLOT_NUM.set(self.cur_slot as i64);
        counters::CUR_SLOT_PHASE.set(match slot_metrics.as_ref().map(|m| m.phase) {
            None => 0,
            Some(Phase::NominatePrepare) => 2,
            Some(Phase::Prepare) => 3,
            Some(Phase::Commit) => 4,
            Some(Phase::Externalize) => 5,
        });
        counters::CUR_SLOT_NUM_VOTED_NOMINATED.set(
            slot_metrics
                .as_ref()
                .map(|m| m.num_voted_nominated as i64)
                .unwrap_or(0),
        );
        counters::CUR_SLOT_NUM_ACCEPTED_NOMINATED.set(
            slot_metrics
                .as_ref()
                .map(|m| m.num_accepted_nominated as i64)
                .unwrap_or(0),
        );
        counters::CUR_SLOT_NUM_CONFIRMED_NOMINATED.set(
            slot_metrics
                .as_ref()
                .map(|m| m.num_confirmed_nominated as i64)
                .unwrap_or(0),
        );
        counters::CUR_SLOT_NOMINATION_ROUND.set(
            slot_metrics
                .as_ref()
                .map(|m| m.cur_nomination_round as i64)
                .unwrap_or(0),
        );
        counters::CUR_SLOT_BALLOT_COUNTER
            .set(slot_metrics.as_ref().map(|m| m.bN as i64).unwrap_or(0));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::validators::DefaultTxManagerUntrustedInterfaces;
    use hex;
    use mc_common::logger::test_with_logger;
    use mc_consensus_enclave_mock::ConsensusServiceMockEnclave;
    use mc_consensus_scp::{core_types::Ballot, msg::*};
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
            ledger.clone(),
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
