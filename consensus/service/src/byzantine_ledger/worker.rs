// Copyright (c) 2018-2022 The MobileCoin Foundation

use crate::{
    byzantine_ledger::{
        ledger_sync_state::LedgerSyncState, pending_values::PendingValues,
        task_message::TaskMessage, IS_BEHIND_GRACE_PERIOD, MAX_PENDING_VALUES_TO_NOMINATE,
    },
    counters,
    mint_tx_manager::MintTxManager,
    tx_manager::TxManager,
};
use mc_attest_verifier_types::prost;
use mc_blockchain_types::{BlockData, BlockID, BlockMetadata, BlockMetadataContents};
use mc_common::{
    logger::{log, Logger},
    ResponderId,
};
use mc_connection::{
    BlockchainConnection, ConnectionManager,
    _retry::{delay::Fibonacci, Error as RetryError},
};
use mc_consensus_enclave::{ConsensusEnclave, FormBlockInputs};
use mc_consensus_scp::{slot::Phase, Msg, ScpNode, SlotIndex};
use mc_crypto_keys::Ed25519Pair;
use mc_ledger_db::Ledger;
use mc_ledger_sync::{LedgerSync, NetworkState, SCPNetworkState};
use mc_peers::{
    Broadcast, ConsensusConnection, ConsensusMsg, ConsensusValue, Error as PeerError,
    RetryableConsensusConnection, VerifiedConsensusMsg,
};
use mc_transaction_core::tx::TxHash;
use mc_util_metered_channel::Receiver;
use mc_util_telemetry::{mark_span_as_active, start_block_span, tracer, Tracer};
use rayon::iter::{IntoParallelIterator, ParallelIterator};
use std::{
    cmp::min,
    collections::{BTreeSet, HashMap},
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc, Mutex,
    },
    thread,
    time::{Duration, Instant},
};

/// Default number of consensus messages to process per batch.
const CONSENSUS_MSG_BATCH_SIZE: usize = 5;

pub struct ByzantineLedgerWorker<
    E: ConsensusEnclave,
    L: Ledger + 'static,
    LS: LedgerSync<SCPNetworkState> + Send + 'static,
    PC: BlockchainConnection + ConsensusConnection + 'static,
    TXM: TxManager,
    MTXM: MintTxManager,
> {
    // Consensus enclave.
    enclave: E,

    // SCP implementation.
    scp_node: Box<dyn ScpNode<ConsensusValue>>,

    // SCP message signing key.
    msg_signer_key: Arc<Ed25519Pair>,

    // Peer connections manager.
    connection_manager: ConnectionManager<PC>,

    // SCP message broadcaster.
    broadcaster: Arc<Mutex<dyn Broadcast>>,

    // Tx manager.
    tx_manager: Arc<TXM>,

    // Mint tx manager.
    mint_tx_manager: Arc<MTXM>,

    // A map of responder id to a list of tx hashes that it is unable to provide. This allows us to
    // skip attempting to fetch txs that are bound to fail. A BTreeSet is used to speed up lookups
    // as expect to be doing more lookups than inserts.
    unavailable_tx_hashes: HashMap<ResponderId, BTreeSet<TxHash>>,

    // Current slot index (the one that is not yet in the ledger / the one currently being worked
    // on).
    current_slot_index: SlotIndex,
    ledger: L,
    ledger_sync_service: LS,
    ledger_sync_state: LedgerSyncState,

    // The worker sets this to true when the local node is behind its peers.
    is_behind: Arc<AtomicBool>,

    // The worker sets this to the highest block index that the network appears to agree on.
    highest_peer_block: Arc<AtomicU64>,

    // Highest consensus message issued by this node.
    highest_issued_msg: Arc<Mutex<Option<ConsensusMsg>>>,

    // Network state, used to track if we've fallen behind.
    network_state: SCPNetworkState,

    // TaskMessages submitted to this worker.
    tasks: Receiver<TaskMessage>,

    // Pending scp messages we need to process.
    pending_consensus_msgs: Vec<(VerifiedConsensusMsg, ResponderId)>,

    // Transactions that this node will attempt to submit to consensus.
    pending_values: PendingValues<TXM, MTXM>,

    // Set to true when the worker has pending values that have not yet been proposed to the
    // scp_node.
    need_nominate: bool,

    logger: Logger,
}

impl<
        E: ConsensusEnclave,
        L: Ledger + 'static,
        LS: LedgerSync<SCPNetworkState> + Send + 'static,
        PC: BlockchainConnection + ConsensusConnection + 'static,
        TXM: TxManager + Send + Sync,
        MTXM: MintTxManager + Send + Sync,
    > ByzantineLedgerWorker<E, L, LS, PC, TXM, MTXM>
{
    /// Create a new ByzantineLedgerWorker.
    ///
    /// # Arguments
    /// * `scp_node` - The local SCP Node.
    /// * `msg_signer_key` - Signs consensus messages issued by this node.
    /// * `ledger` - This node's ledger.
    /// * `ledger_sync_service` - LedgerSyncService
    /// * `connection_manager` - Manages connections to peers.
    /// * `tx_manager` - TxManager
    /// * `mint_tx_manager` - MintTxManager
    /// * `broadcaster` - Broadcaster
    /// * `tasks` - Receiver-end of a queue of task messages for this worker to
    ///   process.
    /// * `is_behind` - Worker sets to true when the local node is behind its
    ///   peers.
    /// * `highest_peer_block` - Worker sets to highest block index that the
    ///   network agrees on.
    /// * `highest_issued_msg` - Worker sets to highest consensus message issued
    ///   by this node.
    /// * `logger` - Logger instance.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        enclave: E,
        scp_node: Box<dyn ScpNode<ConsensusValue>>,
        msg_signer_key: Arc<Ed25519Pair>,
        ledger: L,
        ledger_sync_service: LS,
        connection_manager: ConnectionManager<PC>,
        tx_manager: Arc<TXM>,
        mint_tx_manager: Arc<MTXM>,
        broadcaster: Arc<Mutex<dyn Broadcast>>,
        tasks: Receiver<TaskMessage>,
        is_behind: Arc<AtomicBool>,
        highest_peer_block: Arc<AtomicU64>,
        highest_issued_msg: Arc<Mutex<Option<ConsensusMsg>>>,
        logger: Logger,
    ) -> Self {
        let current_slot_index = ledger.num_blocks().unwrap();

        let network_state = SCPNetworkState::new(scp_node.node_id(), scp_node.quorum_set());

        Self {
            enclave,
            tasks,
            scp_node,
            msg_signer_key,
            is_behind,
            highest_peer_block,
            highest_issued_msg,
            ledger,
            tx_manager: tx_manager.clone(),
            mint_tx_manager: mint_tx_manager.clone(),
            broadcaster,
            connection_manager,
            logger,
            current_slot_index,
            pending_consensus_msgs: Default::default(),
            pending_values: PendingValues::new(tx_manager, mint_tx_manager),
            need_nominate: false,
            network_state,
            ledger_sync_service,
            ledger_sync_state: LedgerSyncState::InSync,
            unavailable_tx_hashes: HashMap::default(),
        }
    }

    // The place where all the consensus work is actually done.
    // Returns true until stop is requested.
    pub fn tick(&mut self) -> bool {
        if !self.receive_tasks() {
            // Stop requested
            return false;
        }

        // Advance the "sync state" state machine.
        let previous_sync_state = {
            let next_state = self.next_sync_state(Instant::now());
            std::mem::replace(&mut self.ledger_sync_state, next_state)
        };
        let mut should_sync = false;
        match (previous_sync_state, &self.ledger_sync_state) {
            // (1) InSync --> InSync
            (LedgerSyncState::InSync, LedgerSyncState::InSync) => {} // Nothing to do.

            // (2) InSync --> MaybeBehind
            (LedgerSyncState::InSync, LedgerSyncState::MaybeBehind(_)) => {
                log::info!(
                    self.logger,
                    "InSync --> MaybeBehind. Slot: {}, network state: {:?}",
                    self.current_slot_index,
                    self.network_state.peer_to_current_slot()
                );
            }

            // (3) InSync --> IsBehind
            (LedgerSyncState::InSync, LedgerSyncState::IsBehind { .. }) => {
                panic!("InSync --> IsBehind transition is not allowed.")
            }

            // (4) MaybeBehind --> InSync
            (LedgerSyncState::MaybeBehind(_), LedgerSyncState::InSync) => {
                log::info!(self.logger, "MaybeBehind --> InSync");
            }

            // (5) MaybeBehind --> MaybeBehind
            (LedgerSyncState::MaybeBehind(_), LedgerSyncState::MaybeBehind(_)) => {} /* Nothing to do. */

            // (6) MaybeBehind --> IsBehind
            (LedgerSyncState::MaybeBehind(_), LedgerSyncState::IsBehind { .. }) => {
                log::info!(self.logger, "MaybeBehind --> IsBehind");
                self.is_behind.store(true, Ordering::SeqCst);
                should_sync = true;
            }

            // (7) IsBehind --> InSync
            (LedgerSyncState::IsBehind { .. }, LedgerSyncState::InSync) => {
                self.is_behind.store(false, Ordering::SeqCst);
                self.current_slot_index = self.ledger.num_blocks().unwrap();
                log::info!(
                    self.logger,
                    "IsBehind --> InSync. Slot {}",
                    &self.current_slot_index
                );

                self.scp_node.reset_slot_index(self.current_slot_index);
                // Clear any pending values that might no longer be valid.
                self.pending_values.clear_invalid_values();
                if !self.pending_values.is_empty() {
                    // These values should be proposed for nomination.
                    self.need_nominate = true;
                }
            }

            // (8) IsBehind --> MaybeBehind
            (LedgerSyncState::IsBehind { .. }, LedgerSyncState::MaybeBehind(_)) => {
                panic!("IsBehind --> MaybeBehind transition is not allowed.")
            }

            // (9) IsBehind --> IsBehind
            (
                LedgerSyncState::IsBehind { .. },
                LedgerSyncState::IsBehind {
                    attempt_sync_at, ..
                },
            ) => {
                let now = Instant::now();
                if now >= *attempt_sync_at {
                    should_sync = true;
                } else {
                    // Not yet time to attempt sync.
                    thread::sleep(Duration::from_millis(100));
                }
            }
        }

        if should_sync {
            // Incrementally sync the ledger.
            let num_blocks = 100;
            self.sync_next_blocks(num_blocks);
            // Continue on the next tick
            return true;
        }

        if let LedgerSyncState::IsBehind { .. } = &self.ledger_sync_state {
            // Still behind. Stop here and continue on next tick.
            return true;
        }
        assert!(!self.is_behind.load(Ordering::SeqCst));

        // Nominate values for current slot.
        if self.need_nominate {
            self.propose_pending_values();
        }

        // Process any queued consensus messages.
        self.process_consensus_msgs();

        // Process SCP timeouts.
        for msg in self.scp_node.process_timeouts().into_iter() {
            let _ = self.issue_consensus_message(msg);
        }

        if let Some(externalized_values) = self
            .scp_node
            .get_externalized_values(self.current_slot_index)
        {
            // The current slot has reached consensus.
            self.complete_current_slot(externalized_values);
        }

        // Update metrics.
        self.update_current_slot_metrics();

        true
    }

    /// The next LedgerSyncState to transition to.
    fn next_sync_state(&self, now: Instant) -> LedgerSyncState {
        if !self.ledger_sync_service.is_behind(&self.network_state) {
            // SyncService reports that we are in sync.
            return LedgerSyncState::InSync;
        }

        // Sync service reports that we are out of sync.
        match &self.ledger_sync_state {
            LedgerSyncState::InSync => LedgerSyncState::MaybeBehind(now),
            LedgerSyncState::MaybeBehind(behind_since) => {
                let is_behind_duration = now - *behind_since;
                if is_behind_duration > IS_BEHIND_GRACE_PERIOD {
                    LedgerSyncState::IsBehind {
                        attempt_sync_at: now,
                        num_sync_attempts: 0,
                    }
                } else {
                    // No change, keep waiting.
                    LedgerSyncState::MaybeBehind(*behind_since)
                }
            }
            LedgerSyncState::IsBehind {
                attempt_sync_at,
                num_sync_attempts,
            } => {
                // No change, still behind.
                LedgerSyncState::IsBehind {
                    attempt_sync_at: *attempt_sync_at,
                    num_sync_attempts: *num_sync_attempts,
                }
            }
        }
    }

    // Incrementally sync the ledger.
    fn sync_next_blocks(&mut self, num_blocks: u32) {
        let num_sync_attempts = if let LedgerSyncState::IsBehind {
            num_sync_attempts, ..
        } = &self.ledger_sync_state
        {
            *num_sync_attempts
        } else {
            panic!("Attempted to sync when not behind?");
        };

        self.ledger_sync_state = match self
            .ledger_sync_service
            .attempt_ledger_sync(&self.network_state, num_blocks)
        {
            Ok(()) => {
                // Synced a chunk of blocks, but may still be behind.
                LedgerSyncState::IsBehind {
                    attempt_sync_at: Instant::now(),
                    num_sync_attempts: 0,
                }
            }
            Err(err) => {
                // Reattempt with capped linear backoff.
                log::warn!(self.logger, "Could not sync ledger: {:?}", err);
                let next_sync_at =
                    Instant::now() + Duration::from_secs(min(num_sync_attempts + 1, 60));
                LedgerSyncState::IsBehind {
                    attempt_sync_at: next_sync_at,
                    num_sync_attempts: num_sync_attempts + 1,
                }
            }
        };
    }

    // Reads tasks from the task queue.
    // Returns false if the worker has been asked to stop.
    fn receive_tasks(&mut self) -> bool {
        for task_msg in self.tasks.try_iter() {
            match task_msg {
                // Transactions submitted by clients. These are assumed to be well-formed, but may
                // not be valid.
                TaskMessage::Values(timestamp, new_values) => {
                    for tx_hash in new_values {
                        if self.pending_values.push(tx_hash, timestamp) {
                            self.need_nominate = true;
                        }
                    }
                }

                // SCP Statement
                TaskMessage::ConsensusMsg(consensus_msg, from_responder_id) => {
                    // Used to detect when we are behind.
                    self.network_state.push(consensus_msg.scp_msg().clone());

                    self.pending_consensus_msgs
                        .push((consensus_msg, from_responder_id));
                }

                // Request to stop thread
                TaskMessage::StopTrigger => {
                    return false;
                }
            };
        }

        // Update highest_peer_block.
        if let Some(peer_block) = self.network_state.highest_block_index_on_network() {
            self.highest_peer_block.store(peer_block, Ordering::SeqCst);
        }

        true
    }

    // Propose pending values for nomination in the current slot.
    fn propose_pending_values(&mut self) {
        assert!(!self.pending_values.is_empty());

        // Fairness heuristics:
        // * Values are proposed in the order that they were received.
        // * Each node limits the total number of values it proposes per slot.
        let values = self
            .pending_values
            .iter()
            .take(MAX_PENDING_VALUES_TO_NOMINATE)
            .cloned()
            .collect();

        let msg_opt = self
            .scp_node
            .propose_values(values)
            .expect("nominate failed");

        if let Some(msg) = msg_opt {
            let _ = self.issue_consensus_message(msg);
        }

        self.need_nominate = false;
    }

    // Process messages for current slot and recent previous slots; retain messages
    // for future slots.
    fn process_consensus_msgs(&mut self) {
        // Process messages for slot indices in [oldest_slot, current_slot].
        let current_slot_index = self.current_slot_index;
        let max_externalized_slots = self.scp_node.max_externalized_slots() as u64;
        let oldest_slot_index = current_slot_index.saturating_sub(max_externalized_slots);
        let (consensus_msgs, future_msgs): (Vec<_>, Vec<_>) = self
            .pending_consensus_msgs
            .drain(..)
            // We do not perform consensus on the origin block.
            .filter(|(consensus_msg, _)| consensus_msg.scp_msg().slot_index != 0)
            .filter(|(consensus_msg, _)| consensus_msg.scp_msg().slot_index >= oldest_slot_index)
            .partition(|(consensus_msg, _)| {
                consensus_msg.scp_msg().slot_index <= current_slot_index
            });

        self.pending_consensus_msgs = future_msgs;

        // Omit "incompatible" messages that refer to a different blockchain history.
        let (compatible_msgs, incompatible_msgs): (Vec<_>, Vec<_>) =
            consensus_msgs.into_iter().partition(|(consensus_msg, _)| {
                let previous_block_id = self
                    .ledger
                    .get_block(consensus_msg.scp_msg().slot_index - 1)
                    .expect("This block must be in our ledger")
                    .id;
                *consensus_msg.prev_block_id() == previous_block_id
            });

        for (consensus_msg, _) in &incompatible_msgs {
            log::warn!(
                self.logger,
                "Msg refers to a different blockchain. Msg {}, previous block ID: {:?}",
                consensus_msg.scp_msg(),
                consensus_msg.prev_block_id(),
            );
        }

        // Process compatible messages in batches.
        for chunk in compatible_msgs.chunks(CONSENSUS_MSG_BATCH_SIZE) {
            // Omit a message if it references a transaction that cannot be obtained.
            let (resolved, failed): (Vec<_>, Vec<_>) =
                chunk
                    .iter()
                    .partition(|(consensus_msg, from_responder_id)| {
                        self.fetch_missing_txs(consensus_msg.scp_msg(), from_responder_id)
                    });

            if !failed.is_empty() {
                log::warn!(
                    self.logger,
                    "Omitted {} message(s) containing transaction(s) that could not be fetched.",
                    failed.len()
                );
            }

            // Broadcast resolved messages.
            for (consensus_msg, from_responder_id) in &resolved {
                self.broadcaster
                    .lock()
                    .expect("mutex poisoned")
                    .broadcast_consensus_msg(consensus_msg.as_ref(), from_responder_id);
            }

            let scp_msgs: Vec<Msg<_>> = resolved
                .into_iter()
                .map(|(consensus_msg, _)| consensus_msg.scp_msg().clone())
                .collect();

            match self.scp_node.handle_messages(scp_msgs) {
                Ok(outgoing_msgs) => {
                    for msg in outgoing_msgs {
                        let _ = self.issue_consensus_message(msg);
                    }
                }
                Err(err) => {
                    log::error!(self.logger, "Failed handling messages: {:?}", err);
                }
            }
        }
    }

    fn complete_current_slot(&mut self, externalized: Vec<ConsensusValue>) {
        let tracer = tracer!();

        let span = start_block_span(&tracer, "complete_current_slot", self.current_slot_index);
        let _active = mark_span_as_active(span);

        // Update pending value processing time metrics.
        for value in externalized.iter() {
            if let Some(received_time) = self.pending_values.get_received_time_for_value(value) {
                let duration = Instant::now().saturating_duration_since(received_time);
                counters::PENDING_VALUE_PROCESSING_TIME.observe(duration.as_secs_f64());
            }
        }

        // Invariant: pending_values only contains valid values that were not
        // externalized.
        self.pending_values
            .retain(|value| !externalized.contains(value));

        log::info!(
            self.logger,
            "Slot {} ended with {} externalized values and {} pending values.",
            self.current_slot_index,
            externalized.len(),
            self.pending_values.len(),
        );

        let block_data = self.form_block_from_externalized_values(externalized.clone());
        let signature = block_data
            .signature()
            .cloned()
            .expect("form_block always returns a signature");

        log::info!(
            self.logger,
            "Appending block {} to ledger (sig: {}, values: {:?}).",
            block_data.block().index,
            signature,
            &externalized,
        );

        tracer.in_span("append_block", |_cx| {
            self.ledger
                .append_block_data(&block_data)
                .expect("failed appending block");
        });

        counters::TX_EXTERNALIZED_COUNT.inc_by(externalized.len() as u64);

        // Update current slot index.
        self.current_slot_index = {
            let current_slot_index: SlotIndex = self.ledger.num_blocks().unwrap();
            assert_eq!(current_slot_index, self.current_slot_index + 1);
            current_slot_index
        };

        // Purge transactions that can no longer be processed based on their tombstone
        // block.
        let max_externalized_slots = self.scp_node.max_externalized_slots() as u64;
        let expired_block_index = self
            .current_slot_index
            .saturating_sub(max_externalized_slots);
        let purged_hashes = self.tx_manager.remove_expired(expired_block_index);
        let pending_values_len_before_purge = self.pending_values.len();

        self.pending_values.retain(|value| match value {
            ConsensusValue::TxHash(tx_hash) => !purged_hashes.contains(tx_hash),
            ConsensusValue::MintConfigTx(mint_config_tx) => {
                mint_config_tx.prefix.tombstone_block > expired_block_index
            }
            ConsensusValue::MintTx(mint_tx) => mint_tx.prefix.tombstone_block > expired_block_index,
        });

        // Drop pending values that are no longer considered valid.
        let pending_values_len_before_clear_invalid = self.pending_values.len();
        self.pending_values.clear_invalid_values();

        log::info!(
            self.logger,
            "Number of pending values post cleanup: {} (purged: {}, invalidated: {})",
            self.pending_values.len(),
            pending_values_len_before_purge - pending_values_len_before_clear_invalid,
            pending_values_len_before_clear_invalid - self.pending_values.len(),
        );

        // Previous slot metrics.
        counters::PREV_SLOT_NUMBER.set((self.current_slot_index - 1) as i64);
        counters::PREV_SLOT_ENDED_AT.set(chrono::Utc::now().timestamp_millis());
        counters::PREV_SLOT_NUM_EXT_VALS.set(externalized.len() as i64);
        counters::PREV_NUM_PENDING_VALUES.set(self.pending_values.len() as i64);

        if !self.pending_values.is_empty() {
            // We have pending values to nominate on the next tick.
            self.need_nominate = true;
        }

        // Clear the missing tx hashes map. If we encounter the same tx hash again in a
        // different slot, it is possible we might be able to fetch it.
        self.unavailable_tx_hashes.clear();

        // If we think we're behind, reset us back to InSync since we made progress. If
        // we're still behind this will result in restarting the grace period
        // timer, which is the desired behavior. This protects us from a node
        // that is slightly behind it's peers but has queued up all the SCP
        // statements it needs to make progress and catch up.
        if self.ledger_sync_state != LedgerSyncState::InSync {
            log::info!(self.logger, "sync_service reported we're behind, but we just externalized a slot. resetting to InSync");
            self.ledger_sync_state = LedgerSyncState::InSync;
        }
    }

    fn fetch_missing_txs(
        &mut self,
        scp_msg: &Msg<ConsensusValue>,
        from_responder_id: &ResponderId,
    ) -> bool {
        // Hashes of transactions that are not currently cached.
        let missing_hashes: Vec<TxHash> = scp_msg
            .values()
            .into_iter()
            .filter_map(|value| {
                if let ConsensusValue::TxHash(tx_hash) = value {
                    if self.tx_manager.contains(&tx_hash) {
                        None
                    } else {
                        Some(tx_hash)
                    }
                } else {
                    None
                }
            })
            .collect();

        // Don't attempt to issue any RPC calls if we know we're going to fail.
        if let Some(previously_missed_hashes) = self.unavailable_tx_hashes.get(from_responder_id) {
            let previously_encountered_missing_hashes = missing_hashes
                .iter()
                .any(|tx_hash| previously_missed_hashes.contains(tx_hash));
            if previously_encountered_missing_hashes {
                log::debug!(
                    self.logger,
                    "Not attempting to resolve missing tx hashes {:?} from {}: contains tx hashes known to not be available",
                    missing_hashes,
                    from_responder_id,
                );
                return false;
            }
        }

        // Get the connection we'll be working with
        let conn = match self.connection_manager.conn(from_responder_id) {
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

        for chunk in missing_hashes[..].chunks(100) {
            match conn.fetch_txs(chunk, Fibonacci::from_millis(100).take(10)) {
                Ok(tx_contexts) => {
                    if tx_contexts.len() != chunk.len() {
                        log::error!(
                            self.logger,
                            "Failed resolving transactions {:?} from {}: expected {}, got {}. local num blocks: {}. msg slot is {}",
                            chunk,
                            from_responder_id,
                            chunk.len(),
                            tx_contexts.len(),
                            self.ledger.num_blocks().unwrap(),
                            scp_msg.slot_index,
                        );
                        return false;
                    }
                    tx_contexts.into_par_iter().for_each_with(
                        (self.tx_manager.clone(), self.logger.clone()),
                        move |(tx_manager, logger), tx_context| match tx_manager.insert(tx_context)
                        {
                            Ok(_) => {}
                            Err(err) => {
                                log::crit!(
                                    logger,
                                    "Received malformed transaction from node {}: {:?}",
                                    from_responder_id,
                                    err,
                                );
                            }
                        },
                    );
                }
                Err(RetryError {
                    error: PeerError::TxHashesNotInCache(tx_hashes),
                    ..
                }) => {
                    let entry = self
                        .unavailable_tx_hashes
                        .entry(from_responder_id.clone())
                        .or_default();
                    entry.extend(tx_hashes);
                    return false;
                }
                Err(err) => {
                    log::error!(
                        self.logger,
                        "Failed resolving transactions {:?} from {}: {:?}",
                        chunk,
                        from_responder_id,
                        err
                    );
                    return false;
                }
            }
        }

        true
    }

    /// Broadcast a consensus message issued by this node.
    fn issue_consensus_message(&mut self, msg: Msg<ConsensusValue>) -> Result<(), &'static str> {
        let consensus_msg =
            ConsensusMsg::from_scp_msg(&self.ledger, msg, self.msg_signer_key.as_ref())
                .map_err(|_| "Failed creating ConsensusMsg")?;

        // Broadcast the message to the network.
        self.broadcaster
            .lock()
            .map(|mut broadcast| {
                broadcast
                    .broadcast_consensus_msg(&consensus_msg, &self.scp_node.node_id().responder_id)
            })
            .map_err(|_e| "Mutex poisoned: broadcaster")?;

        // Update highest_issued_msg.
        let mut inner = self
            .highest_issued_msg
            .lock()
            .map_err(|_e| "Mutex poisoned: highest_issued_msg")?;

        match &*inner {
            Some(highest_msg) => {
                if consensus_msg.scp_msg.slot_index > highest_msg.scp_msg.slot_index
                    || consensus_msg.scp_msg.topic > highest_msg.scp_msg.topic
                {
                    // New highest message.
                    *inner = Some(consensus_msg);
                }
            }
            None => *inner = Some(consensus_msg),
        }

        Ok(())
    }

    fn update_current_slot_metrics(&mut self) {
        let slot_metrics = self.scp_node.get_current_slot_metrics();
        counters::CUR_NUM_PENDING_VALUES.set(self.pending_values.len() as i64);
        counters::CUR_SLOT_NUM.set(self.current_slot_index as i64);
        counters::CUR_SLOT_PHASE.set(match &slot_metrics.phase {
            Phase::NominatePrepare => 2,
            Phase::Prepare => 3,
            Phase::Commit => 4,
            Phase::Externalize => 5,
        });
        counters::CUR_SLOT_NUM_VOTED_NOMINATED.set(slot_metrics.num_voted_nominated as i64);
        counters::CUR_SLOT_NUM_ACCEPTED_NOMINATED.set(slot_metrics.num_accepted_nominated as i64);
        counters::CUR_SLOT_NUM_CONFIRMED_NOMINATED.set(slot_metrics.num_confirmed_nominated as i64);
        counters::CUR_SLOT_NOMINATION_ROUND.set(slot_metrics.cur_nomination_round as i64);
        counters::CUR_SLOT_BALLOT_COUNTER.set(slot_metrics.bN as i64);
    }

    fn form_block_from_externalized_values(
        &self,
        externalized_values: Vec<ConsensusValue>,
    ) -> BlockData {
        let parent_block = self
            .ledger
            .get_latest_block()
            .expect("Failed to get latest block.");

        // Split externalized values into the different transaction types
        let mut tx_hashes = Vec::new();
        let mut mint_config_txs = Vec::new();
        let mut mint_txs = Vec::new();

        for value in externalized_values {
            match value {
                ConsensusValue::TxHash(tx_hash) => tx_hashes.push(tx_hash),
                ConsensusValue::MintConfigTx(mint_config_tx) => {
                    mint_config_txs.push(mint_config_tx);
                }
                ConsensusValue::MintTx(mint_tx) => {
                    mint_txs.push(mint_tx);
                }
            }
        }

        // Resolve hashes into well formed encrypted txs and associated proofs.
        let well_formed_encrypted_txs_with_proofs = self
            .tx_manager
            .tx_hashes_to_well_formed_encrypted_txs_and_proofs(&tx_hashes)
            .unwrap_or_else(|e| panic!("failed resolving tx_hashes {tx_hashes:?}: {e:?}"));

        // Bundle mint_txs with the matching configuration that allows the minting.
        let mint_txs_with_config = self
            .mint_tx_manager
            .mint_txs_with_config(&mint_txs)
            .unwrap_or_else(|e| panic!("failed resolving mint txs {mint_txs:?}: {e:?}"));

        // Get the root membership element, which is needed for validating the
        // membership proofs (and also storing in the block for bookkeeping
        // purposes).
        let root_element = self
            .ledger
            .get_root_tx_out_membership_element()
            .expect("Failed getting root tx out membership element");

        // Request the enclave to form the next block.
        let (block, block_contents, mut signature) = self
            .enclave
            .form_block(
                &parent_block,
                FormBlockInputs {
                    well_formed_encrypted_txs_with_proofs,
                    mint_config_txs,
                    mint_txs_with_config,
                },
                &root_element,
            )
            .expect("form_block failed");

        // The enclave cannot provide a timestamp, so this happens in untrusted.
        signature.set_signed_at(chrono::Utc::now().timestamp() as u64);

        let metadata = self.get_block_metadata(&block.id);

        BlockData::new(block, block_contents, signature, metadata)
    }

    fn get_block_metadata(&self, block_id: &BlockID) -> BlockMetadata {
        let dcap_evidence = self
            .enclave
            .get_attestation_evidence()
            .unwrap_or_else(|err| {
                panic!(
                    "Failed to fetch attestation evidence after forming block {block_id:?}: {err}"
                )
            });
        let prost_evidence = prost::DcapEvidence::try_from(&dcap_evidence).unwrap_or_else(|err| {
            panic!(
                "Failed to convert attestation evidence to prost after forming block {block_id:?}: {err}"
            )
        });
        let contents = BlockMetadataContents::new(
            block_id.clone(),
            self.scp_node.quorum_set(),
            prost_evidence.into(),
            self.scp_node.node_id().responder_id,
        );

        BlockMetadata::from_contents_and_keypair(contents, &self.msg_signer_key).unwrap_or_else(
            |err| panic!("Failed to sign block metadata for block {block_id:?}: {err}"),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        byzantine_ledger::tests::{get_local_node_config, get_peers, PeerConfig},
        mint_tx_manager::{MintTxManagerImpl, MockMintTxManager},
        tx_manager::{MockTxManager, TxManagerError, TxManagerImpl},
        validators::DefaultTxManagerUntrustedInterfaces,
    };
    use mc_account_keys::AccountKey;
    use mc_blockchain_types::{AttestationEvidence, Block, BlockContents, BlockVersion};
    use mc_common::{logger::test_with_logger, NodeID};
    use mc_consensus_enclave::GovernorsMap;
    use mc_consensus_enclave_mock::{ConsensusServiceMockEnclave, MockConsensusEnclave};
    use mc_consensus_scp::{
        msg::{NominatePayload, Topic::Nominate},
        slot::SlotMetrics,
        MockScpNode, QuorumSet,
    };
    use mc_crypto_multisig::SignerSet;
    use mc_ledger_db::{
        test_utils::{
            add_block_contents_to_ledger, create_ledger, create_transaction, initialize_ledger,
        },
        MockLedger,
    };
    use mc_ledger_sync::{LedgerSyncError, MockLedgerSync, SCPNetworkState};
    use mc_peers::MockBroadcast;
    use mc_peers_test_utils::MockPeerConnection;
    use mc_sgx_report_cache_api::ReportableEnclave;
    use mc_transaction_core::{
        tx::{Tx, TxHash},
        validation::TransactionValidationError,
        TokenId,
    };
    use mc_transaction_core_test_utils::{
        create_mint_config_tx_and_signers, create_mint_tx_to_recipient, mint_config_tx_to_validated,
    };
    use mc_util_metered_channel::{Receiver, Sender};
    use mc_util_metrics::OpMetrics;
    use mockall::predicate::eq;
    use rand::{rngs::StdRng, SeedableRng};

    /// Create test mocks with sensible defaults.
    ///
    /// # Arguments
    /// * `node_id` - The local node's ID.
    /// * `quorum_set` - The local node's quorum set.
    /// * `num_blocks` - Number of blocks in the ledger.
    fn get_mocks(
        node_id: &NodeID,
        quorum_set: &QuorumSet,
        num_blocks: u64,
    ) -> (
        MockConsensusEnclave,
        MockScpNode<ConsensusValue>,
        MockLedger,
        MockLedgerSync<SCPNetworkState>,
        MockTxManager,
        MockMintTxManager,
        MockBroadcast,
    ) {
        let mut scp_node = MockScpNode::new();
        scp_node.expect_node_id().return_const(node_id.clone());
        scp_node
            .expect_quorum_set()
            .return_const(quorum_set.clone());

        let mut ledger = MockLedger::new();
        ledger.expect_num_blocks().return_const(Ok(num_blocks));
        (
            MockConsensusEnclave::new(),
            scp_node,
            ledger,
            MockLedgerSync::new(),
            MockTxManager::new(),
            MockMintTxManager::new(),
            MockBroadcast::new(),
        )
    }

    fn get_channel() -> (Sender<TaskMessage>, Receiver<TaskMessage>) {
        let gauge = OpMetrics::new("test").gauge("byzantine_ledger_msg_queue_size");
        mc_util_metered_channel::unbounded(&gauge)
    }

    fn get_connection_manager(
        local_node_id: &NodeID,
        peers: &[PeerConfig],
        logger: &Logger,
    ) -> ConnectionManager<MockPeerConnection<MockLedger>> {
        let connections: Vec<_> = peers
            .iter()
            .map(|peer_config| {
                let ledger = MockLedger::new();
                MockPeerConnection::new(peer_config.uri.clone(), local_node_id.clone(), ledger, 10)
            })
            .collect();

        ConnectionManager::new(connections, logger.clone())
    }

    #[test_with_logger]
    /// Test that `new` correctly initializes the instance.
    fn test_new(logger: Logger) {
        let mut rng: StdRng = SeedableRng::from_seed([7u8; 32]);
        let (local_node_id, _local_node_uri, msg_signer_key) = get_local_node_config(11);

        // Local node's quorum set.
        let peers = get_peers(&[22, 33], &mut rng);
        let quorum_set =
            QuorumSet::new_with_node_ids(2, vec![peers[0].id.clone(), peers[1].id.clone()]);

        let num_blocks = 15;
        let (enclave, scp_node, ledger, ledger_sync, tx_manager, mint_tx_manager, broadcast) =
            get_mocks(&local_node_id, &quorum_set, num_blocks);

        let connection_manager = get_connection_manager(&local_node_id, &peers, &logger);

        let (_task_sender, task_receiver) = get_channel();

        let worker = ByzantineLedgerWorker::new(
            enclave,
            Box::new(scp_node),
            msg_signer_key,
            ledger,
            ledger_sync,
            connection_manager,
            Arc::new(tx_manager),
            Arc::new(mint_tx_manager),
            Arc::new(Mutex::new(broadcast)),
            task_receiver,
            Arc::new(AtomicBool::new(false)),
            Arc::new(AtomicU64::new(0)),
            Arc::new(Mutex::new(Option::<ConsensusMsg>::None)),
            logger,
        );

        // current_slot_index should be initialized from the ledger.
        assert_eq!(worker.current_slot_index, num_blocks);

        // Initially, the worker should think that its ledger is in sync with the
        // network.
        assert_eq!(worker.ledger_sync_state, LedgerSyncState::InSync);
    }

    /// Asserts that next_sync_state maps (initial_state, is_behind, now) -->
    /// expected_state
    fn next_sync_state_helper(
        initial_state: LedgerSyncState,
        is_behind: bool,
        now: Instant,
        expected_state: LedgerSyncState,
        logger: Logger,
    ) {
        let (node_id, _local_node_uri, msg_signer_key) = get_local_node_config(11);

        let mut rng: StdRng = SeedableRng::from_seed([7u8; 32]);
        let peers = get_peers(&[22, 33], &mut rng);
        let quorum_set =
            QuorumSet::new_with_node_ids(2, vec![peers[0].id.clone(), peers[1].id.clone()]);

        let num_blocks = 12;
        let (enclave, scp_node, ledger, mut ledger_sync, tx_manager, mint_tx_manager, broadcast) =
            get_mocks(&node_id, &quorum_set, num_blocks);

        // Mock returns `is_behind`.
        ledger_sync.expect_is_behind().return_const(is_behind);

        let connection_manager = get_connection_manager(&node_id, &peers, &logger);

        let (_task_sender, task_receiver) = get_channel();

        let mut worker = ByzantineLedgerWorker::new(
            enclave,
            Box::new(scp_node),
            msg_signer_key,
            ledger,
            ledger_sync,
            connection_manager,
            Arc::new(tx_manager),
            Arc::new(mint_tx_manager),
            Arc::new(Mutex::new(broadcast)),
            task_receiver,
            Arc::new(AtomicBool::new(false)),
            Arc::new(AtomicU64::new(0)),
            Arc::new(Mutex::new(Option::<ConsensusMsg>::None)),
            logger,
        );

        // Set initial state.
        worker.ledger_sync_state = initial_state;

        let next_state = worker.next_sync_state(now);
        assert_eq!(next_state, expected_state);
    }

    #[test_with_logger]
    /// Test LedgerSyncState transitions.
    fn test_next_sync_state(logger: Logger) {
        // is_behind = false, InSync --> InSync
        next_sync_state_helper(
            LedgerSyncState::InSync,
            false,
            Instant::now(),
            LedgerSyncState::InSync,
            logger.clone(),
        );

        // is_behind = false, MaybeBehind --> InSync
        next_sync_state_helper(
            LedgerSyncState::MaybeBehind(Instant::now()), // TODO: when?
            false,
            Instant::now(),
            LedgerSyncState::InSync,
            logger.clone(),
        );

        // is_behind = false, IsBehind --> InSync
        next_sync_state_helper(
            LedgerSyncState::IsBehind {
                attempt_sync_at: Instant::now(),
                num_sync_attempts: 3,
            }, // TODO: when?
            false,
            Instant::now(),
            LedgerSyncState::InSync,
            logger.clone(),
        );

        // is_behind = true, InSync -> MaybeBehind
        let now = Instant::now();
        next_sync_state_helper(
            LedgerSyncState::InSync,
            true,
            now,
            LedgerSyncState::MaybeBehind(now),
            logger.clone(),
        );

        // is_behind = true, MaybeBehind -> MaybeBehind
        // This happens when not enough time has elapsed since entering the MaybeBehind
        // state.
        let now = Instant::now();
        next_sync_state_helper(
            LedgerSyncState::MaybeBehind(now),
            true,
            now, // no time has passed
            LedgerSyncState::MaybeBehind(now),
            logger.clone(),
        );

        // is_behind = true, MaybeBehind -> IsBehind
        // This happens when the grace period has elapsed since entering the MaybeBehind
        // state.
        let behind_since = Instant::now();
        // IS_BEHIND_GRACE_PERIOD + 1 seconds has elapsed
        let now = behind_since + IS_BEHIND_GRACE_PERIOD + Duration::from_secs(1);
        next_sync_state_helper(
            LedgerSyncState::MaybeBehind(behind_since),
            true,
            now,
            LedgerSyncState::IsBehind {
                attempt_sync_at: now,
                num_sync_attempts: 0,
            },
            logger,
        );
    }

    #[test_with_logger]
    // Should correctly update `ledger_sync_state` if syncing blocks succeeds.
    fn test_sync_next_blocks_success(logger: Logger) {
        let (node_id, _local_node_uri, msg_signer_key) = get_local_node_config(11);
        let mut rng: StdRng = SeedableRng::from_seed([97u8; 32]);
        let peers = get_peers(&[22, 33], &mut rng);
        let quorum_set =
            QuorumSet::new_with_node_ids(2, vec![peers[0].id.clone(), peers[1].id.clone()]);

        let num_blocks = 12;
        let (enclave, scp_node, ledger, mut ledger_sync, tx_manager, mint_tx_manager, broadcast) =
            get_mocks(&node_id, &quorum_set, num_blocks);
        let connection_manager = get_connection_manager(&node_id, &peers, &logger);
        let (_task_sender, task_receiver) = get_channel();

        // `attempt_ledger_sync` should succeed.
        ledger_sync
            .expect_attempt_ledger_sync()
            .return_once(|_, _| Ok(())); // This is a hack because LedgerSyncError is not Clone.

        let mut worker = ByzantineLedgerWorker::new(
            enclave,
            Box::new(scp_node),
            msg_signer_key,
            ledger,
            ledger_sync,
            connection_manager,
            Arc::new(tx_manager),
            Arc::new(mint_tx_manager),
            Arc::new(Mutex::new(broadcast)),
            task_receiver,
            Arc::new(AtomicBool::new(false)),
            Arc::new(AtomicU64::new(0)),
            Arc::new(Mutex::new(Option::<ConsensusMsg>::None)),
            logger,
        );

        // The worker must be behind.
        let first_sync_at = Instant::now();
        worker.ledger_sync_state = LedgerSyncState::IsBehind {
            attempt_sync_at: first_sync_at,
            num_sync_attempts: 7,
        };

        let num_blocks = 58; // Arbitrary
        worker.sync_next_blocks(num_blocks);

        // Reset ledger_sync_state to IsBehind with zero sync attempts.
        match &worker.ledger_sync_state {
            LedgerSyncState::IsBehind {
                attempt_sync_at,
                num_sync_attempts,
            } => {
                assert!(*attempt_sync_at > first_sync_at);
                assert_eq!(*num_sync_attempts, 0);
            }

            _ => panic!("Unexpected"),
        }
    }

    #[test_with_logger]
    // Should correctly update `ledger_sync_state` if syncing blocks fails.
    fn test_sync_next_blocks_failure(logger: Logger) {
        let (node_id, _local_node_uri, msg_signer_key) = get_local_node_config(11);
        let mut rng: StdRng = SeedableRng::from_seed([97u8; 32]);
        let peers = get_peers(&[22, 33], &mut rng);
        let quorum_set =
            QuorumSet::new_with_node_ids(2, vec![peers[0].id.clone(), peers[1].id.clone()]);

        let num_blocks = 12;
        let (enclave, scp_node, ledger, mut ledger_sync, tx_manager, mint_tx_manager, broadcast) =
            get_mocks(&node_id, &quorum_set, num_blocks);
        let connection_manager = get_connection_manager(&node_id, &peers, &logger);
        let (_task_sender, task_receiver) = get_channel();

        // `attempt_ledger_sync` should fail.
        ledger_sync
            .expect_attempt_ledger_sync()
            .return_once(|_, _| Err(LedgerSyncError::NoSafeBlocks)); // This is a hack because LedgerSyncError is not Clone.

        let mut worker = ByzantineLedgerWorker::new(
            enclave,
            Box::new(scp_node),
            msg_signer_key,
            ledger,
            ledger_sync,
            connection_manager,
            Arc::new(tx_manager),
            Arc::new(mint_tx_manager),
            Arc::new(Mutex::new(broadcast)),
            task_receiver,
            Arc::new(AtomicBool::new(false)),
            Arc::new(AtomicU64::new(0)),
            Arc::new(Mutex::new(Option::<ConsensusMsg>::None)),
            logger,
        );

        // The worker must be behind.
        let first_sync_at = Instant::now();
        worker.ledger_sync_state = LedgerSyncState::IsBehind {
            attempt_sync_at: first_sync_at,
            num_sync_attempts: 7,
        };

        let num_blocks = 58; // Arbitrary
        worker.sync_next_blocks(num_blocks);

        // Increment the num_sync_atempts
        match &worker.ledger_sync_state {
            LedgerSyncState::IsBehind {
                attempt_sync_at,
                num_sync_attempts,
            } => {
                assert!(*attempt_sync_at > first_sync_at);
                assert_eq!(*num_sync_attempts, 8);
            }

            _ => panic!("Unexpected"),
        }
    }

    #[test_with_logger]
    fn test_receive_tasks(logger: Logger) {
        let (node_id, _local_node_uri, msg_signer_key) = get_local_node_config(11);
        let mut rng: StdRng = SeedableRng::from_seed([97u8; 32]);
        let peers = get_peers(&[22, 33], &mut rng);
        let quorum_set =
            QuorumSet::new_with_node_ids(2, vec![peers[0].id.clone(), peers[1].id.clone()]);

        let num_blocks = 12;
        let (
            enclave,
            scp_node,
            mut ledger,
            ledger_sync,
            mut tx_manager,
            mint_tx_manager,
            broadcast,
        ) = get_mocks(&node_id, &quorum_set, num_blocks);

        // Transaction hashes that will be submitted by clients.
        let tx_hashes: Vec<_> = (0..200).map(|i| TxHash([i as u8; 32])).collect();

        // The first 100 are valid.
        for tx_hash in &tx_hashes[0..100] {
            tx_manager
                .expect_validate()
                .with(eq(*tx_hash))
                .return_const(Ok(()));
        }

        // The next 3 have expired.
        for tx_hash in &tx_hashes[100..103] {
            tx_manager
                .expect_validate()
                .with(eq(*tx_hash))
                .return_const(Err(TxManagerError::TransactionValidation(
                    TransactionValidationError::TombstoneBlockExceeded,
                )));
        }

        // The rest are valid.
        for tx_hash in &tx_hashes[103..] {
            tx_manager
                .expect_validate()
                .with(eq(*tx_hash))
                .return_const(Ok(()));
        }

        let connection_manager = get_connection_manager(&node_id, &peers, &logger);
        let (task_sender, task_receiver) = get_channel();

        let previous_block = Block::new_origin_block(&[]);
        ledger
            .expect_get_block()
            .times(1)
            .return_const(Ok(previous_block));

        let verified_consensus_msg =
            get_verified_consensus_msg(&peers[0].id, &peers[0].signer_key, &ledger);

        let mut worker = ByzantineLedgerWorker::new(
            enclave,
            Box::new(scp_node),
            msg_signer_key,
            ledger,
            ledger_sync,
            connection_manager,
            Arc::new(tx_manager),
            Arc::new(mint_tx_manager),
            Arc::new(Mutex::new(broadcast)),
            task_receiver,
            Arc::new(AtomicBool::new(false)),
            Arc::new(AtomicU64::new(0)),
            Arc::new(Mutex::new(Option::<ConsensusMsg>::None)),
            logger,
        );

        // Should return true when the task queue is empty.
        assert!(worker.receive_tasks());

        // Should return false when a StopTrigger is consumed.
        task_sender.send(TaskMessage::StopTrigger).unwrap();
        assert!(!worker.receive_tasks());

        for tx_hash in &tx_hashes {
            task_sender
                .send(TaskMessage::Values(
                    Some(Instant::now()),
                    vec![ConsensusValue::TxHash(*tx_hash)],
                ))
                .unwrap();
        }
        // Initially, pending_values should be empty.
        assert!(worker.pending_values.is_empty());
        assert!(worker.receive_tasks());
        // Should maintain the invariant that pending_values only contains tx_hashes
        // corresponding to transactions that are valid w.r.t. the current ledger.
        assert_eq!(worker.pending_values.len(), tx_hashes.len() - 3);

        let responder_id = ResponderId::default();

        task_sender
            .send(TaskMessage::ConsensusMsg(
                verified_consensus_msg,
                responder_id,
            ))
            .unwrap();

        // Initially, pending_consensus_msgs should be empty.
        assert_eq!(worker.pending_consensus_msgs, vec![]);
        assert!(worker.receive_tasks());
        // The message from the task queue should now be pending.
        assert_eq!(worker.pending_consensus_msgs.len(), 1);
    }

    /// Should maintain the invariant that pending_values and pending_values map
    /// only contain tx_hashes corresponding to transactions that are valid
    /// w.r.t the current ledger.
    #[test_with_logger]
    fn receive_tasks_omits_expired_transactions(logger: Logger) {
        let (node_id, _local_node_uri, msg_signer_key) = get_local_node_config(11);
        let mut rng: StdRng = SeedableRng::from_seed([97u8; 32]);
        let peers = get_peers(&[22, 33], &mut rng);
        let quorum_set =
            QuorumSet::new_with_node_ids(2, vec![peers[0].id.clone(), peers[1].id.clone()]);

        let num_blocks = 12;
        let (enclave, scp_node, ledger, ledger_sync, mut tx_manager, mint_tx_manager, broadcast) =
            get_mocks(&node_id, &quorum_set, num_blocks);

        let connection_manager = get_connection_manager(&node_id, &peers, &logger);
        let (task_sender, task_receiver) = get_channel();

        // Transaction hashes that will be submitted by clients.
        let tx_hashes: Vec<_> = (0..10).map(|i| TxHash([i as u8; 32])).collect();

        // Configure mock TxManager. All transactions have expired.
        for tx_hash in &tx_hashes {
            tx_manager
                .expect_validate()
                .with(eq(*tx_hash))
                .return_const(Err(TxManagerError::TransactionValidation(
                    TransactionValidationError::TombstoneBlockExceeded,
                )));
        }

        let mut worker = ByzantineLedgerWorker::new(
            enclave,
            Box::new(scp_node),
            msg_signer_key,
            ledger,
            ledger_sync,
            connection_manager,
            Arc::new(tx_manager),
            Arc::new(mint_tx_manager),
            Arc::new(Mutex::new(broadcast)),
            task_receiver,
            Arc::new(AtomicBool::new(false)),
            Arc::new(AtomicU64::new(0)),
            Arc::new(Mutex::new(Option::<ConsensusMsg>::None)),
            logger,
        );

        // Initially, pending_values should be empty.
        assert_eq!(worker.pending_values.len(), 0);

        // Submit the transactions.
        for tx_hash in &tx_hashes {
            task_sender
                .send(TaskMessage::Values(
                    Some(Instant::now()),
                    vec![ConsensusValue::TxHash(*tx_hash)],
                ))
                .unwrap();
        }

        assert!(worker.receive_tasks());
        // Should maintain the invariant that pending_values and pending_values map
        // only contain tx_hashes corresponding to transactions that are valid w.r.t the
        // current ledger.
        assert_eq!(worker.pending_values.len(), 0);
    }

    /// Constructs a VerifiedConsensusMsg.
    ///
    /// # Arguments
    /// * `sender_id` - Sender of the message.
    /// * `signer_key` - The sender's message signing keypair.
    /// * `ledger` - The sender's local ledger.
    fn get_verified_consensus_msg<L: Ledger>(
        sender_id: &NodeID,
        signer_key: &Ed25519Pair,
        ledger: &L,
    ) -> VerifiedConsensusMsg {
        let msg: Msg<ConsensusValue, NodeID> = Msg {
            sender_id: sender_id.clone(),
            slot_index: 1,
            quorum_set: QuorumSet {
                threshold: 0,
                members: vec![],
            },
            topic: Nominate(NominatePayload {
                X: Default::default(),
                Y: Default::default(),
            }),
        };

        let consensus_msg = ConsensusMsg::from_scp_msg(ledger, msg, signer_key).unwrap();
        VerifiedConsensusMsg::try_from(consensus_msg).unwrap()
    }

    #[test_with_logger]
    fn test_propose_pending_values(logger: Logger) {
        let (node_id, _local_node_uri, msg_signer_key) = get_local_node_config(11);
        let mut rng: StdRng = SeedableRng::from_seed([97u8; 32]);
        let peers = get_peers(&[22, 33], &mut rng);
        let quorum_set =
            QuorumSet::new_with_node_ids(2, vec![peers[0].id.clone(), peers[1].id.clone()]);

        let num_blocks = 12;
        let (
            enclave,
            mut scp_node,
            ledger,
            ledger_sync,
            mut tx_manager,
            mint_tx_manager,
            broadcast,
        ) = get_mocks(&node_id, &quorum_set, num_blocks);
        let connection_manager = get_connection_manager(&node_id, &peers, &logger);
        let (_task_sender, task_receiver) = get_channel();

        // `validate` will be called one for each pushed value.
        tx_manager.expect_validate().return_const(Ok(()));

        // Up to MAX_PENDING_VALUES_TO_NOMINATE values should be proposed to the
        // scp_node.
        scp_node
            .expect_propose_values()
            .times(1)
            .withf(|values| values.len() <= MAX_PENDING_VALUES_TO_NOMINATE)
            .return_const(Ok(None));

        let mut worker = ByzantineLedgerWorker::new(
            enclave,
            Box::new(scp_node),
            msg_signer_key,
            ledger,
            ledger_sync,
            connection_manager,
            Arc::new(tx_manager),
            Arc::new(mint_tx_manager),
            Arc::new(Mutex::new(broadcast)),
            task_receiver,
            Arc::new(AtomicBool::new(false)),
            Arc::new(AtomicU64::new(0)),
            Arc::new(Mutex::new(Option::<ConsensusMsg>::None)),
            logger,
        );

        // Create more than MAX_PENDING_VALUES_TO_NOMINATE pending values.
        let tx_hashes: Vec<_> = (0..MAX_PENDING_VALUES_TO_NOMINATE * 2)
            .map(|i| TxHash([i as u8; 32]))
            .collect();
        for tx_hash in tx_hashes {
            worker
                .pending_values
                .push(tx_hash.into(), Some(Instant::now()));
        }
        worker.need_nominate = true;

        worker.propose_pending_values();
    }

    #[test_with_logger]
    fn test_complete_current_slot_forms_block_successfully(logger: Logger) {
        let mut rng: StdRng = SeedableRng::from_seed([77u8; 32]);
        let block_version = BlockVersion::MAX;
        let sender = AccountKey::random(&mut rng);
        let recipient = AccountKey::random(&mut rng);
        let mut ledger = create_ledger();
        let n_blocks = 1;
        initialize_ledger(block_version, &mut ledger, n_blocks, &sender, &mut rng);

        let origin_block_contents = ledger.get_block_contents(0).unwrap();

        let txs: Vec<Tx> = (0..3)
            .map(|i| {
                let tx_out = origin_block_contents.outputs[i].clone();

                create_transaction(
                    block_version,
                    &ledger,
                    &tx_out,
                    &sender,
                    &recipient.default_subaddress(),
                    n_blocks + 10,
                    &mut rng,
                )
            })
            .collect();

        let (local_node_id, _local_node_uri, msg_signer_key) = get_local_node_config(11);

        // Local node's quorum set.
        let peers = get_peers(&[22, 33], &mut rng);
        let quorum_set =
            QuorumSet::new_with_node_ids(2, vec![peers[0].id.clone(), peers[1].id.clone()]);

        let (
            _enclave,
            mut scp_node,
            _ledger,
            mut ledger_sync,
            _tx_manager,
            _mint_tx_manager,
            broadcast,
        ) = get_mocks(&local_node_id, &quorum_set, n_blocks);
        let enclave = ConsensusServiceMockEnclave::default();
        let attestation_evidence = enclave.get_attestation_evidence().unwrap();

        let tx_manager = TxManagerImpl::new(
            enclave.clone(),
            DefaultTxManagerUntrustedInterfaces::new(ledger.clone()),
            logger.clone(),
        );

        let connection_manager = get_connection_manager(&local_node_id, &peers, &logger);

        let (_task_sender, task_receiver) = get_channel();

        let hash_tx1 = tx_manager
            .insert(ConsensusServiceMockEnclave::tx_to_tx_context(&txs[0]))
            .unwrap();

        let hash_tx2 = tx_manager
            .insert(ConsensusServiceMockEnclave::tx_to_tx_context(&txs[1]))
            .unwrap();

        let hash_tx3 = tx_manager
            .insert(ConsensusServiceMockEnclave::tx_to_tx_context(&txs[2]))
            .unwrap();

        // Generate a minting transaction.
        let token_id1 = TokenId::from(2);
        let (mint_config_tx1, signers1) = create_mint_config_tx_and_signers(token_id1, &mut rng);
        let mint_recipient = AccountKey::random(&mut rng);

        let mint_tx1 = create_mint_tx_to_recipient(
            token_id1,
            &signers1,
            12,
            &mint_recipient.default_subaddress(),
            &mut rng,
        );

        // Put MintConfigTx into the ledger so that MintTxManager::mint_txs_with_config
        // can resolve it.
        let block_contents = BlockContents {
            validated_mint_config_txs: vec![mint_config_tx_to_validated(&mint_config_tx1)],
            ..Default::default()
        };
        add_block_contents_to_ledger(&mut ledger, block_version, block_contents, &mut rng).unwrap();

        let signer_set1 = SignerSet::new(signers1.iter().map(|s| s.public_key()).collect(), 1);
        let governors_map = GovernorsMap::try_from_iter([(token_id1, signer_set1)]).unwrap();
        let mint_tx_manager =
            MintTxManagerImpl::new(ledger.clone(), block_version, governors_map, logger.clone());

        // Configure our mocks to land us into complete_current_slot
        ledger_sync.expect_is_behind().return_const(false);
        scp_node
            .expect_max_externalized_slots()
            .return_const(5_usize);
        scp_node.expect_process_timeouts().return_const(Vec::new());
        scp_node.expect_get_externalized_values().return_const(vec![
            ConsensusValue::TxHash(hash_tx1),
            ConsensusValue::TxHash(hash_tx2),
            ConsensusValue::TxHash(hash_tx3),
            ConsensusValue::MintTx(mint_tx1.clone()),
        ]);
        scp_node
            .expect_get_current_slot_metrics()
            .returning(|| SlotMetrics {
                phase: Phase::Externalize,
                num_voted_nominated: 0,
                num_accepted_nominated: 0,
                num_confirmed_nominated: 0,
                cur_nomination_round: 0,
                bN: 0,
            });

        let mut worker = ByzantineLedgerWorker::new(
            enclave,
            Box::new(scp_node),
            msg_signer_key,
            ledger.clone(),
            ledger_sync,
            connection_manager,
            Arc::new(tx_manager),
            Arc::new(mint_tx_manager),
            Arc::new(Mutex::new(broadcast)),
            task_receiver,
            Arc::new(AtomicBool::new(false)),
            Arc::new(AtomicU64::new(0)),
            Arc::new(Mutex::new(Option::<ConsensusMsg>::None)),
            logger,
        );

        worker.tick();

        // A new block should appear, with the outputs of our transactions.
        let block_data = ledger
            .get_block_data(ledger.num_blocks().unwrap() - 1)
            .unwrap();
        let block = block_data.block();
        let block_contents = block_data.contents();
        let parent_block = ledger.get_block(block.index - 1).unwrap();

        assert_eq!(block.index, parent_block.index + 1);
        assert_eq!(block.parent_id, parent_block.id);

        // The mock enclave does not mint a fee output, so the number of outputs matches
        // the number of transactions that we fed into it.
        assert_eq!(block_contents.outputs.len(), 4);

        assert!(block_contents.outputs.contains(&txs[0].prefix.outputs[0]));
        assert!(block_contents.outputs.contains(&txs[1].prefix.outputs[0]));
        assert!(block_contents.outputs.contains(&txs[2].prefix.outputs[0]));

        // Our mint tx should make it into the block.
        assert_eq!(block_contents.mint_txs, vec![mint_tx1]);

        // The block should have a signature and metadata.
        assert!(block_data.signature().is_some());

        let metadata = block_data.metadata().expect("missing metadata");
        metadata
            .verify()
            .expect("worker produced invalid signature");
        let contents = metadata.contents();
        assert_eq!(&block.id, contents.block_id());
        assert_eq!(&quorum_set, contents.quorum_set());
        let prost_evidence = prost::DcapEvidence::try_from(&attestation_evidence)
            .expect("Failed decoding attestation evidence");
        assert_eq!(
            &AttestationEvidence::DcapEvidence(prost_evidence),
            contents.attestation_evidence()
        );
        assert_eq!(&local_node_id.responder_id, contents.responder_id());
    }

    // TODO: test process_consensus_msgs

    // TODO: test fetch_missing_txs

    // TODO: test issue_consensus_message
}
