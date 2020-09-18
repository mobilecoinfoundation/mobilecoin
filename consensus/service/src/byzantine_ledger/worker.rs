// Copyright (c) 2018-2020 MobileCoin Inc.

use crate::{
    byzantine_ledger::{
        ledger_sync_state::LedgerSyncState, task_message::TaskMessage, IS_BEHIND_GRACE_PERIOD,
        MAX_PENDING_VALUES_TO_NOMINATE,
    },
    counters,
    tx_manager::TxManager,
};
use mc_common::{
    logger::{log, Logger},
    ResponderId,
};
use mc_connection::{
    BlockchainConnection, ConnectionManager,
    _retry::{delay::Fibonacci, Error as RetryError},
};
use mc_consensus_scp::{slot::Phase, Msg, ScpNode, SlotIndex};
use mc_crypto_keys::Ed25519Pair;
use mc_ledger_db::Ledger;
use mc_ledger_sync::{LedgerSync, NetworkState, SCPNetworkState};
use mc_peers::{
    Broadcast, ConsensusConnection, ConsensusMsg, Error as PeerError, RetryableConsensusConnection,
    VerifiedConsensusMsg,
};
use mc_transaction_core::tx::TxHash;
use mc_util_metered_channel::Receiver;
use rayon::iter::{IntoParallelIterator, ParallelIterator};
use std::{
    cmp::min,
    collections::{hash_map::Entry::Vacant, BTreeSet, HashMap},
    iter::FromIterator,
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
    L: Ledger + 'static,
    LS: LedgerSync<SCPNetworkState> + Send + 'static,
    PC: BlockchainConnection + ConsensusConnection + 'static,
    TXM: TxManager,
> {
    scp_node: Box<dyn ScpNode<TxHash>>,
    msg_signer_key: Arc<Ed25519Pair>,

    connection_manager: ConnectionManager<PC>,
    broadcaster: Arc<Mutex<dyn Broadcast>>,
    tx_manager: Arc<TXM>,
    // A map of responder id to a list of tx hashes that it is unable to provide. This allows us to
    // skip attempting to fetch txs that are bound to fail. A BTreeSet is used to speed up lookups
    // as expect to be doing more lookups than inserts.
    unavailable_tx_hashes: HashMap<ResponderId, BTreeSet<TxHash>>,

    // Current slot index (the one that is not yet in the ledger / the one currently being worked on).
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

    // Pending transactions we're trying to push. We need to store them as a vec so we can process values
    // on a first-come first-served basis. However, we want to be able to:
    // 1) Efficiently see if we already have a given transaction and ignore duplicates
    // 2) Track how long each transaction took to externalize.
    //
    // To accomplish these goals we store, in addition to the queue of pending values, a
    // map that maps a value to when we first encountered it. Note that we only store a
    // timestamp for values that were handed to us directly from a client. We skip tracking
    // processing times for relayed values since we want to track the time from when the network
    // first saw a value, and not when a specific node saw it.
    pending_values: Vec<TxHash>,
    pending_values_map: HashMap<TxHash, Option<Instant>>,

    // Set to true when the worker has pending values that have not yet been proposed to the scp_node.
    need_nominate: bool,

    logger: Logger,
}

impl<
        L: Ledger + 'static,
        LS: LedgerSync<SCPNetworkState> + Send + 'static,
        PC: BlockchainConnection + ConsensusConnection + 'static,
        TXM: TxManager + Send + Sync,
    > ByzantineLedgerWorker<L, LS, PC, TXM>
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
    /// * `broadcaster` - Broadcaster
    /// * `tasks` - Receiver-end of a queue of task messages for this worker to process.
    /// * `is_behind` - Worker sets to true when the local node is behind its peers.
    /// * `highest_peer_block` - Worker sets to highest block index that the network agrees on.
    /// * `highest_issued_msg` - Worker sets to highest consensus message issued by this node.
    /// * `logger`  
    pub fn new(
        scp_node: Box<dyn ScpNode<TxHash>>,
        msg_signer_key: Arc<Ed25519Pair>,
        ledger: L,
        ledger_sync_service: LS,
        connection_manager: ConnectionManager<PC>,
        tx_manager: Arc<TXM>,
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
            tasks,
            scp_node,
            msg_signer_key,
            is_behind,
            highest_peer_block,
            highest_issued_msg,
            ledger,
            tx_manager,
            broadcaster,
            connection_manager,
            logger,
            current_slot_index,
            pending_consensus_msgs: Default::default(),
            pending_values: Vec::new(),
            pending_values_map: Default::default(),
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
        assert_eq!(self.pending_values.len(), self.pending_values_map.len()); // Invariant

        if !self.receive_tasks() {
            // Stop requested
            return false;
        }

        // Update ledger_sync_state.
        let sync_service_is_behind = self.ledger_sync_service.is_behind(&self.network_state);
        match (self.ledger_sync_state.clone(), sync_service_is_behind) {
            // Fully in sync, nothing to do.
            (LedgerSyncState::InSync, false) => {}

            // Sync service reports we're behind and we are just finding out about it now.
            (LedgerSyncState::InSync, true) => {
                log::info!(self.logger, "sync_service reported we are behind, we're at slot {} and network state is {:?}", self.current_slot_index, self.network_state.peer_to_current_slot());
                self.ledger_sync_state = LedgerSyncState::MaybeBehind(Instant::now());
            }

            // Sync service reports we're behind and we're maybe behind, see if enough time has
            // passed to move to IsBehind.
            (LedgerSyncState::MaybeBehind(behind_since), true) => {
                let is_behind_duration = Instant::now() - behind_since;
                if is_behind_duration > IS_BEHIND_GRACE_PERIOD {
                    log::warn!(
                        self.logger,
                        "sync_service reports we are behind, and we are past the grace period on slot {}!",
                        self.current_slot_index,
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

                // Clear any pending values that might no longer be valid.
                let tx_manager = self.tx_manager.clone();
                self.pending_values_map
                    .retain(|tx_hash, _| tx_manager.validate(tx_hash).is_ok());
                // help the borrow checker
                let self_pending_values_map = &self.pending_values_map;
                self.pending_values
                    .retain(|tx_hash| self_pending_values_map.contains_key(tx_hash));

                debug_assert!(self.pending_values_map.len() == self.pending_values.len());

                // Nominate if needed.
                if !self.pending_values.is_empty() {
                    self.need_nominate = true;
                }

                // Update state.
                self.is_behind.store(false, Ordering::SeqCst);
                self.ledger_sync_state = LedgerSyncState::InSync;
                self.current_slot_index = self.ledger.num_blocks().unwrap();

                // Reset scp state.
                self.scp_node.reset_slot_index(self.current_slot_index);
            }
        };

        // Sanity - code here should never run if we're behind.
        assert!(!self.is_behind.load(Ordering::SeqCst));
        if let LedgerSyncState::IsBehind { .. } = &self.ledger_sync_state {
            unreachable!();
        }

        // Nominate values for current slot.
        if self.need_nominate {
            self.nominate_pending_values();
        }

        // Process any queues consensus messages.
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

    // Reads tasks from the task queue.
    // Returns false if the worker has been asked to stop.
    fn receive_tasks(&mut self) -> bool {
        for task_msg in self.tasks.try_iter() {
            match task_msg {
                // Transactions submitted by clients.
                TaskMessage::Values(timestamp, new_values) => {
                    for tx_hash in new_values {
                        if let Vacant(entry) = self.pending_values_map.entry(tx_hash) {
                            // A new value.
                            entry.insert(timestamp);
                            self.pending_values.push(tx_hash);
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

    fn nominate_pending_values(&mut self) {
        assert!(!self.pending_values.is_empty());

        let msg_opt = self
            .scp_node
            .propose_values(BTreeSet::from_iter(
                self.pending_values
                    .iter()
                    .take(MAX_PENDING_VALUES_TO_NOMINATE)
                    .cloned(),
            ))
            .expect("nominate failed");

        if let Some(msg) = msg_opt {
            let _ = self.issue_consensus_message(msg);
        }

        self.need_nominate = false;
    }

    // Process messages for current slot and recent previous slots; retain messages for future slots.
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
                consensus_msg.scp_msg().to_display(),
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
                    .broadcast_consensus_msg(consensus_msg.as_ref(), &from_responder_id);
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

    fn complete_current_slot(&mut self, externalized: Vec<TxHash>) {
        // Update pending value processing time metrics.
        for tx_hash in externalized.iter() {
            if let Some(Some(timestamp)) = self.pending_values_map.get(tx_hash) {
                let duration = Instant::now().saturating_duration_since(*timestamp);
                counters::PENDING_VALUE_PROCESSING_TIME.observe(duration.as_secs_f64());
            }
        }

        // Invariant: pending_values only contains valid values that were not externalized.
        self.pending_values
            .retain(|tx_hash| !externalized.contains(tx_hash));

        log::info!(
            self.logger,
            "Slot {} ended with {} externalized values and {} pending values.",
            self.current_slot_index,
            externalized.len(),
            self.pending_values.len(),
        );

        let num_blocks = self
            .ledger
            .num_blocks()
            .expect("Ledger must contain a block.");
        let parent_block = self
            .ledger
            .get_block(num_blocks - 1)
            .expect("Ledger must contain a block.");
        let (block, block_contents, signature) = self
            .tx_manager
            .tx_hashes_to_block(&externalized, &parent_block)
            .unwrap_or_else(|e| panic!("Failed to build block from {:?}: {:?}", externalized, e));

        log::info!(
            self.logger,
            "Appending block {} to ledger (sig: {}, tx_hashes: {:?}).",
            block.index,
            signature,
            &externalized,
        );

        self.ledger
            .append_block(&block, &block_contents, Some(signature))
            .expect("failed appending block");

        counters::TX_EXTERNALIZED_COUNT.inc_by(externalized.len() as i64);

        // Update current slot index.
        self.current_slot_index = {
            let current_slot_index: SlotIndex = self.ledger.num_blocks().unwrap();
            assert_eq!(current_slot_index, self.current_slot_index + 1);
            current_slot_index
        };

        // Purge transactions that can no longer be processed based on their tombstone block.
        let max_externalized_slots = self.scp_node.max_externalized_slots() as u64;
        let purged_hashes = {
            let index = self
                .current_slot_index
                .saturating_sub(max_externalized_slots);
            self.tx_manager.remove_expired(index)
        };

        // Drop pending values that are no longer considered valid.
        let tx_manager = self.tx_manager.clone();
        self.pending_values_map.retain(|tx_hash, _| {
            !purged_hashes.contains(tx_hash) && tx_manager.validate(tx_hash).is_ok()
        });
        // help the borrow checker
        let self_pending_values_map = &self.pending_values_map;
        self.pending_values
            .retain(|tx_hash| self_pending_values_map.contains_key(tx_hash));

        debug_assert!(self.pending_values_map.len() == self.pending_values.len());

        log::info!(
            self.logger,
            "Number of pending values post cleanup: {} ({} expired)",
            self.pending_values.len(),
            purged_hashes.len(),
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
        // Hashes of transactions that are not currently cached.
        let missing_hashes: Vec<TxHash> = scp_msg
            .values()
            .into_iter()
            .filter(|tx_hash| !self.tx_manager.contains(tx_hash))
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
            match conn.fetch_txs(&chunk, Fibonacci::from_millis(100).take(10)) {
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
                Err(RetryError::Operation {
                    error: PeerError::TxHashesNotInCache(tx_hashes),
                    ..
                }) => {
                    let entry = self
                        .unavailable_tx_hashes
                        .entry(from_responder_id.clone())
                        .or_insert_with(BTreeSet::default);
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
    fn issue_consensus_message(&mut self, msg: Msg<TxHash>) -> Result<(), &'static str> {
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
}

#[cfg(test)]
mod tests {
    use crate::{
        byzantine_ledger::{
            ledger_sync_state::LedgerSyncState,
            tests::{get_local_node_config, get_peers},
            worker::ByzantineLedgerWorker,
        },
        tx_manager::MockTxManager,
    };
    use mc_common::logger::{test_with_logger, Logger};
    use mc_connection::ConnectionManager;
    use mc_consensus_scp::{MockScpNode, QuorumSet};
    use mc_ledger_db::MockLedger;
    use mc_ledger_sync::MockLedgerSync;
    use mc_peers::{ConsensusMsg, MockBroadcast};
    use mc_peers_test_utils::MockPeerConnection;
    use mc_util_metrics::OpMetrics;
    use rand::rngs::StdRng;
    use rand_core::SeedableRng;
    use std::sync::{
        atomic::{AtomicBool, AtomicU64},
        Arc, Mutex,
    };

    #[test_with_logger]
    /// Test that `new` correctly initializes the instance.
    fn test_new(logger: Logger) {
        let mut rng: StdRng = SeedableRng::from_seed([7u8; 32]);
        let (local_node_id, _local_node_uri, msg_signer_key) = get_local_node_config(11);

        // Local node's quorum set.
        let peers = get_peers(&[22, 33], &mut rng);
        let local_quorum_set =
            QuorumSet::new_with_node_ids(2, vec![peers[0].id.clone(), peers[1].id.clone()]);

        let mut scp_node = MockScpNode::new();
        scp_node
            .expect_node_id()
            .return_const(local_node_id.clone());
        scp_node.expect_quorum_set().return_const(local_quorum_set);

        let mut ledger = MockLedger::new();
        let num_blocks: u64 = 15;
        ledger.expect_num_blocks().return_const(Ok(num_blocks));

        let ledger_sync_service = MockLedgerSync::new();

        let connection_manager = {
            let ledger = MockLedger::new();
            ConnectionManager::new(
                vec![MockPeerConnection::new(
                    peers[0].uri.clone(),
                    local_node_id.clone(),
                    ledger,
                    10,
                )],
                logger.clone(),
            )
        };

        let tx_manager = MockTxManager::new();
        let broadcaster = MockBroadcast::new();

        let gauge = OpMetrics::new("test").gauge("byzantine_ledger_msg_queue_size");
        let (_task_sender, task_receiver) = mc_util_metered_channel::unbounded(&gauge);

        let is_behind = Arc::new(AtomicBool::new(false));
        let highest_peer_block = Arc::new(AtomicU64::new(0));
        let highest_issued_msg = Arc::new(Mutex::new(Option::<ConsensusMsg>::None));

        let worker = ByzantineLedgerWorker::new(
            Box::new(scp_node),
            msg_signer_key,
            ledger,
            ledger_sync_service,
            connection_manager,
            Arc::new(tx_manager),
            Arc::new(Mutex::new(broadcaster)),
            task_receiver,
            is_behind,
            highest_peer_block,
            highest_issued_msg,
            logger,
        );

        // current_slot_index should be initialized from the ledger.
        assert_eq!(worker.current_slot_index, num_blocks);

        // Initially, the worker should think that its ledger is in sync with the network.
        assert_eq!(worker.ledger_sync_state, LedgerSyncState::InSync);
    }
}
