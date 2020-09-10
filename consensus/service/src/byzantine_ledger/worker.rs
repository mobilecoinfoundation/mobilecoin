// Copyright (c) 2018-2020 MobileCoin Inc.

use crate::{
    byzantine_ledger::{
        ledger_sync_state::LedgerSyncState, task_message::TaskMessage, IS_BEHIND_GRACE_PERIOD,
        MAX_PENDING_VALUES_TO_NOMINATE,
    },
    counters,
    tx_manager::{TxManager, TxManagerError},
};
use mc_common::{
    logger::{log, Logger},
    NodeID, ResponderId,
};
use mc_connection::{
    BlockchainConnection, ConnectionManager,
    _retry::{delay::Fibonacci, Error as RetryError},
};
use mc_consensus_scp::{slot::Phase, Msg, QuorumSet, ScpNode, SlotIndex};
use mc_ledger_db::Ledger;
use mc_ledger_sync::{
    LedgerSyncService, NetworkState, ReqwestTransactionsFetcher, SCPNetworkState,
};
use mc_peers::{
    Broadcast, ConsensusConnection, Error as PeerError, RetryableConsensusConnection,
    VerifiedConsensusMsg,
};
use mc_transaction_core::{tx::TxHash, BlockID};
use mc_util_metered_channel::Receiver;
use rayon::iter::{IntoParallelIterator, ParallelIterator};
use std::{
    cmp::min,
    collections::{btree_map::Entry::Vacant, BTreeMap, BTreeSet, HashMap},
    iter::FromIterator,
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc, Mutex,
    },
    thread,
    time::{Duration, Instant},
};

pub struct ByzantineLedgerWorker<
    F: Fn(Msg<TxHash>),
    L: Ledger + 'static,
    PC: BlockchainConnection + ConsensusConnection + 'static,
    TXM: TxManager,
> {
    receiver: Receiver<TaskMessage>,
    scp: Box<dyn ScpNode<TxHash>>,
    is_behind: Arc<AtomicBool>,
    highest_peer_block: Arc<AtomicU64>,
    send_scp_message: F,
    ledger: L,
    peer_manager: ConnectionManager<PC>,
    tx_manager: Arc<TXM>,
    broadcaster: Arc<Mutex<dyn Broadcast>>,
    logger: Logger,

    // Current slot index (the one that is not yet in the ledger / the one currently being worked on).
    current_slot_index: SlotIndex,

    // Previous block id
    prev_block_id: BlockID,

    // Pending scp messages we need to process.
    pending_consensus_msgs: Vec<(VerifiedConsensusMsg, ResponderId)>,

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

    // A map of responder id to a list of tx hashes that it is unable to provide. This allows us to
    // skip attempting to fetch txs that are bound to fail. A BTreeSet is used to speed up lookups
    // as expect to be doing more lookups than inserts.
    unavailable_tx_hashes: HashMap<ResponderId, BTreeSet<TxHash>>,
}

impl<
        F: Fn(Msg<TxHash>),
        L: Ledger + Clone + 'static,
        PC: BlockchainConnection + ConsensusConnection + 'static,
        TXM: TxManager + Send + Sync,
    > ByzantineLedgerWorker<F, L, PC, TXM>
{
    pub fn start(
        node_id: NodeID,
        quorum_set: QuorumSet,
        receiver: Receiver<TaskMessage>,
        scp: Box<dyn ScpNode<TxHash>>,
        is_behind: Arc<AtomicBool>,
        highest_peer_block: Arc<AtomicU64>,
        send_scp_message: F,
        ledger: L,
        peer_manager: ConnectionManager<PC>,
        tx_manager: Arc<TXM>,
        broadcaster: Arc<Mutex<dyn Broadcast>>,
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

            current_slot_index: cur_slot,
            prev_block_id,
            pending_consensus_msgs: Default::default(),
            pending_values: Vec::new(),
            pending_values_map: BTreeMap::default(),
            need_nominate: false,
            network_state,
            ledger_sync_service,
            ledger_sync_state: LedgerSyncState::InSync,
            unavailable_tx_hashes: HashMap::default(),
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
                log::info!(self.logger, "sync_service reported we are behind, we're at slot {} and network state is {:?}", self.current_slot_index, self.network_state.peer_to_current_slot());
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
                self.pending_values
                    .retain(|tx_hash| tx_manager.validate(tx_hash).is_ok());

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
                self.current_slot_index = self.ledger.num_blocks().unwrap();
                self.prev_block_id = self
                    .ledger
                    .get_block(self.current_slot_index - 1)
                    .unwrap()
                    .id;

                // Reset scp state.
                self.scp.reset_slot_index(self.current_slot_index);
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
        self.process_consensus_msgs();

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
            match task_msg {
                // Values submitted by a client.
                TaskMessage::Values(timestamp, new_values) => {
                    for value in new_values {
                        // A new value.
                        if let Vacant(entry) = self.pending_values_map.entry(value) {
                            entry.insert(timestamp);
                            self.pending_values.push(value);
                            self.need_nominate = true;
                        }
                    }
                }

                // SCP Statement
                TaskMessage::ConsensusMsg(consensus_msg, from_responder_id) => {
                    // Only look at messages that are not for past slots.
                    if consensus_msg.scp_msg().slot_index >= self.current_slot_index {
                        // Used to detect when we are behind.
                        self.network_state.push(consensus_msg.scp_msg().clone());

                        self.pending_consensus_msgs
                            .push((consensus_msg, from_responder_id));
                    }
                }

                // Request to stop thread
                TaskMessage::StopTrigger => {
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
            .propose_values(BTreeSet::from_iter(
                self.pending_values
                    .iter()
                    .take(MAX_PENDING_VALUES_TO_NOMINATE)
                    .cloned(),
            ))
            .expect("nominate failed");

        if let Some(msg) = msg_opt {
            (self.send_scp_message)(msg)
        }

        self.need_nominate = false;
    }

    // Process messages for current slot and recent previous slots; retain messages for future slots.
    fn process_consensus_msgs(&mut self) {
        // Process messages for slot indices in [oldest_slot, current_slot].
        let current_slot = self.current_slot_index;
        let max_externalized_slots = self.scp.max_externalized_slots() as u64;
        let oldest_slot = current_slot.saturating_sub(max_externalized_slots);
        let (consensus_msgs, future_msgs): (Vec<_>, Vec<_>) = self
            .pending_consensus_msgs
            .drain(..)
            // We do not perform consensus on the origin block.
            .filter(|(consensus_msg, _)| consensus_msg.scp_msg().slot_index != 0)
            .filter(|(consensus_msg, _)| consensus_msg.scp_msg().slot_index >= oldest_slot)
            .partition(|(consensus_msg, _)| consensus_msg.scp_msg().slot_index <= current_slot);

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
        let batch_size = 5;
        for chunk in compatible_msgs.chunks(batch_size) {
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

            match self.scp.handle_messages(scp_msgs) {
                Ok(outgoing_msgs) => {
                    for msg in outgoing_msgs {
                        (self.send_scp_message)(msg);
                    }
                }
                Err(err) => {
                    log::error!(self.logger, "Failed handling messages: {:?}", err);
                }
            }
        }
    }

    fn attempt_complete_cur_slot(&mut self) {
        // See if we have externalized values for the current slot.
        match self.scp.get_externalized_values(self.current_slot_index) {
            None => {}
            Some(ext_vals) => {
                // Update pending value processing time metrics.
                for value in ext_vals.iter() {
                    if let Some(Some(timestamp)) = self.pending_values_map.get(value) {
                        let duration = Instant::now().saturating_duration_since(*timestamp);
                        counters::PENDING_VALUE_PROCESSING_TIME.observe(duration.as_secs_f64());
                    }
                }

                // Invariant: pending_values only contains valid values that were not externalized.
                self.pending_values
                    .retain(|tx_hash| !ext_vals.contains(tx_hash));

                log::info!(
                    self.logger,
                    "Slot {} ended with {} externalized values and {} pending values.",
                    self.current_slot_index,
                    ext_vals.len(),
                    self.pending_values.len(),
                );

                // Write to ledger.
                let block_id = {
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
                        .tx_hashes_to_block(&ext_vals, &parent_block)
                        .unwrap_or_else(|e| {
                            panic!("Failed to build block from {:?}: {:?}", ext_vals, e)
                        });

                    log::info!(
                        self.logger,
                        "Appending block {} to ledger (sig: {}, tx_hashes: {:?}).",
                        block.index,
                        signature,
                        ext_vals,
                    );

                    self.ledger
                        .append_block(&block, &block_contents, Some(signature))
                        .expect("failed appending block");

                    counters::TX_EXTERNALIZED_COUNT.inc_by(ext_vals.len() as i64);

                    block.id
                };

                // Sanity check + update current slot.
                let current_slot_index =
                    self.ledger.num_blocks().expect("num blocks failed") as SlotIndex;

                assert_eq!(current_slot_index, self.current_slot_index + 1);

                self.current_slot_index = current_slot_index;
                self.prev_block_id = block_id;

                // Purge transactions that can no longer be processed based on their tombstone block.
                let max_externalized_slots = self.scp.max_externalized_slots() as u64;
                let purged_hashes = {
                    let index = current_slot_index.saturating_sub(max_externalized_slots);
                    self.tx_manager.remove_expired(index)
                };

                counters::TX_CACHE_NUM_ENTRIES.set(self.tx_manager.num_entries() as i64);

                // Drop pending values that are no longer considered valid.
                let tx_manager = self.tx_manager.clone();
                self.pending_values.retain(|tx_hash| {
                    !purged_hashes.contains(tx_hash) && tx_manager.validate(tx_hash).is_ok()
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

                // Previous slot metrics.
                counters::PREV_SLOT_NUMBER.set((current_slot_index - 1) as i64);
                counters::PREV_SLOT_ENDED_AT.set(chrono::Utc::now().timestamp_millis());
                counters::PREV_SLOT_NUM_EXT_VALS.set(ext_vals.len() as i64);
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
                            Ok(_) | Err(TxManagerError::AlreadyInCache) => {}
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

    fn update_cur_metrics(&mut self) {
        let slot_metrics = self.scp.get_current_slot_metrics();
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
