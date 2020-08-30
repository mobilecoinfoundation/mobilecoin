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
    collections::{btree_map::Entry::Vacant, BTreeMap, BTreeSet, HashMap, VecDeque},
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
    _broadcaster: Arc<Mutex<dyn Broadcast>>, // FIXME: I don't think we need to broadcast from here
    logger: Logger,

    // Current slot (the one that is not yet in the ledger / the one currently being worked on).
    cur_slot: SlotIndex,

    // Previous block id
    prev_block_id: BlockID,

    // Map of slot index -> pending scp messages we need to process, per peer (including self).
    pending_consensus_msgs:
        HashMap<ResponderId, HashMap<SlotIndex, VecDeque<VerifiedConsensusMsg>>>,

    // Pending values we're trying to push, stored as a vec per peer, including self.
    // We need to store them as a vec per peer so we can process values
    // on a first-come first-served basis. However, we want to be able to:
    // 1) Efficiently see if we already have a given value and ignore duplicates
    // 2) Track how long each value took to externalize.
    // To accomplish both of these goals we store, in addition to the queue of pending values, a
    // BTreeMap that maps a value to when we first encountered it. Note that we only store a
    // timestamp for values that were handed to us directly from a client. We skip tracking
    // processing times for relayed values since we want to track the time from when the network
    // first saw a value, and not when a specific node saw it.
    // FIXME: These are only pending values from self - does not need to be per responder_id
    pending_values: HashMap<ResponderId, Vec<TxHash>>,
    pending_values_map: BTreeMap<TxHash, Option<Instant>>,

    // Do we need to nominate anything? Stored per peer, including self.
    need_nominate: HashMap<ResponderId, bool>,

    // Network state, used to track if we've fallen behind.
    network_state: SCPNetworkState,

    // Ledger sync service
    ledger_sync_service: LedgerSyncService<L, PC, ReqwestTransactionsFetcher>,

    // Ledger sync state.
    ledger_sync_state: LedgerSyncState,

    // A map of responder id to a list of tx hashes that it is unable to provide. This allows us to
    // skip attemping to fetch txs that are bound to fail. A BTreeSet is used to speed up lookups
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
            _broadcaster: broadcaster,
            peer_manager,
            logger,

            cur_slot,
            prev_block_id,
            pending_consensus_msgs: HashMap::default(),
            pending_values: HashMap::default(),
            pending_values_map: BTreeMap::default(),
            need_nominate: HashMap::default(),
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
        let total_values: usize = self.pending_values.values().map(|p| p.len()).sum();
        assert_eq!(total_values, self.pending_values_map.len());

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

                let tx_manager = self.tx_manager.clone();

                // Re-construct the BTreeMap with the remaining values, using the old timestamps.
                let mut new_pending_values_map = BTreeMap::new();

                for (responder_id, pending_values) in self.pending_values.iter_mut() {
                    // Clear any pending values that might no longer be valid.
                    pending_values.retain(|tx_hash| tx_manager.validate(tx_hash).is_ok());

                    for val in pending_values.iter_mut() {
                        new_pending_values_map
                            .insert(*val, *self.pending_values_map.get(val).unwrap());
                    }

                    // Nominate if needed.
                    if !pending_values.is_empty() {
                        self.need_nominate.insert(responder_id.clone(), true);
                    }
                }
                self.pending_values_map = new_pending_values_map;

                // Update state.
                self.is_behind.store(false, Ordering::SeqCst);
                self.ledger_sync_state = LedgerSyncState::InSync;
                self.cur_slot = self.ledger.num_blocks().unwrap();
                self.prev_block_id = self.ledger.get_block(self.cur_slot - 1).unwrap().id;

                // Clear old entries from pending_consensus_msgs
                let cur_slot = self.cur_slot;
                for pending_consensus_msgs in self.pending_consensus_msgs.values_mut() {
                    pending_consensus_msgs.retain(|&slot_index, _| slot_index >= cur_slot);
                }
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
                TaskMessage::Values(timestamp, new_values) => {
                    //                    println!("\x1b[1;31m received nominate {:?}\x1b[0m", new_values);
                    // Collect.
                    for value in new_values {
                        // If we don't already know of this value, add it to the pending list and
                        // map.
                        if let Vacant(entry) = self.pending_values_map.entry(value) {
                            entry.insert(timestamp);
                            //                            println!(
                            //                                "\x1b[1;37m now adding to pending values and need nominate\x1b[0m"
                            //                            );
                            self.pending_values
                                .entry(self.scp.node_id().responder_id)
                                .or_default()
                                .push(value);
                            self.need_nominate
                                .insert(self.scp.node_id().responder_id, true);
                            //                            println!(
                            //                                "\x1b[1;32m pending values = {:?} \n\n need_nominate = {:?}",
                            //                                self.pending_values, self.need_nominate
                            //                            );
                        }
                    }
                }

                // SCP Statement
                TaskMessage::ConsensusMsg(consensus_msg, from_responder_id) => {
                    //                    println!("\x1b[1;31m received network msg\x1b[0m");

                    // Only look at messages that are not for past slots.
                    if consensus_msg.scp_msg().slot_index >= self.cur_slot {
                        // FIXME: feed in "fair" manner?
                        // Feed network state. The sync service needs this
                        // to be able to tell if we fell behind based on the slot values.
                        // Block ID checking is skipped here, since if we fell behind
                        // we are not going to have blocks to compare to.
                        self.network_state.push(consensus_msg.scp_msg().clone());

                        // Collect.
                        self.pending_consensus_msgs
                            .entry(from_responder_id)
                            .or_default()
                            .entry(consensus_msg.scp_msg().slot_index)
                            .or_default()
                            .push_back(consensus_msg);
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

    /// Nominate all pending values up to MAX_PENDING_VALUES_TO_NOMINATE.
    /// Note: We only nominate values that were submitted to this node.
    /// FIXME: does not need to be in round-robin fashion, we only nominate values from us
    fn nominate_pending_values(&mut self) {
        let mut values_nominated = 0;
        let mut nom_index = 0;
        while values_nominated < MAX_PENDING_VALUES_TO_NOMINATE
            && self.need_nominate.values().any(|v| *v)
        {
            //            println!("\x1b[1;31m Now nominating pending values\x1b[0m");
            for (responder_id, need_nominate) in self.need_nominate.iter_mut() {
                //                println!(
                //                    "\x1b[1;32m nominating for responder id {:?} which needs nominate? {:?}\x1b[0m",
                //                    responder_id, need_nominate,
                //                );
                if !*need_nominate {
                    continue;
                }

                let pending_values = self
                    .pending_values
                    .get(responder_id)
                    .expect("Expected pending values for responder_id");

                //                println!(
                //                    "\x1b[1;33m Got pending values = {:?}\x1b[0m",
                //                    pending_values
                //                );
                assert!(!pending_values.is_empty());

                //                println!(
                //                    "\x1b[1;31m len {:?} gotta be <= nom_index {}\x1b[0m",
                //                    pending_values.len(),
                //                    nom_index
                //                );
                if pending_values.len() <= nom_index {
                    // We've already nominated all the values for this responder_id
                    //self.need_nominate.insert(responder_id.clone(), false);
                    *need_nominate = false;
                    continue;
                }

                //                println!("\x1b[1;34m Sending to scp \x1b[0m");
                let msg_opt = self
                    .scp
                    .propose_values(
                        self.cur_slot,
                        BTreeSet::from_iter(vec![pending_values[nom_index]]),
                    )
                    .expect("nominate failed");

                if let Some(msg) = msg_opt {
                    (self.send_scp_message)(msg)
                }

                values_nominated += 1;
            }
            nom_index += 1;
        }
    }

    /// Process the consensus messages for the current slot, in round robin fashion.
    /// Note: In practice, the pending_consensus_msg queue does not often fill up,
    /// however, we send to the consensus layer in round robin fashion between peers in order
    /// to make sure that messages are processed fairly, and e.g. neighbors with lower latency
    /// do not receive priority.
    fn process_consensus_msgs_for_cur_slot(&mut self) {
        // FIXME: handle unwraps
        let mut remaining_pending: Vec<ResponderId> = self
            .pending_consensus_msgs
            .iter()
            .filter(|(_k, v)| match v.get(&self.cur_slot) {
                Some(p) => !p.is_empty(),
                None => false,
            })
            .map(|(k, _v)| k.clone())
            .collect::<Vec<ResponderId>>();
        // Fully exhaust messages for current slot - FIXME: any early exits we would need if the slot moved?
        while !remaining_pending.is_empty() {
            for from_responder_id in remaining_pending {
                if let Some(consensus_msgs) = self
                    .pending_consensus_msgs
                    .get_mut(&from_responder_id)
                    .unwrap()
                    .get_mut(&self.cur_slot)
                {
                    // Only process one consensus message per peer, each round
                    let consensus_msg = consensus_msgs.pop_front().unwrap();
                    let (scp_msg, their_prev_block_id) =
                        (consensus_msg.scp_msg(), consensus_msg.prev_block_id());

                    if self.prev_block_id != *their_prev_block_id {
                        log::warn!(self.logger, "Received message {:?} that refers to an invalid block id {:?} != {:?} (cur_slot = {})",
                scp_msg, their_prev_block_id, self.prev_block_id, self.cur_slot);
                    }

                    if !self.fetch_missing_txs(scp_msg, &from_responder_id) {
                        continue;
                    }

                    // Broadcast this message to the rest of the network. Do this immediately so that
                    // other nodes' slots may also work on this message.
                    self._broadcaster
                        .lock()
                        .expect("mutex poisoned")
                        .broadcast_consensus_msg(consensus_msg.as_ref(), &from_responder_id);

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

                    // Pass message to the scp layer. The slot will evaluate the message and possibly
                    // progress the state machine, producing a new message to send.
                    match self.scp.handle(scp_msg) {
                        Ok(msg_opt) => {
                            if let Some(msg) = msg_opt {
                                log::debug!(self.logger, "Now sending scp message {:?}", msg);

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
            remaining_pending = self
                .pending_consensus_msgs
                .iter()
                .filter(|(_k, v)| match v.get(&self.cur_slot) {
                    Some(p) => !p.is_empty(),
                    None => false,
                })
                .map(|(k, _v)| k.clone())
                .collect::<Vec<ResponderId>>();
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
        for pending_values in self.pending_values.values_mut() {
            pending_values.retain(|tx_hash| !ext_vals.contains(tx_hash));
        }

        log::info!(
            self.logger,
            "Slot {} ended with {} externalized values and {:?} pending values.",
            self.cur_slot,
            ext_vals.len(),
            self.pending_values
                .iter()
                .map(|(k, v)| (k, v.len()))
                .collect::<HashMap<&ResponderId, usize>>(),
        );

        // Write to ledger.
        {
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
                .unwrap_or_else(|e| panic!("Failed to build block from {:?}: {:?}", ext_vals, e));

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
        }

        // Sanity check + update current slot.
        let cur_slot = self.ledger.num_blocks().expect("num blocks failed") as SlotIndex;

        assert_eq!(cur_slot, self.cur_slot + 1);

        self.cur_slot = cur_slot;
        self.prev_block_id = self.ledger.get_block(cur_slot - 1).unwrap().id;

        // Evacuate transactions that are no longer valid based on their
        // tombstone block.
        let purged_hashes = self.tx_manager.remove_expired(cur_slot);

        counters::TX_CACHE_NUM_ENTRIES.set(self.tx_manager.num_entries() as i64);

        // Re-construct the BTreeMap with the remaining values, using the old timestamps.
        let mut new_pending_values_map = BTreeMap::new();

        let tx_manager = self.tx_manager.clone();
        for pending_values in self.pending_values.values_mut() {
            // Drop pending values that are no longer considered valid and
            pending_values.retain(|tx_hash| {
                !purged_hashes.contains(tx_hash) && tx_manager.validate(tx_hash).is_ok()
            });

            for val in pending_values.iter() {
                new_pending_values_map.insert(*val, *self.pending_values_map.get(val).unwrap());
            }
        }

        self.pending_values_map = new_pending_values_map;

        log::info!(
            self.logger,
            "number of pending values post cleanup: {:?} ({} expired)",
            self.pending_values
                .iter()
                .map(|(k, v)| (k, v.len()))
                .collect::<HashMap<&ResponderId, usize>>(),
            purged_hashes.len(),
        );

        // Prev slot metrics.
        counters::PREV_SLOT_NUMBER.set((cur_slot - 1) as i64);
        counters::PREV_SLOT_ENDED_AT.set(chrono::Utc::now().timestamp_millis());
        counters::PREV_SLOT_NUM_EXT_VALS.set(ext_vals.len() as i64);

        for (responder_id, pending_values) in self.pending_values.iter() {
            // If we have any pending values, we'd like to issue a nominate statement on the next
            // tick.
            if !pending_values.is_empty() {
                self.need_nominate.insert(responder_id.clone(), true);
            }
        }

        let num_pending: usize = self.pending_values.values().map(|v| v.len()).sum();
        counters::PREV_NUM_PENDING_VALUES.set(num_pending as i64);

        // If we think we're behind, reset us back to InSync since we made progress. If we're still
        // behind this will result in restarting the grace period timer, which is the desired
        // behavior. This protects us from a node that is slightly behind it's peers but has queued
        // up all the SCP statements it needs to make progress and catch up.
        if self.ledger_sync_state != LedgerSyncState::InSync {
            log::info!(self.logger, "sync_service reported we're behind, but we just externalized a slot. resetting to InSync");
            self.ledger_sync_state = LedgerSyncState::InSync;
        }

        // Clear the missing tx hashes map. If we encounter the same tx hash again in a different
        // slot, it is possible we might be able to fetch it.
        self.unavailable_tx_hashes.clear();
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
        let slot_metrics = self.scp.get_slot_metrics(self.cur_slot);
        let num_pending: usize = self.pending_values.values().map(|v| v.len()).sum();
        counters::CUR_NUM_PENDING_VALUES.set(num_pending as i64);
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
