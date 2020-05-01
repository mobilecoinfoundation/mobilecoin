// Copyright (c) 2018-2020 MobileCoin Inc.

//! A node determines whether transactions are valid, and participates in voting with the members of its quorum set.
use crate::{
    core_types::{CombineFn, SlotIndex, ValidityFn, Value},
    msg::{ExternalizePayload, Msg, Topic},
    quorum_set::QuorumSet,
    slot::{Slot, SlotMetrics},
};
use mc_common::{
    logger::{log, Logger},
    Hash, LruCache, NodeID,
};
use mc_crypto_digestible::Digestible;
use sha3::Sha3_256;
use std::{collections::BTreeSet, fmt::Display, time::Duration};

/// Max number of pending slots to store.
const MAX_PENDING_SLOTS: usize = 10;

/// Max number of externalized slots to store.
const MAX_EXTERNALIZED_SLOTS: usize = 10;

/// Number of last seen messages to keep track of.
const LAST_SEEN_HISTORY_SIZE: usize = 1000;

/// A node participates in federated voting.
pub struct Node<V: Value, ValidationError: Display> {
    /// Local node ID.
    pub ID: NodeID,

    /// Local node quorum set.
    pub Q: QuorumSet,

    /// Map of last few slot indexes -> slots.
    pub pending: LruCache<SlotIndex, Slot<V, ValidationError>>,

    /// Map of last few slot indexes -> externalized slots.
    pub externalized: LruCache<SlotIndex, ExternalizePayload<V>>,

    /// Application-specific validation of value.
    validity_fn: ValidityFn<V, ValidationError>,

    /// Application-specific function for combining multiple values. Must be deterministic.
    combine_fn: CombineFn<V>,

    /// Hashes of messages we've already processed.
    /// (We store hashes instead of message content to reduce memory footprint.)
    pub seen_msg_hashes: LruCache<Hash, ()>,

    /// Logger.
    logger: Logger,

    /// Sets the 'base round timeout' and the 'base ballot timeout' when creating a slot.
    /// (Defaults to 1 second to match the SCP whitepaper specification.)
    pub scp_timebase: Duration,
}

impl<V: Value, ValidationError: Display> Node<V, ValidationError> {
    /// Creates a new Node.
    pub fn new(
        ID: NodeID,
        Q: QuorumSet,
        validity_fn: ValidityFn<V, ValidationError>,
        combine_fn: CombineFn<V>,
        logger: Logger,
    ) -> Self {
        Self {
            ID,
            Q,
            pending: LruCache::new(MAX_PENDING_SLOTS),
            externalized: LruCache::new(MAX_EXTERNALIZED_SLOTS),
            validity_fn,
            combine_fn,
            seen_msg_hashes: LruCache::new(LAST_SEEN_HISTORY_SIZE),
            logger,
            scp_timebase: Duration::from_millis(1000),
        }
    }

    /// Get or crate a pending slot.
    fn get_or_create_pending_slot(
        &mut self,
        slot_index: SlotIndex,
    ) -> &mut Slot<V, ValidationError> {
        // Create new Slot if necessary.
        if !self.pending.contains(&slot_index) {
            let mut slot = Slot::new(
                self.ID.clone(),
                self.Q.clone(),
                slot_index,
                self.validity_fn.clone(),
                self.combine_fn.clone(),
                self.logger.clone(),
            );
            slot.base_round_interval = self.scp_timebase;
            slot.base_ballot_interval = self.scp_timebase;
            self.pending.put(slot_index, slot);
        }

        // Return slot.
        self.pending.get_mut(&slot_index).unwrap()
    }

    fn externalize(
        &mut self,
        slot_index: SlotIndex,
        payload: &ExternalizePayload<V>,
    ) -> Result<(), String> {
        // Check for invalid values. This should be redundant, but may be helpful during development.
        let mut externalized_invalid_values = false;
        for value in &payload.C.X {
            if let Err(e) = (self.validity_fn)(value) {
                externalized_invalid_values = true;
                log::error!(
                    self.logger,
                    "Slot {} externalized invalid value: {:?}, {}",
                    slot_index,
                    value,
                    e
                );
            }
        }
        if externalized_invalid_values {
            return Err("Slot Externalized invalid values.".to_string());
        }

        self.externalized.put(slot_index, payload.clone());
        Ok(())
    }
}

/// A node capable of participating in SCP.
pub trait ScpNode<V: Value>: Send {
    /// Get local node ID.
    fn node_id(&self) -> NodeID;

    /// Get local node quorum set.
    fn quorum_set(&self) -> QuorumSet;

    /// Submit a list of values of nomination.
    fn nominate(
        &mut self,
        slot_index: SlotIndex,
        values: BTreeSet<V>,
    ) -> Result<Option<Msg<V>>, String>;

    /// Handle incoming message from the network.
    fn handle(&mut self, msg: &Msg<V>) -> Result<Option<Msg<V>>, String>;

    /// Get externalized values (or an empty vector) for a given slot index.
    fn get_externalized_values(&self, slot_index: SlotIndex) -> Vec<V>;

    /// Check if we have externalized values for a given slot index.
    fn has_externalized_values(&self, slot_index: SlotIndex) -> bool;

    /// Process pending timeouts.
    fn process_timeouts(&mut self) -> Vec<Msg<V>>;

    /// Get metrics for a specific slot.
    fn get_slot_metrics(&mut self, slot_index: SlotIndex) -> Option<SlotMetrics>;

    /// Clear the list of pending slots. This is useful if the user of this object realizes they
    /// have fallen behind their peers, and as such they want to abort processing of current slots.
    fn clear_pending_slots(&mut self);
}

impl<V: Value, ValidationError: Display> ScpNode<V> for Node<V, ValidationError> {
    fn node_id(&self) -> NodeID {
        self.ID.clone()
    }

    fn quorum_set(&self) -> QuorumSet {
        self.Q.clone()
    }

    /// Submit a list of values of nomination.
    fn nominate(
        &mut self,
        slot_index: SlotIndex,
        values: BTreeSet<V>,
    ) -> Result<Option<Msg<V>>, String> {
        if values.is_empty() {
            log::error!(self.logger, "nominate() called with 0 values.");
            return Ok(None);
        }

        let valid_values: BTreeSet<V> = values
            .into_iter()
            .filter(|value| (self.validity_fn)(&value).is_ok())
            .collect();

        if valid_values.is_empty() {
            log::error!(
                self.logger,
                "nominate() called with only invalid values. Ignoring."
            );
            return Ok(None);
        }

        let slot = self.get_or_create_pending_slot(slot_index);
        let outbound = slot.propose_values(&valid_values)?;

        match &outbound {
            None => Ok(None),
            Some(msg) => {
                if let Topic::Externalize(ext_payload) = &msg.topic {
                    self.externalize(msg.slot_index, ext_payload)?;
                }
                Ok(outbound)
            }
        }
    }

    /// Handle incoming message from the network.
    fn handle(&mut self, msg: &Msg<V>) -> Result<Option<Msg<V>>, String> {
        if msg.sender_id == self.ID {
            log::error!(
                self.logger,
                "node.handle received message from self: {:?}",
                msg
            );
            return Ok(None);
        }

        // Log an error if another node Externalizes different values.
        if let Topic::Externalize(received_externalized_payload) = &msg.topic {
            if let Some(our_externalized_payload) = self.externalized.get(&msg.slot_index) {
                if our_externalized_payload.C.X != received_externalized_payload.C.X {
                    // Another node has externalized a different value for this slot. This could be
                    // a problem with consensus, or a Byzantine node.
                    log::error!(
                        self.logger,
                        "Node {:?} externalized different values. Ours:{:#?} Theirs:{:#?}",
                        msg.sender_id,
                        our_externalized_payload,
                        received_externalized_payload
                    );

                    // TODO: return an error.
                    return Ok(None);
                }
            }
        }

        // Calculate message hash.
        let msg_hash = msg.digest_with::<Sha3_256>().into();

        // If we've already seen this message, we don't need to do anything.
        // We use `get()` instead of `contains()` to update LRU state.
        if self.seen_msg_hashes.get(&msg_hash).is_some() {
            return Ok(None);
        }

        // Store message so it doesn't get processed again.
        self.seen_msg_hashes.put(msg_hash, ());

        // Process message using the Slot.
        let slot = self.get_or_create_pending_slot(msg.slot_index);
        let outbound = slot.handle(msg)?;

        match &outbound {
            None => Ok(None),
            Some(msg) => {
                if let Topic::Externalize(ext_payload) = &msg.topic {
                    self.externalize(msg.slot_index, ext_payload)?;
                }
                Ok(outbound)
            }
        }
    }

    /// Get externalized values (or an empty vector) for a given slot index.
    fn get_externalized_values(&self, slot_index: SlotIndex) -> Vec<V> {
        match self.externalized.peek(&slot_index) {
            None => Vec::new(),
            Some(payload) => payload.C.X.clone(),
        }
    }

    /// Check if we have externalized values for a given slot index.
    fn has_externalized_values(&self, slot_index: SlotIndex) -> bool {
        self.externalized.contains(&slot_index)
    }

    /// Process pending timeouts.
    fn process_timeouts(&mut self) -> Vec<Msg<V>> {
        let mut msgs = Vec::<Msg<V>>::new();

        for (_, slot) in self.pending.iter_mut() {
            msgs.extend(slot.process_timeouts());
        }

        msgs
    }

    /// Get metrics for a specific slot.
    fn get_slot_metrics(&mut self, slot_index: SlotIndex) -> Option<SlotMetrics> {
        self.pending.get(&slot_index).map(|slot| slot.get_metrics())
    }

    /// Clear the list of pending slots. This is useful if the user of this object realizes they
    /// have fallen behind their peers, and as such they want to abort processing of current slots.
    fn clear_pending_slots(&mut self) {
        self.pending.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{core_types::Ballot, msg::*, test_utils::*};
    use mc_common::logger::test_with_logger;
    use std::{iter::FromIterator, sync::Arc};

    #[test_with_logger]
    /// Steps through a sequence of messages that allow a two-node network to reach consensus.
    fn basic_two_node_consensus(logger: Logger) {
        // A two-node network, where the only quorum is both nodes.
        let mut node1 = Node::<u32, TransactionValidationError>::new(
            test_node_id(1),
            QuorumSet::new_with_node_ids(1, vec![test_node_id(2)]),
            Arc::new(trivial_validity_fn),
            Arc::new(trivial_combine_fn),
            logger.clone(),
        );
        let mut node2 = Node::<u32, TransactionValidationError>::new(
            test_node_id(2),
            QuorumSet::new_with_node_ids(1, vec![test_node_id(1)]),
            Arc::new(trivial_validity_fn),
            Arc::new(trivial_combine_fn),
            logger.clone(),
        );

        // Client(s) submits some values to node 2.
        let slot_index = 1;
        let values = vec![1000, 2000];
        let msg = node2
            .nominate(slot_index, BTreeSet::from_iter(values.clone()))
            .expect("error handling msg")
            .expect("no msg?");

        // Node 2 should emit "vote nominate([1000, 2000])"
        assert_eq!(
            msg,
            Msg::new(
                node2.node_id(),
                node2.quorum_set(),
                slot_index,
                Topic::Nominate(NominatePayload {
                    X: BTreeSet::from_iter(values.clone()),
                    Y: Default::default(),
                }),
            )
        );

        // Node 1 handles Node 2's message. It may accept nominate [1000, 2000]
        let msg = node1
            .handle(&msg)
            .expect("error handling msg")
            .expect("no msg?");

        assert_eq!(
            msg,
            Msg::new(
                node1.node_id(),
                node1.quorum_set(),
                slot_index,
                Topic::Nominate(NominatePayload {
                    X: Default::default(),
                    Y: BTreeSet::from_iter(values.clone()),
                }),
            )
        );

        // Node 2 may "confirm nominate", and issue "vote prepare(<1, [1000,2000]>)
        let msg = node2
            .handle(&msg)
            .expect("error handling msg")
            .expect("no msg?");

        assert_eq!(
            msg,
            Msg::new(
                node2.node_id(),
                node2.quorum_set(),
                slot_index,
                Topic::NominatePrepare(
                    NominatePayload {
                        X: Default::default(),
                        Y: BTreeSet::from_iter(values.clone())
                    },
                    PreparePayload {
                        B: Ballot::new(1, &[1000, 2000]),
                        P: None,
                        PP: None,
                        CN: 0,
                        HN: 0
                    }
                ),
            )
        );

        // Node 1 issues "accept prepare(<1, [1000,2000])
        let msg = node1
            .handle(&msg)
            .expect("error handling msg")
            .expect("no msg?");

        assert_eq!(
            msg,
            Msg::new(
                node1.node_id(),
                node1.quorum_set(),
                slot_index,
                Topic::NominatePrepare(
                    NominatePayload {
                        X: Default::default(),
                        Y: BTreeSet::from_iter(values.clone())
                    },
                    PreparePayload {
                        B: Ballot::new(1, &values),
                        P: Some(Ballot::new(1, &values)),
                        PP: None,
                        CN: 0,
                        HN: 0
                    }
                ),
            )
        );

        // Node 2 issues "vote commit"
        let msg = node2
            .handle(&msg)
            .expect("error handling msg")
            .expect("no msg?");

        assert_eq!(
            msg,
            Msg::new(
                node2.node_id(),
                node2.quorum_set(),
                slot_index,
                Topic::Prepare(PreparePayload {
                    B: Ballot::new(1, &values),
                    P: Some(Ballot::new(1, &values)),
                    PP: None,
                    CN: 1,
                    HN: 1,
                },),
            )
        );

        // Node 1 issues "accept commit".
        let msg = node1
            .handle(&msg)
            .expect("error handling msg")
            .expect("no msg?");

        assert_eq!(
            msg,
            Msg::new(
                node1.node_id(),
                node1.quorum_set(),
                slot_index,
                Topic::Commit(CommitPayload {
                    B: Ballot::new(1, &values),
                    PN: 1,
                    CN: 1,
                    HN: 1
                }),
            )
        );

        // Node 2 externalizes.
        let msg = node2
            .handle(&msg)
            .expect("error handling msg")
            .expect("no msg?");

        assert_eq!(
            msg,
            Msg::new(
                node2.node_id(),
                node2.quorum_set(),
                slot_index,
                Topic::Externalize(ExternalizePayload {
                    C: Ballot::new(1, &values),
                    HN: 1,
                }),
            )
        );

        // Node 1 externalizes.
        let msg = node1
            .handle(&msg)
            .expect("error handling msg")
            .expect("no msg?");

        // Both nodes have issued Externalize, which implies
        // "accept prepare(<infinity, commit.value>)".
        // That means node 1 can also state "confirm prepare(<infinity, commit.value>)",
        // so HN is now INFINITY.
        assert_eq!(
            msg,
            Msg::new(
                node1.node_id(),
                node1.quorum_set(),
                slot_index,
                Topic::Externalize(ExternalizePayload {
                    C: Ballot::new(1, &values),
                    HN: INFINITY,
                }),
            )
        );
    }
}
