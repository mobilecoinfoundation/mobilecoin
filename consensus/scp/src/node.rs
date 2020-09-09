// Copyright (c) 2018-2020 MobileCoin Inc.

//! A node determines whether transactions are valid, and participates in voting with the members of its quorum set.
use crate::{
    core_types::{CombineFn, SlotIndex, ValidityFn, Value},
    msg::{ExternalizePayload, Msg, Topic},
    quorum_set::QuorumSet,
    slot::{ScpSlot, Slot, SlotMetrics},
};
use mc_common::{
    logger::{log, Logger},
    NodeID,
};
#[cfg(test)]
use mockall::*;
use std::{
    collections::{BTreeSet, HashMap},
    fmt::Display,
    time::Duration,
};

/// Max number of externalized slots to store.
pub const MAX_EXTERNALIZED_SLOTS: usize = 1;

/// A node participates in federated voting.
pub struct Node<V: Value, ValidationError: Clone + Display> {
    /// Local node ID.
    pub ID: NodeID,

    /// Local node quorum set.
    pub Q: QuorumSet,

    /// The current slot that this node is attempting to reach consensus on.
    pub current_slot: Slot<V, ValidationError>,

    /// A queue of externalized slots, ordered by increasing slot index.
    pub externalized_slots: Vec<Slot<V, ValidationError>>,

    /// Application-specific validation of value.
    validity_fn: ValidityFn<V, ValidationError>,

    /// Application-specific function for combining multiple values. Must be deterministic.
    combine_fn: CombineFn<V, ValidationError>,

    /// Logger.
    logger: Logger,

    /// Sets the 'base round timeout' and the 'base ballot timeout' when creating a slot.
    /// (Defaults to 1 second to match the SCP whitepaper specification.)
    pub scp_timebase: Duration,
}

impl<V: Value, ValidationError: Clone + Display + 'static> Node<V, ValidationError> {
    /// Creates a new Node.
    ///
    /// # Arguments
    /// * `node_id` - This node's ID.
    /// * `quorum_set` - This node's quorum set.
    /// * `validity_fn` - Validates a value.
    /// * `combine_fn` - Combines a set of values into a composite value (i.e. block).
    /// * `current_slot_index` - Index of the slot to begin performing consensus on.
    /// * `logger`
    pub fn new(
        node_id: NodeID,
        quorum_set: QuorumSet,
        validity_fn: ValidityFn<V, ValidationError>,
        combine_fn: CombineFn<V, ValidationError>,
        current_slot_index: SlotIndex,
        logger: Logger,
    ) -> Self {
        let slot = Slot::new(
            node_id.clone(),
            quorum_set.clone(),
            current_slot_index,
            validity_fn.clone(),
            combine_fn.clone(),
            logger.clone(),
        );

        Self {
            ID: node_id,
            Q: quorum_set,
            current_slot: slot,
            externalized_slots: Vec::new(),
            validity_fn,
            combine_fn,
            logger,
            scp_timebase: Duration::from_millis(1000),
        }
    }

    // Record the values externalized by the current slot and advance the current slot.
    fn externalize(
        &mut self,
        slot_index: SlotIndex,
        payload: &ExternalizePayload<V>,
    ) -> Result<(), String> {
        // Log an error if any invalid values were externalized.
        // This is be redundant, but may be helpful during development.
        for value in &payload.C.X {
            if let Err(e) = (self.validity_fn)(value) {
                log::error!(
                    self.logger,
                    "Slot {} externalized invalid value: {:?}, {}",
                    slot_index,
                    value,
                    e
                );
            }
        }

        self.push_externalized_slot(self.current_slot.clone());

        // Advance to the next slot.
        self.current_slot = Slot::new(
            self.ID.clone(),
            self.Q.clone(),
            slot_index + 1,
            self.validity_fn.clone(),
            self.combine_fn.clone(),
            self.logger.clone(),
        );

        Ok(())
    }

    /// Push an externalized slot into the queue of externalized slots.
    fn push_externalized_slot(&mut self, slot: Slot<V, ValidationError>) {
        self.externalized_slots.push(slot);
        while self.externalized_slots.len() > MAX_EXTERNALIZED_SLOTS {
            // Remove the first slot, which is the oldest.
            self.externalized_slots.remove(0);
        }
    }
}

/// A node capable of participating in SCP.
#[cfg_attr(test, automock)]
pub trait ScpNode<V: Value>: Send {
    /// Get local node ID.
    fn node_id(&self) -> NodeID;

    /// Get local node quorum set.
    fn quorum_set(&self) -> QuorumSet;

    /// Propose values for this node to nominate.
    fn propose_values(&mut self, values: BTreeSet<V>) -> Result<Option<Msg<V>>, String>;

    /// Handle incoming message from the network.
    fn handle_message(&mut self, msg: &Msg<V>) -> Result<Option<Msg<V>>, String>;

    /// Handle incoming messages from the network.
    fn handle_messages(&mut self, msgs: Vec<Msg<V>>) -> Result<Vec<Msg<V>>, String>;

    /// Get externalized values (or an empty vector) for a given slot index.
    fn get_externalized_values(&self, slot_index: SlotIndex) -> Option<Vec<V>>;

    /// Process pending timeouts.
    fn process_timeouts(&mut self) -> Vec<Msg<V>>;

    /// Get the current slot's index.
    fn current_slot_index(&self) -> SlotIndex;

    /// Get metrics for the current slot.
    fn get_slot_metrics(&mut self) -> SlotMetrics;

    /// Additional debug info, e.g. a JSON representation of the Slot's state.
    fn get_slot_debug_snapshot(&mut self, slot_index: SlotIndex) -> Option<String>;

    /// Reset the current slot.
    fn reset_slot_index(&mut self, slot_index: SlotIndex);
}

impl<V: Value, ValidationError: Clone + Display + 'static> ScpNode<V> for Node<V, ValidationError> {
    fn node_id(&self) -> NodeID {
        self.ID.clone()
    }

    fn quorum_set(&self) -> QuorumSet {
        self.Q.clone()
    }

    /// Propose values for this node to nominate.
    fn propose_values(&mut self, values: BTreeSet<V>) -> Result<Option<Msg<V>>, String> {
        if values.is_empty() {
            log::error!(self.logger, "propose_values called with 0 values.");
            return Ok(None);
        }

        match self.current_slot.propose_values(&values)? {
            None => Ok(None),
            Some(msg) => {
                if let Topic::Externalize(ext_payload) = &msg.topic {
                    self.externalize(msg.slot_index, ext_payload)?;
                }
                Ok(Some(msg))
            }
        }
    }

    /// Handle an incoming message from the network.
    fn handle_message(&mut self, msg: &Msg<V>) -> Result<Option<Msg<V>>, String> {
        let outgoing_messages = self.handle_messages(vec![msg.clone()])?;
        Ok(outgoing_messages.get(0).cloned())
    }

    /// Handle incoming message from the network.
    fn handle_messages(&mut self, msgs: Vec<Msg<V>>) -> Result<Vec<Msg<V>>, String> {
        // Omit messages from self.
        let (msgs_from_peers, msgs_from_self): (Vec<_>, Vec<_>) =
            msgs.into_iter().partition(|msg| msg.sender_id != self.ID);

        if !msgs_from_self.is_empty() {
            log::error!(
                self.logger,
                "Received {} messages from self.",
                msgs_from_self.len()
            );
        }

        // Omit messages for future slots.
        let (msgs_to_process, future_msgs): (Vec<_>, Vec<_>) = msgs_from_peers
            .into_iter()
            .partition(|msg| msg.slot_index <= self.current_slot.get_index());

        if !future_msgs.is_empty() {
            log::error!(
                self.logger,
                "Received {} messages for future slots.",
                future_msgs.len()
            );
        }

        // Group messages by slot index.
        let mut slot_index_to_msgs: HashMap<SlotIndex, Vec<Msg<V>>> = Default::default();
        for msg in msgs_to_process {
            slot_index_to_msgs
                .entry(msg.slot_index)
                .or_insert_with(Vec::new)
                .push(msg);
        }

        // Messages emitted by this node that should be sent to the network.
        let mut outbound_msgs: Vec<_> = Vec::new();

        // Handle messages for current slot.
        if let Some(msgs) = slot_index_to_msgs.get(&self.current_slot.get_index()) {
            if let Some(response) = self.current_slot.handle_messages(msgs)? {
                if let Topic::Externalize(ext_payload) = &response.topic {
                    self.externalize(response.slot_index, &ext_payload)?;
                }
                outbound_msgs.push(response);
            }
        }

        // Handle messages for previous slots.
        for slot in self.externalized_slots.iter_mut() {
            if let Some(msgs) = slot_index_to_msgs.get(&slot.get_index()) {
                if let Some(response) = slot.handle_messages(msgs)? {
                    outbound_msgs.push(response);
                }
            }
        }

        // Note: messages for older slots are ignored.

        Ok(outbound_msgs)
    }

    /// Get externalized values for a given slot index, if any.
    fn get_externalized_values(&self, slot_index: SlotIndex) -> Option<Vec<V>> {
        if let Some(slot) = self
            .externalized_slots
            .iter()
            .find(|slot| slot.get_index() == slot_index)
        {
            if let Topic::Externalize(payload) = slot
                .get_last_message_sent()
                .expect("Previous slots must have a message")
                .topic
            {
                Some(payload.C.X)
            } else {
                panic!("Previous slot has not externalized?");
            }
        } else {
            None
        }
    }

    /// Process pending timeouts.
    fn process_timeouts(&mut self) -> Vec<Msg<V>> {
        self.current_slot.process_timeouts()
    }

    /// Get the current slot's index.
    fn current_slot_index(&self) -> SlotIndex {
        self.current_slot.get_index()
    }

    /// Get metrics for the current slot.
    fn get_slot_metrics(&mut self) -> SlotMetrics {
        self.current_slot.get_metrics()
    }

    /// Get the slot internal state (for debug purposes).
    fn get_slot_debug_snapshot(&mut self, _slot_index: SlotIndex) -> Option<String> {
        // TODO: return debug snapshots for other slots?
        Some(self.current_slot.get_debug_snapshot())
    }

    /// Reset the current slot.
    fn reset_slot_index(&mut self, slot_index: SlotIndex) {
        self.current_slot = Slot::new(
            self.ID.clone(),
            self.Q.clone(),
            slot_index,
            self.validity_fn.clone(),
            self.combine_fn.clone(),
            self.logger.clone(),
        );
    }
}

#[cfg(test)]
mod node_tests {
    use super::*;
    use crate::{core_types::Ballot, msg::*, test_utils::*};
    // use maplit::btreeset;
    use mc_common::logger::test_with_logger;
    use std::{iter::FromIterator, sync::Arc};

    #[test_with_logger]
    // Initially, `externalized_slots` should be empty.
    fn test_initialization(logger: Logger) {
        let node = Node::<u32, TransactionValidationError>::new(
            test_node_id(1),
            QuorumSet::new_with_node_ids(1, vec![test_node_id(2)]),
            Arc::new(trivial_validity_fn),
            Arc::new(trivial_combine_fn),
            0,
            logger.clone(),
        );

        assert!(node.externalized_slots.is_empty());
    }

    // #[test_with_logger]
    // // Should pass values to the appropriate slot.
    // fn test_propose_values(logger: Logger) {
    //     type V = &'static str;
    //
    //     let mut node = Node::<V, TransactionValidationError>::new(
    //         test_node_id(1),
    //         QuorumSet::new_with_node_ids(1, vec![test_node_id(2)]),
    //         Arc::new(trivial_validity_fn),
    //         Arc::new(trivial_combine_fn),
    //         0,
    //         logger.clone(),
    //     );
    //
    //     let mut slot = MockScpSlot::<V>::new();
    //     slot.expect_propose_values().times(1).return_const(Ok(None));
    //     // TODO
    //     node.current_slot = Box::new(slot);
    //
    //     let values = btreeset!["a", "b", "c"];
    //     let _res = node.propose_values(values);
    // }

    #[test_with_logger]
    /// Steps through a sequence of messages that allow a two-node network to reach consensus.
    fn basic_two_node_consensus(logger: Logger) {
        let slot_index = 1;

        // A two-node network, where the only quorum is both nodes.
        let mut node1 = Node::<u32, TransactionValidationError>::new(
            test_node_id(1),
            QuorumSet::new_with_node_ids(1, vec![test_node_id(2)]),
            Arc::new(trivial_validity_fn),
            Arc::new(trivial_combine_fn),
            slot_index,
            logger.clone(),
        );
        let mut node2 = Node::<u32, TransactionValidationError>::new(
            test_node_id(2),
            QuorumSet::new_with_node_ids(1, vec![test_node_id(1)]),
            Arc::new(trivial_validity_fn),
            Arc::new(trivial_combine_fn),
            slot_index,
            logger.clone(),
        );

        // Client(s) submits some values to node 2.
        let values = vec![1000, 2000];
        let msg = node2
            .propose_values(BTreeSet::from_iter(values.clone()))
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
            .handle_message(&msg)
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
            .handle_message(&msg)
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
            .handle_message(&msg)
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
            .handle_message(&msg)
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
            .handle_message(&msg)
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
            .handle_message(&msg)
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
            .handle_message(&msg)
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
