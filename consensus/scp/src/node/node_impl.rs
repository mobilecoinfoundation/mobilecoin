// Copyright (c) 2018-2021 The MobileCoin Foundation

//! A node determines whether transactions are valid, and participates in voting
//! with the members of its quorum set.
use crate::{
    core_types::{CombineFn, SlotIndex, ValidityFn, Value},
    msg::{ExternalizePayload, Msg, Topic},
    quorum_set::QuorumSet,
    slot::{ScpSlot, Slot, SlotMetrics},
    ScpNode,
};
use mc_common::{
    logger::{log, Logger},
    NodeID,
};
use std::{
    collections::{BTreeSet, HashMap},
    fmt::Display,
    time::Duration,
};

/// Default limit on number of externalized slots to store.
const MAX_EXTERNALIZED_SLOTS: usize = 1;

/// A node participates in federated voting.
pub struct Node<V: Value, ValidationError: Clone + Display> {
    /// Local node ID.
    pub ID: NodeID,

    /// Local node quorum set.
    pub Q: QuorumSet,

    /// The current slot that this node is attempting to reach consensus on.
    current_slot: Box<dyn ScpSlot<V>>,

    /// Maximum number of stored externalized slots.
    max_externalized_slots: usize,

    /// A queue of externalized slots, ordered by increasing slot index.
    externalized_slots: Vec<Box<dyn ScpSlot<V>>>,

    /// Application-specific validation of value.
    validity_fn: ValidityFn<V, ValidationError>,

    /// Application-specific function for combining multiple values. Must be
    /// deterministic.
    combine_fn: CombineFn<V, ValidationError>,

    /// Logger.
    logger: Logger,

    /// Sets the 'base round timeout' and the 'base ballot timeout' when
    /// creating a slot. (Defaults to 1 second to match the SCP whitepaper
    /// specification.)
    pub scp_timebase: Duration,
}

impl<V: Value, ValidationError: Clone + Display + 'static> Node<V, ValidationError> {
    /// Creates a new Node.
    ///
    /// # Arguments
    /// * `node_id` - This node's ID.
    /// * `quorum_set` - This node's quorum set.
    /// * `validity_fn` - Validates a value.
    /// * `combine_fn` - Combines a set of values into a composite value (i.e.
    ///   block).
    /// * `current_slot_index` - Index of the slot to begin performing consensus
    ///   on.
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
            current_slot: Box::new(slot),
            max_externalized_slots: MAX_EXTERNALIZED_SLOTS,
            externalized_slots: Vec::new(),
            validity_fn,
            combine_fn,
            logger,
            scp_timebase: Duration::from_millis(1000),
        }
    }

    // Record the values externalized by the current slot and advance the current
    // slot.
    fn externalize(&mut self, payload: &ExternalizePayload<V>) -> Result<(), String> {
        let slot_index = self.current_slot.get_index();

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

        let next_slot = Box::new(Slot::new(
            self.ID.clone(),
            self.Q.clone(),
            slot_index + 1,
            self.validity_fn.clone(),
            self.combine_fn.clone(),
            self.logger.clone(),
        ));

        // Advance to the next slot.
        let externalized_slot = std::mem::replace(&mut self.current_slot, next_slot);

        self.push_externalized_slot(externalized_slot);

        Ok(())
    }

    /// Push an externalized slot into the queue of externalized slots.
    fn push_externalized_slot(&mut self, slot: Box<dyn ScpSlot<V>>) {
        self.externalized_slots.push(slot);
        while self.externalized_slots.len() > self.max_externalized_slots {
            // Remove the first slot, which is the oldest.
            self.externalized_slots.remove(0);
        }
    }

    /// Get the externalized slot, if any.
    fn get_externalized_slot(&self, slot_index: SlotIndex) -> Option<&dyn ScpSlot<V>> {
        self.externalized_slots
            .iter()
            .find(|slot| slot.get_index() == slot_index)
            .map(|slot| slot.as_ref())
    }
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
                    self.externalize(ext_payload)?;
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

        // Handle messages for recent externalized slots. Messages for older slots are
        // ignored.
        for slot in self.externalized_slots.iter_mut() {
            if let Some(msgs) = slot_index_to_msgs.get(&slot.get_index()) {
                if let Some(response) = slot.handle_messages(msgs)? {
                    outbound_msgs.push(response);
                }
            }
        }

        // Handle messages for current slot.
        if let Some(msgs) = slot_index_to_msgs.get(&self.current_slot.get_index()) {
            if let Some(response) = self.current_slot.handle_messages(msgs)? {
                if let Topic::Externalize(ext_payload) = &response.topic {
                    self.externalize(&ext_payload)?;
                }
                outbound_msgs.push(response);
            }
        }

        Ok(outbound_msgs)
    }

    /// Maximum number of stored externalized slots.
    fn max_externalized_slots(&self) -> usize {
        self.max_externalized_slots
    }

    /// Set the maximum number of stored externalized slots. Must be non-zero.
    fn set_max_externalized_slots(&mut self, n: usize) {
        debug_assert!(n > 0);
        self.max_externalized_slots = n;
    }

    /// Get externalized values for a given slot index, if any.
    fn get_externalized_values(&self, slot_index: SlotIndex) -> Option<Vec<V>> {
        self.get_externalized_slot(slot_index).map(|slot| {
            if let Topic::Externalize(payload) = slot
                .get_last_message_sent()
                .expect("Previous slots must have a message")
                .topic
            {
                payload.C.X
            } else {
                panic!("Previous slot has not externalized?");
            }
        })
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
    fn get_current_slot_metrics(&mut self) -> SlotMetrics {
        self.current_slot.get_metrics()
    }

    /// Get the slot internal state (for debug purposes).
    fn get_slot_debug_snapshot(&mut self, slot_index: SlotIndex) -> Option<String> {
        if slot_index == self.current_slot_index() {
            Some(self.current_slot.get_debug_snapshot())
        } else {
            self.get_externalized_slot(slot_index)
                .map(|slot| slot.get_debug_snapshot())
        }
    }

    /// Set the node's current slot index, abandoning any current and
    /// externalized slots.
    fn reset_slot_index(&mut self, slot_index: SlotIndex) {
        // The slot index should only increase.
        debug_assert!(slot_index > self.current_slot_index());

        self.current_slot = Box::new(Slot::new(
            self.ID.clone(),
            self.Q.clone(),
            slot_index,
            self.validity_fn.clone(),
            self.combine_fn.clone(),
            self.logger.clone(),
        ));

        self.externalized_slots.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{core_types::Ballot, msg::*, slot::MockScpSlot, test_utils::*};
    use maplit::btreeset;
    use mc_common::logger::test_with_logger;
    use std::{iter::FromIterator, sync::Arc};

    fn get_node(
        slot_index: SlotIndex,
        logger: Logger,
    ) -> Node<&'static str, TransactionValidationError> {
        let node_id = test_node_id(1);
        let quorum_set = QuorumSet::new_with_node_ids(1, vec![test_node_id(2)]);
        Node::<&'static str, TransactionValidationError>::new(
            node_id,
            quorum_set,
            Arc::new(trivial_validity_fn),
            Arc::new(trivial_combine_fn),
            slot_index,
            logger,
        )
    }

    #[test_with_logger]
    // Node::new should correctly initialize current_slot and externalized_slots.
    fn test_initialization(logger: Logger) {
        let node_id = test_node_id(1);
        let quorum_set = QuorumSet::new_with_node_ids(1, vec![test_node_id(2)]);
        let slot_index = 6;
        let node = Node::<u32, TransactionValidationError>::new(
            node_id.clone(),
            quorum_set.clone(),
            Arc::new(trivial_validity_fn),
            Arc::new(trivial_combine_fn),
            slot_index,
            logger,
        );

        assert_eq!(node.current_slot.get_index(), slot_index);
        assert_eq!(node.node_id(), node_id);
        assert_eq!(node.quorum_set(), quorum_set);

        // Initially, `externalized_slots` should be empty.
        assert!(node.externalized_slots.is_empty());
    }

    #[test_with_logger]
    // Should pass values to the appropriate slot.
    fn test_propose_values_no_outgoing_message(logger: Logger) {
        // type V = &'static str;
        let mut node = get_node(0, logger);

        // Should call `propose_values` on the current slot.
        let mut slot = MockScpSlot::new();
        slot.expect_propose_values().times(1).return_const(Ok(None)); // No outgoing Msg.
        node.current_slot = Box::new(slot);

        // Should not call anything on an externalized slot.
        let externalized_slot = MockScpSlot::new();
        node.push_externalized_slot(Box::new(externalized_slot));

        let values = btreeset!["a", "b", "c"];
        assert_eq!(node.propose_values(values), Ok(None));
    }

    #[test_with_logger]
    // Should pass values to the appropriate slot and return the outgoing msg.
    fn test_propose_values_with_outgoing_message(logger: Logger) {
        let slot_index = 1;
        let mut node = get_node(slot_index, logger);

        // Should call `propose_values` on the current slot, which returns a Msg.
        let msg = Msg::new(
            test_node_id(2),
            QuorumSet::new_with_node_ids(1, vec![test_node_id(3)]),
            slot_index,
            Topic::Nominate(NominatePayload {
                X: Default::default(),
                Y: Default::default(),
            }),
        );
        let mut slot = MockScpSlot::new();
        slot.expect_propose_values()
            .times(1)
            .return_const(Ok(Some(msg.clone()))); //  Outgoing Msg, not an Externalize.
        node.current_slot = Box::new(slot);

        let values = btreeset!["a", "b", "c"];
        assert_eq!(node.propose_values(values), Ok(Some(msg)));
    }

    #[test_with_logger]
    // Should pass values to the appropriate slot, externalize the slot,  and return
    // the outgoing msg.
    fn test_propose_values_with_externalize(logger: Logger) {
        let slot_index = 4;
        let mut node = get_node(slot_index, logger);

        // Should call `propose_values` on the current slot, which returns a Msg.
        let msg = Msg::new(
            test_node_id(2),
            QuorumSet::new_with_node_ids(1, vec![test_node_id(3)]),
            slot_index,
            Topic::Externalize(ExternalizePayload {
                C: Ballot::new(4, &[]),
                HN: 3,
            }),
        );

        let mut slot = MockScpSlot::new();
        slot.expect_propose_values()
            .times(1)
            .return_const(Ok(Some(msg.clone()))); //  Outgoing Msg, not an Externalize.
        slot.expect_get_index().return_const(slot_index);
        node.current_slot = Box::new(slot);

        let values = btreeset!["a", "b", "c"];
        assert_eq!(node.propose_values(values), Ok(Some(msg)));

        // The `slot_index` slot should now be extnalized, and current_slot should be at
        // `slot_index + 1`.
        assert_eq!(node.current_slot.get_index(), slot_index + 1);
        assert_eq!(node.externalized_slots.len(), 1);
        assert_eq!(node.externalized_slots[0].get_index(), slot_index)
    }

    #[test_with_logger]
    // Should omit messages from self.
    fn test_handle_messages_omit_from_self(logger: Logger) {
        let slot_index = 1985;
        let mut node = get_node(slot_index, logger);

        // The current slot should not be called.
        let mut slot = MockScpSlot::new();
        slot.expect_get_index().return_const(slot_index);
        node.current_slot = Box::new(slot);

        // The recent externalized slot should not be called.
        let mut externalized_slot = MockScpSlot::new();
        externalized_slot
            .expect_get_index()
            .return_const(slot_index - 1);
        node.push_externalized_slot(Box::new(externalized_slot));

        let msg_from_self = Msg::new(
            node.ID.clone(),
            node.quorum_set(),
            slot_index,
            Topic::Externalize(ExternalizePayload {
                C: Ballot::new(4, &[]),
                HN: 3,
            }),
        );

        match node.handle_messages(vec![msg_from_self.clone(), msg_from_self.clone()]) {
            Ok(outgoing_msgs) => assert_eq!(outgoing_msgs.len(), 0),
            Err(e) => panic!("Unexpected error {:?}", e),
        }
    }

    #[test_with_logger]
    // Should omit messages for future slots.
    fn test_handle_messages_omit_from_future(logger: Logger) {
        let slot_index = 1985;
        let mut node = get_node(slot_index, logger);

        // The current slot should not be called.
        let mut slot = MockScpSlot::new();
        slot.expect_get_index().return_const(slot_index);
        node.current_slot = Box::new(slot);

        // The recent externalized slot should not be called.
        let mut externalized_slot = MockScpSlot::new();
        externalized_slot
            .expect_get_index()
            .return_const(slot_index - 1);
        node.push_externalized_slot(Box::new(externalized_slot));

        // A message from a peer for a future slot index.
        let msg_for_future_slot = Msg::new(
            test_node_id(2),
            QuorumSet::new_with_node_ids(1, vec![test_node_id(3)]),
            2015, // Where we're going, we don't need roads.
            Topic::Externalize(ExternalizePayload {
                C: Ballot::new(4, &[]),
                HN: 3,
            }),
        );

        match node.handle_messages(vec![msg_for_future_slot]) {
            Ok(outgoing_msgs) => assert_eq!(outgoing_msgs.len(), 0),
            Err(e) => panic!("Unexpected error {:?}", e),
        }
    }

    #[test_with_logger]
    // Should omit messages that are too old.
    fn test_handle_messages_omit_old(logger: Logger) {
        let slot_index = 1985;
        let mut node = get_node(slot_index, logger);

        // The current slot should not be called.
        let mut slot = MockScpSlot::new();
        slot.expect_get_index().return_const(slot_index);
        node.current_slot = Box::new(slot);

        // The recent externalized slot should not be called.
        let mut externalized_slot = MockScpSlot::new();
        externalized_slot
            .expect_get_index()
            .return_const(slot_index - 1);
        node.push_externalized_slot(Box::new(externalized_slot));

        // A message from an old slot.
        let msg_for_old_slot = Msg::new(
            test_node_id(2),
            QuorumSet::new_with_node_ids(1, vec![test_node_id(3)]),
            1885, // Too old
            Topic::Nominate(NominatePayload {
                X: Default::default(),
                Y: Default::default(),
            }),
        );

        match node.handle_messages(vec![msg_for_old_slot]) {
            Ok(outgoing_msgs) => assert_eq!(outgoing_msgs.len(), 0),
            Err(e) => panic!("Unexpected error {:?}", e),
        }
    }

    #[test_with_logger]
    // Should pass messages to the current slot.
    fn test_handle_messages_current_slot(logger: Logger) {
        let slot_index = 1985;
        let mut node = get_node(slot_index, logger);

        // The current slot should be called, and should return a message.
        let mut slot = MockScpSlot::new();
        {
            slot.expect_get_index().return_const(slot_index);

            let msg = Msg::new(
                node.ID.clone(),
                node.quorum_set(),
                slot_index,
                Topic::Externalize(ExternalizePayload {
                    C: Ballot::new(4, &[]),
                    HN: 3,
                }),
            );

            slot.expect_handle_messages()
                .times(1)
                .return_const(Ok(Some(msg)));
        }
        node.current_slot = Box::new(slot);

        // The recent externalized slot should not be called.
        let mut externalized_slot = MockScpSlot::new();
        externalized_slot
            .expect_get_index()
            .return_const(slot_index - 1);
        node.push_externalized_slot(Box::new(externalized_slot));

        let msg_for_current_slot = Msg::new(
            test_node_id(2),
            QuorumSet::new_with_node_ids(1, vec![test_node_id(3)]),
            slot_index,
            Topic::Nominate(NominatePayload {
                X: Default::default(),
                Y: Default::default(),
            }),
        );

        match node.handle_messages(vec![msg_for_current_slot]) {
            Ok(outgoing_msgs) => assert_eq!(outgoing_msgs.len(), 1), // Should return a message.
            Err(e) => panic!("Unexpected error {:?}", e),
        }
    }

    #[test_with_logger]
    // Should pass messages to the correct externalized slot.
    fn test_handle_messages_externalized_slots(logger: Logger) {
        let slot_index = 1985;
        let mut node = get_node(slot_index, logger);

        // The current slot should not be called.
        let mut slot = MockScpSlot::new();
        slot.expect_get_index().return_const(slot_index);
        node.current_slot = Box::new(slot);

        // The recently externalized slot should be called.
        let mut externalized_slot = MockScpSlot::new();
        {
            externalized_slot
                .expect_get_index()
                .return_const(slot_index - 1);

            let msg = Msg::new(
                node.ID.clone(),
                node.quorum_set(),
                slot_index - 1,
                Topic::Externalize(ExternalizePayload {
                    C: Ballot::new(4, &[]),
                    HN: 3,
                }),
            );

            externalized_slot
                .expect_handle_messages()
                .times(1)
                .return_const(Ok(Some(msg)));
        }
        node.push_externalized_slot(Box::new(externalized_slot));

        let msg_for_recent_slot = Msg::new(
            test_node_id(2),
            QuorumSet::new_with_node_ids(1, vec![test_node_id(3)]),
            slot_index - 1,
            Topic::Nominate(NominatePayload {
                X: Default::default(),
                Y: Default::default(),
            }),
        );

        match node.handle_messages(vec![msg_for_recent_slot]) {
            Ok(outgoing_msgs) => assert_eq!(outgoing_msgs.len(), 1), // Should return a message.
            Err(e) => panic!("Unexpected error {:?}", e),
        }
    }

    #[test_with_logger]
    // Should get externalized values from the correct externalized slot.
    fn test_get_externalized_values(logger: Logger) {
        let slot_index = 56;
        let mut node = get_node(slot_index, logger);
        node.set_max_externalized_slots(2);

        // push externalized slots for 51, 52, ..., 55
        for i in 51..slot_index {
            let mut externalized_slot = MockScpSlot::new();
            externalized_slot.expect_get_index().return_const(i);

            let msg = Msg::new(
                test_node_id(2),
                QuorumSet::new_with_node_ids(1, vec![test_node_id(3)]),
                i,
                Topic::Externalize(ExternalizePayload {
                    C: Ballot::new(4, &[]),
                    HN: 3,
                }),
            );

            externalized_slot
                .expect_get_last_message_sent()
                .return_const(Some(msg));

            node.push_externalized_slot(Box::new(externalized_slot));
        }

        // These slots are too old, and are no longer maintained.
        for i in 51..=53 {
            assert_eq!(node.get_externalized_values(i), None)
        }

        // Slots 54 and 55 should still be maintained.
        for i in 54..=55 {
            assert!(node.get_externalized_values(i).is_some());
        }
    }

    #[test_with_logger]
    fn test_process_timeouts(logger: Logger) {
        let mut node = get_node(0, logger);

        // Should call `propose_values` on the current slot.
        let mut slot = MockScpSlot::new();
        let messages: Vec<Msg<&'static str>> = vec![];
        slot.expect_process_timeouts()
            .times(1)
            .return_const(messages.clone());
        node.current_slot = Box::new(slot);

        // Should not call anything on an externalized slot, which no longer have
        // timeouts.
        let externalized_slot = MockScpSlot::new();
        node.push_externalized_slot(Box::new(externalized_slot));

        assert_eq!(node.process_timeouts(), messages);
    }

    #[test_with_logger]
    // Should reset `current_slot` to a new Slot for the given index.
    fn test_reset_slot_index(logger: Logger) {
        let slot_index = 14;
        let mut node = get_node(slot_index, logger);

        node.set_max_externalized_slots(2);
        for _i in 12..slot_index {
            let externalized_slot = MockScpSlot::new();
            node.push_externalized_slot(Box::new(externalized_slot));
        }

        assert_eq!(node.current_slot_index(), slot_index);
        assert_eq!(node.externalized_slots.len(), 2);

        let new_slot_index = 987;
        node.reset_slot_index(new_slot_index);
        assert_eq!(node.current_slot_index(), new_slot_index);
        assert_eq!(node.current_slot.get_index(), new_slot_index);

        // externalized_slots should be empty
        assert_eq!(node.externalized_slots.len(), 0);
    }

    #[test_with_logger]
    /// Steps through a sequence of messages that allow a two-node network to
    /// reach consensus.
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
