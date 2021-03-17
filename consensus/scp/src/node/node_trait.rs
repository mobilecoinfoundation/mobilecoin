// Copyright (c) 2018-2021 The MobileCoin Foundation

use crate::{slot::SlotMetrics, Msg, QuorumSet, SlotIndex, Value};
use mc_common::NodeID;
use mockall::*;
use std::collections::BTreeSet;

/// A node capable of participating in SCP.
#[automock]
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

    /// Maximum number of stored externalized slots.
    fn max_externalized_slots(&self) -> usize;

    /// Set the maximum number of stored externalized slots. Must be non-zero.
    fn set_max_externalized_slots(&mut self, n: usize);

    /// Get externalized values (or an empty vector) for a given slot index.
    fn get_externalized_values(&self, slot_index: SlotIndex) -> Option<Vec<V>>;

    /// Process pending timeouts.
    fn process_timeouts(&mut self) -> Vec<Msg<V>>;

    /// Get the current slot's index.
    fn current_slot_index(&self) -> SlotIndex;

    /// Get metrics for the current slot.
    fn get_current_slot_metrics(&mut self) -> SlotMetrics;

    /// Additional debug info, e.g. a JSON representation of the Slot's state.
    fn get_slot_debug_snapshot(&mut self, slot_index: SlotIndex) -> Option<String>;

    /// Set the node's current slot index, abandoning any current and
    /// externalized slots.
    fn reset_slot_index(&mut self, slot_index: SlotIndex);
}
