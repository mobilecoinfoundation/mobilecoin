// Copyright (c) 2018-2022 The MobileCoin Foundation

//! The state held by a single slot. Currently this duplicates the state inside
//! `Slot` and is only used for debug/serialization purposes but a future change
//! might embed a `SlotIndex` directly inside a `Slot`.

use crate::{
    core_types::{Ballot, SlotIndex, Value},
    msg::*,
    slot::{Phase, Slot},
};
use mc_common::{HashSet, NodeID};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeSet, fmt::Display};

/// Serializable slot state used for debugging purposes.
#[derive(Clone, Serialize, Deserialize)]
pub struct SlotState<V: Value> {
    /// Current slot number.
    slot_index: SlotIndex,

    /// Local node ID.
    node_id: NodeID,

    /// List of highest messages from each node.
    /// This is not stored as a HashMap since it simplifies serialization. The
    /// node id is part of the message so that can be derived.
    M: Vec<Msg<V>>,

    /// Set of values that have been proposed, but not yet voted for.
    W: HashSet<V>,

    /// Set of values we have voted to nominate.
    X: HashSet<V>,

    /// Set of values we have accepted as nominated.
    Y: HashSet<V>,

    /// Set of values we have confirmed as nominated.
    Z: HashSet<V>,

    /// Current ballot we are trying to pass.
    B: Ballot<V>,

    /// The highest accepted prepared ballot, if any.
    P: Option<Ballot<V>>,

    /// The highest accepted prepared ballot that is less-than-and-incompatible
    /// with P.
    PP: Option<Ballot<V>>,

    /// In Prepare: the highest ballot that this node confirms prepared, if any.
    /// In Commit: the highest ballot that this node accepts committed, if any.
    /// In Externalize: The highest ballot that this node confirms committed.
    H: Option<Ballot<V>>,

    /// In Prepare: The lowest ballot that this node votes to commit, if any.
    /// In Commit: The lowest ballot that this node accepts committed, if any.
    /// In Externalize: The lowest ballot that this node confirms committed.
    /// Invariant: if C is Some, C \lesssim H \lesssim B
    C: Option<Ballot<V>>,

    /// Current phase of the protocol.
    phase: Phase,

    /// Last message sent by us.
    last_sent_msg: Option<Msg<V>>,

    /// Max priority peers - nodes from which we listen to value nominations.
    max_priority_peers: HashSet<NodeID>,

    /// Current nomination round number.
    nominate_round: u32,

    /// List of values that have been checked to be valid for the current slot.
    /// We can cache this and save on validation calls since the ledger doesn't
    /// change during a slot.
    valid_values: BTreeSet<V>,
}
impl<V: Value, ValidationError: Display> From<&Slot<V, ValidationError>> for SlotState<V> {
    fn from(src: &Slot<V, ValidationError>) -> Self {
        Self {
            slot_index: src.slot_index,
            node_id: src.node_id.clone(),
            M: src.M.values().cloned().collect(),
            W: src.W.clone(),
            X: src.X.clone(),
            Y: src.Y.clone(),
            Z: src.Z.clone(),
            B: src.B.clone(),
            P: src.P.clone(),
            PP: src.PP.clone(),
            H: src.H.clone(),
            C: src.C.clone(),
            phase: src.phase,
            last_sent_msg: src.last_sent_msg.clone(),
            max_priority_peers: src.max_priority_peers.clone(),
            nominate_round: src.nominate_round,
            valid_values: src.valid_values.clone(),
        }
    }
}
