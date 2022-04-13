// Copyright (c) 2018-2022 The MobileCoin Foundation

#![doc = include_str!("../README.md")]
#![allow(non_snake_case)]
#![deny(missing_docs)]

pub mod node;
pub mod scp_log;
pub mod slot;
pub mod slot_state;
#[cfg(any(test, feature = "test_utils"))]
pub mod test_utils;
mod utils;

#[doc(inline)]
pub use mc_consensus_scp_core::{core_types, msg, predicates, quorum_set};

#[doc(inline)]
pub use crate::{
    core_types::{CombineFn, GenericNodeId, Identifier, SlotIndex, ValidityFn, Value},
    msg::{Msg, Topic},
    node::{MockScpNode, Node, ScpNode},
    quorum_set::{QuorumSet, QuorumSetMember},
};
