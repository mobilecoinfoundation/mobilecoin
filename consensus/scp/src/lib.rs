// Copyright (c) 2018-2021 The MobileCoin Foundation

#![feature(external_doc)]
#![doc(include = "../README.md")]
#![allow(non_snake_case)]
#![deny(missing_docs)]

pub mod core_types;
pub mod msg;
pub mod node;
pub mod predicates;
pub mod quorum_set;
pub mod scp_log;
pub mod slot;
pub mod slot_state;
pub mod test_utils;
mod utils;

#[doc(inline)]
pub use self::{
    core_types::{CombineFn, GenericNodeId, Identifier, SlotIndex, ValidityFn, Value},
    msg::{Msg, Topic},
    node::{MockScpNode, Node, ScpNode},
    quorum_set::{QuorumSet, QuorumSetMember},
};
