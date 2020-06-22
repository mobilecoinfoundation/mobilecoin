// Copyright (c) 2018-2020 MobileCoin Inc.

#![feature(external_doc)]
#![doc(include = "../README.md")]
#![allow(non_snake_case)]
#![deny(missing_docs)]


#[cfg(test)]
#[macro_use]
extern crate pest_derive;

pub mod core_types;
pub mod msg;
pub mod node;
pub mod predicates;
pub mod quorum_set;
pub mod scp_log;
pub mod slot;
pub mod test_utils;
mod utils;

#[doc(inline)]
pub use self::{
    core_types::{CombineFn, GenericNodeId, Identifier, SlotIndex, ValidityFn, Value},
    msg::{Msg, Topic},
    node::{Node, ScpNode},
    quorum_set::{QuorumSet, QuorumSetMember},
};
