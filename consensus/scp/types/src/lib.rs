// Copyright (c) 2018-2022 The MobileCoin Foundation

#![no_std]
#![doc = include_str!("../../README.md")]
#![warn(unused_extern_crates)]
#![allow(non_snake_case)]

extern crate alloc;

pub mod core_types;
pub mod quorum_set;
#[cfg(any(test, feature = "test_utils"))]
pub mod test_utils;

#[doc(inline)]
pub use crate::{
    core_types::{GenericNodeId, Identifier, SlotIndex, Value},
    quorum_set::{QuorumSet, QuorumSetMember, QuorumSetMemberWrapper},
};
