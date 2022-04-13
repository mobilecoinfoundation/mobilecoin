// Copyright (c) 2018-2022 The MobileCoin Foundation

#![doc = include_str!("../../README.md")]
#![cfg_attr(not(any(test, feature = "std", feature = "test_utils")), no_std)]
#![warn(unused_extern_crates)]
#![allow(non_snake_case)]

// FIXME: Re-enable when prost-generated for `derive(Oneof)` has the necessary
// doc comments: https://github.com/tokio-rs/prost/issues/237
//#![deny(missing_docs)]

extern crate alloc;

pub mod core_types;
pub mod quorum_set;
#[cfg(any(test, feature = "test_utils"))]
pub mod test_utils;

#[doc(inline)]
pub use crate::{
    core_types::{GenericNodeId, Identifier, SlotIndex, Value},
    quorum_set::{QuorumSet, QuorumSetMember},
};
