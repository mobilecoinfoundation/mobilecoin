// Copyright (c) 2018-2022 The MobileCoin Foundation

#![doc = include_str!("../../README.md")]
#![cfg_attr(not(any(test, feature = "std", feature = "test_utils")), no_std)]
#![warn(unused_extern_crates)]
#![allow(non_snake_case)]
#![deny(missing_docs)]

extern crate alloc;

pub mod core_types;
pub mod msg;
pub mod predicates;
pub mod quorum_set;
#[cfg(any(test, feature = "test_utils"))]
pub mod test_utils;

#[doc(inline)]
pub use crate::{core_types::*, msg::*, predicates::*, quorum_set::*};
