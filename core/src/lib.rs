// Copyright (c) 2018-2022 The MobileCoin Foundation

//! MobileCoin core library.
//! This provides base types and common functions for mobilecoin implementers /
//! consumers.

#![no_std]
#![warn(missing_docs)]
#![deny(unsafe_code)]

// Re-export shared type modules
pub use mc_core_types::{account, keys};

pub mod consts;

pub mod memo;

pub mod subaddress;

pub mod slip10;

pub mod traits;

pub mod account_id;
