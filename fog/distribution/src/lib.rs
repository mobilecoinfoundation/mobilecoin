// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Fog-distribution is a tool which serves two purposes:
//! * Transfer funds from bootstrapped ledger to fog accounts (which can't get
//!   bootstrapped directly)
//! * Slam the network with transactions as a load test

#![deny(missing_docs)]

pub mod config;

pub use crate::config::Config;
