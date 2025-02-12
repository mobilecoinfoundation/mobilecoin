// Copyright (c) 2018-2022 The MobileCoin Foundation

//! The fog ingest server
//!
//! The ingest server functions as the "engine" of fog.
//! It enables fog to post-process the blockchain and figure out which
//! transactions were going to which fog users, and then tag these transactions
//! with random values that those users know to search for, so that they can
//! find their transactions without revealing to the node operator which
//! transactions were theirs. It uses an SGX enclave to do all of this
//! decryption, and this enclave also contains an RNG per user that it is
//! supporting.

#![deny(missing_docs)]
#![allow(clippy::result_large_err)]

pub mod config;
pub mod connection;
pub mod connection_error;
pub mod connection_traits;
pub mod error;
pub mod ingest_peer_service;
pub mod ingest_service;
pub mod server;
pub mod state_file;

mod attested_api_service;
mod controller;
mod controller_state;
mod counters;
mod worker;

use mc_util_metrics::ServiceMetrics;

lazy_static::lazy_static! {
    /// Generates service metrics for tracking
    pub static ref SVC_COUNTERS: ServiceMetrics = ServiceMetrics::new_and_registered("fog_ingest_service");
}
