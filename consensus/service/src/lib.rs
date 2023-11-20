// Copyright (c) 2018-2022 The MobileCoin Foundation

//! The MobileCoin consensus node.

#![feature(test)]
#![allow(clippy::result_large_err)]

#[cfg(test)]
extern crate test;
use mc_util_metrics::ServiceMetrics;

pub mod consensus_service;
pub mod mint_tx_manager;
pub mod tx_manager;
pub mod validators; // Public so that it can be benchmarked by the `benchmarks` crate.

mod api;
mod background_work_queue;
mod byzantine_ledger;
mod counters;
mod peer_keepalive;
mod timestamp_validator;

lazy_static::lazy_static! {
    pub static ref SVC_COUNTERS: ServiceMetrics = ServiceMetrics::new_and_registered("consensus_service");
}
