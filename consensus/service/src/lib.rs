// Copyright (c) 2018-2020 MobileCoin Inc.

//! The MobileCoin consensus node.

#![feature(test)]

#[cfg(test)]
extern crate test;

pub mod config;
pub mod consensus_service;
pub mod tx_manager;
pub mod validators; // Public so that it can be benchmarked by the `benchmarks` crate.

mod attested_api_service;
mod background_work_queue;
mod blockchain_api_service;
mod byzantine_ledger;
mod client_api_service;
mod counters;
mod grpc_error;
mod peer_api_service;
mod peer_keepalive;
