// Copyright (c) 2018-2022 The MobileCoin Foundation

//! MobileCoin Fog View target
#![allow(clippy::result_large_err)]
use mc_util_metrics::ServiceMetrics;

pub mod config;
pub mod error;
pub mod fog_view_router_server;
pub mod fog_view_router_service;
pub mod fog_view_service;
pub mod fog_view_service_standalone;
pub mod server;
pub mod sharding_strategy;

mod block_tracker;
mod counters;
mod db_fetcher;
mod router_admin_service;
mod router_request_handler;
mod shard_responses_processor;

lazy_static::lazy_static! {
    pub static ref SVC_COUNTERS: ServiceMetrics = ServiceMetrics::new_and_registered("fog_view_service");
}
