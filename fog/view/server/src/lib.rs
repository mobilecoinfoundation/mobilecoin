// Copyright (c) 2018-2022 The MobileCoin Foundation

//! MobileCoin Fog View target
use mc_util_metrics::ServiceMetrics;

pub mod config;
pub mod error;
pub mod fog_view_service;
pub mod server;

mod block_tracker;
mod counters;
mod db_fetcher;

lazy_static::lazy_static! {
    pub static ref SVC_COUNTERS: ServiceMetrics = ServiceMetrics::new_and_registered("fog_view");
}
