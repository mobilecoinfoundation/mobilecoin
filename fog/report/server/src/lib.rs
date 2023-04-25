// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Server for ingest reports.

#![deny(missing_docs)]

mod config;
mod server;
mod service;

pub use crate::{
    config::{Config, Error, Materials},
    server::Server,
};

use mc_util_metrics::ServiceMetrics;

lazy_static::lazy_static! {
    /// Generates service metrics for tracking
    pub static ref SVC_COUNTERS: ServiceMetrics = ServiceMetrics::new_and_registered("fog_report_service");
}
