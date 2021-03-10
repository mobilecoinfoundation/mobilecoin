// Copyright (c) 2018-2021 The MobileCoin Foundation

//! Metrics reporting.

pub use chrono::prelude::{SecondsFormat, Utc};
use lazy_static::lazy_static;
pub use serde_json::json;

// ------------------------- Prometheus Metrics
// ------------------------------------
mod json_encoder;
mod op_counters;
mod service_metrics;

pub use json_encoder::JsonEncoder as MetricsJsonEncoder;
pub use op_counters::OpMetrics;
pub use prometheus::{
    core::{Collector, Desc},
    proto::MetricFamily,
    register, register_histogram, Histogram, HistogramOpts, HistogramVec, IntCounter,
    IntCounterVec, IntGauge, IntGaugeVec, Opts,
};
pub use service_metrics::ServiceMetrics;

lazy_static! {
    pub static ref SVC_COUNTERS: ServiceMetrics = ServiceMetrics::new_and_registered();
}
