// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Metrics reporting.

pub use chrono::prelude::{SecondsFormat, Utc};
pub use serde_json::json;

// ------------------------- Prometheus Metrics
// ------------------------------------
mod json_encoder;
mod op_counters;
#[cfg(feature = "service_metrics")]
mod service_metrics;

pub use json_encoder::JsonEncoder as MetricsJsonEncoder;
pub use op_counters::OpMetrics;
pub use prometheus::{
    core::{Collector, Desc},
    proto::MetricFamily,
    register, register_histogram, Histogram, HistogramOpts, HistogramVec, IntCounter,
    IntCounterVec, IntGauge, IntGaugeVec, Opts,
};
#[cfg(feature = "service_metrics")]
pub use service_metrics::{GrpcMethodName, ServiceMetrics};
