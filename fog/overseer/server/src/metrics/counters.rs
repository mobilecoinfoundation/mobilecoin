// Copyright (c) 2018-2022 MobileCoin Inc.

//! Defines Prometheus metrics that Fog Overseer emits.

use mc_util_metrics::{IntGauge, OpMetrics};

lazy_static::lazy_static! {
    pub static ref OP_COUNTERS: OpMetrics = OpMetrics::new_and_registered("fog_overseer");

    /// Number of unique ingress keys currently held by the Fog Ingest nodes 
    /// that Fog Overseer monitors.
    pub static ref INGRESS_KEY_COUNT: IntGauge = OP_COUNTERS.gauge("ingress_key_count");

    /// Number of egress keys currently held by the Fog Ingest nodes that
    /// Fog Overseer monitors.
    pub static ref EGRESS_KEY_COUNT: IntGauge = OP_COUNTERS.gauge("egress_key_count");

    /// Number of active Fog Ingest nodes.
    pub static ref ACTIVE_NODE_COUNT: IntGauge = OP_COUNTERS.gauge("active_node_count");

    /// Number of idle Fog Ingest nodes.
    pub static ref IDLE_NODE_COUNT: IntGauge = OP_COUNTERS.gauge("idle_node_count");
}
