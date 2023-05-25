// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Fog overseer metrics.

pub mod counters;

use mc_common::logger::{log, Logger};
use mc_fog_api::ingest_common::{IngestControllerMode, IngestSummary};
use std::collections::HashSet;

/// Increments the `unresponsive_node_count` metric.
pub fn increment_unresponsive_node_count(logger: &Logger) {
    log::trace!(logger, "Setting unresponsive node metric.");
    counters::UNRESPONSIVE_NODE_COUNT.inc();
}

/// Sets prometheus metrics.
pub fn set_metrics(logger: &Logger, ingest_summaries: &[IngestSummary]) {
    log::trace!(logger, "Setting prometheus metrics.");

    let ingress_key_count = get_ingress_key_count(ingest_summaries);
    counters::INGRESS_KEY_COUNT.set(ingress_key_count);

    let egress_key_count = get_egress_key_count(ingest_summaries);
    counters::EGRESS_KEY_COUNT.set(egress_key_count);

    let active_node_count = get_active_node_count(ingest_summaries);
    counters::ACTIVE_NODE_COUNT.set(active_node_count);

    let idle_node_count = ingest_summaries.len() as i64 - active_node_count;
    counters::IDLE_NODE_COUNT.set(idle_node_count);
}

fn get_ingress_key_count(ingest_summaries: &[IngestSummary]) -> i64 {
    let ingress_key_count = ingest_summaries
        .iter()
        .map(|ingest_summary| ingest_summary.get_ingress_pubkey().get_data())
        .collect::<HashSet<_>>()
        .len();

    ingress_key_count.try_into().unwrap()
}

fn get_egress_key_count(ingest_summaries: &[IngestSummary]) -> i64 {
    let egress_key_count = ingest_summaries
        .iter()
        .map(|ingest_summary| ingest_summary.get_egress_pubkey())
        .collect::<HashSet<_>>()
        .len();

    egress_key_count.try_into().unwrap()
}

fn get_active_node_count(ingest_summaries: &[IngestSummary]) -> i64 {
    ingest_summaries
        .iter()
        .filter(|ingest_summary| ingest_summary.get_mode() == IngestControllerMode::Active)
        .count()
        .try_into()
        .unwrap()
}
