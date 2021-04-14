// Copyright (c) 2018-2021 The MobileCoin Foundation

//! LedgerDB metrics.
//! Usually we would use `uc_util_metrics::OpMetrics` for metric collections.
//! However, since there could exist multiple LedgerDB instances in a given
//! process, we'd like to group the metric collection by the database so that
//! they do not get mixed together. The code here is based on OpMetrics and
//! allows us to do so.

use mc_util_metrics::{
    register, Collector, Desc, Histogram, HistogramOpts, HistogramVec, IntCounter, IntCounterVec,
    IntGauge, IntGaugeVec, MetricFamily, Opts,
};
use std::{
    path::Path,
    time::{Duration, Instant},
};

/// Metrics collector - used internally to report metrics into the Prometheus
/// crate.
#[derive(Clone)]
struct LedgerMetricsCollector {
    /// Counters collection to be reported to Prometheus.
    counters: IntCounterVec,

    /// Gauges collection to be reported to Prometheus.
    gauges: IntGaugeVec,

    /// Duration histograms to be reported to Prometheus.
    duration: HistogramVec,
}

impl LedgerMetricsCollector {
    pub fn new_and_registered() -> Self {
        let metrics = Self {
            counters: IntCounterVec::new(
                Opts::new("ledger_db_counter", "LedgerDB Counters"),
                &["op", "db_path"],
            )
            .unwrap(),

            gauges: IntGaugeVec::new(
                Opts::new("ledger_db_gauge", "LedgerDB Gauges"),
                &["op", "db_path"],
            )
            .unwrap(),

            duration: HistogramVec::new(
                HistogramOpts::new("ledger_db_duration", "LedgerDB Duration Histograms"),
                &["op", "db_path"],
            )
            .unwrap(),
        };

        register(Box::new(metrics.clone()))
            .expect("LedgerMetrics registration on Prometheus failed.");

        metrics
    }
}

lazy_static::lazy_static! {
    static ref COLLECTOR: LedgerMetricsCollector = LedgerMetricsCollector::new_and_registered();
}

impl Collector for LedgerMetricsCollector {
    fn desc(&self) -> Vec<&Desc> {
        let mut ms = Vec::with_capacity(1);
        ms.extend(self.counters.desc());
        ms.extend(self.gauges.desc());
        ms.extend(self.duration.desc());
        ms
    }

    fn collect(&self) -> Vec<MetricFamily> {
        let mut ms = Vec::with_capacity(1);
        ms.extend(self.counters.collect());
        ms.extend(self.gauges.collect());
        ms.extend(self.duration.collect());
        ms
    }
}

/// The collection of metrics tracked for each LedgerDB instance.
#[derive(Clone)]
pub struct LedgerMetrics {
    /// Blocks written through ledger sync since this node started.
    pub blocks_written_count: IntCounter,

    /// Transaction outputs written through ledger sync since this node started.
    pub txo_written_count: IntCounter,

    /// Number of blocks written to the ledger (by querying ledger).
    pub num_blocks: IntGauge,

    /// Number of txouts in the ledger (by querying ledger).
    pub num_txos: IntGauge,

    /// The size (in bytes) of the ledger database.
    pub db_file_size: IntGauge,

    /// Time it takes to perform append_block.
    append_block_time: Histogram,
}

impl LedgerMetrics {
    pub fn new(db_path: &Path) -> Self {
        let db_path_str = db_path
            .to_str()
            .expect("failed converting ledger path to string");

        Self {
            blocks_written_count: COLLECTOR
                .counters
                .with_label_values(&["blocks_written_count", db_path_str]),

            txo_written_count: COLLECTOR
                .counters
                .with_label_values(&["txo_written_count", db_path_str]),

            num_blocks: COLLECTOR
                .gauges
                .with_label_values(&["num_blocks", db_path_str]),

            num_txos: COLLECTOR
                .gauges
                .with_label_values(&["num_txos", db_path_str]),

            db_file_size: COLLECTOR
                .gauges
                .with_label_values(&["db_file_size", db_path_str]),

            append_block_time: COLLECTOR
                .duration
                .with_label_values(&["append_block", db_path_str]),
        }
    }

    pub fn observe_append_block_time(&self, start_time: Instant) {
        self.append_block_time
            .observe(duration_to_seconds(start_time.elapsed()));
    }
}

/// `duration_to_seconds` converts Duration to seconds.
// Taken from `prometheus::histogram`.
#[inline]
fn duration_to_seconds(d: Duration) -> f64 {
    let nanos = f64::from(d.subsec_nanos()) / 1e9;
    d.as_secs() as f64 + nanos
}
