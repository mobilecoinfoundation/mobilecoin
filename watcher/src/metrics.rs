// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Watcher metrics comparing ledger height and block height

use mc_common::HashMap;
use mc_util_metrics::{IntGauge, OpMetrics};
use url::Url;

lazy_static::lazy_static! {
    /// Create metric object for tracking watcher
    pub static ref COLLECTOR: OpMetrics = OpMetrics::new_and_registered("watcher");
}

/// Watcher metrics tracker used to report metrics on watcher to Prometheus
pub struct WatcherMetrics {
    /// Number of blocks in the ledger
    ledger_block_height: IntGauge,
}

impl Default for WatcherMetrics {
    fn default() -> Self {
        Self::new()
    }
}

impl WatcherMetrics {
    /// Initialize new metrics object
    pub fn new() -> Self {
        let ledger_block_height = COLLECTOR.gauge("ledger_block_height");
        Self {
            ledger_block_height,
        }
    }

    /// Record current ledger height
    pub fn set_ledger_height(&self, ledger_height: i64) {
        self.ledger_block_height.set(ledger_height);
    }

    /// Measure blocks synced so far for each peer
    pub fn collect_peer_blocks_synced(&self, peer_sync_states: HashMap<Url, Option<u64>>) {
        peer_sync_states.iter().for_each(|(url, num_blocks)| {
            COLLECTOR
                .peer_gauge("watcher_blocks_synced", url.as_str())
                .set(num_blocks.unwrap_or(0) as i64);
        });
    }
}
