// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Prometheus counters.

use mc_util_metrics::{IntGauge, OpMetrics};

lazy_static::lazy_static! {
    /// Prometheus counters.
    pub static ref OP_COUNTERS: OpMetrics = OpMetrics::new_and_registered("mc-mint-auditor");

    /// Number of blocks synced.
    pub static ref NUM_BLOCKS_SYNCED: IntGauge = OP_COUNTERS.gauge("num_blocks_synced");

    /// Number of burns exceeding calculated balance.
    pub static ref NUM_BURNS_EXCEEDING_BALANCE: IntGauge = OP_COUNTERS.gauge("num_burns_exceeding_balance");

    /// Number of MintTxs without a matching MintConfig.
    pub static ref NUM_MINT_TXS_WITHOUT_MATCHING_MINT_CONFIG: IntGauge = OP_COUNTERS.gauge("num_mint_txs_without_matching_mint_config");
}
