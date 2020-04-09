// Copyright (c) 2018-2020 MobileCoin Inc.

use lazy_static;
use metrics::{Histogram, IntCounter, IntGauge, OpMetrics};

lazy_static::lazy_static! {
    pub static ref OP_COUNTERS: OpMetrics = OpMetrics::new_and_registered("ledger_sync");
}

lazy_static::lazy_static! {
    // Blocks written through ledger sync since this node started.
    pub static ref BLOCKS_WRITTEN_COUNT: IntCounter = OP_COUNTERS.counter("blocks_written_count");

    // Transactions written through ledger sync since this node started.
    pub static ref TX_WRITTEN_COUNT: IntCounter = OP_COUNTERS.counter("tx_written_count");

    // Number of blocks written to the ledger (by querying ledger)
    pub static ref BLOCKS_IN_LEDGER: IntGauge = OP_COUNTERS.gauge("num_blocks");

    // Number of transactions written to the ledger (by querying ledger)
    pub static ref TX_IN_LEDGER: IntGauge = OP_COUNTERS.gauge("num_txs");

    // Number of txouts in the ledger (by querying ledger)
    pub static ref TXO_IN_LEDGER: IntGauge = OP_COUNTERS.gauge("num_txos");

    // Time it takes to perform append_block
    pub static ref APPEND_BLOCK_TIME: Histogram = OP_COUNTERS.histogram("append_block");
}
