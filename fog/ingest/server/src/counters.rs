// Copyright (c) 2018-2021 MobileCoin Inc.

use mc_util_metrics::{Histogram, IntCounter, IntGauge, OpMetrics};

// Numerical values for the 2 possible modes.
pub const MODE_IDLE: i64 = 0;
pub const MODE_ACTIVE: i64 = 1;

lazy_static::lazy_static! {
    pub static ref OP_COUNTERS: OpMetrics = OpMetrics::new_and_registered("fog_ingest");

    // The last block index we processed.
    pub static ref LAST_PROCESSED_BLOCK_INDEX: IntGauge = OP_COUNTERS.gauge("last_processed_block_index");

    // Number of blocks processed since startup.
    pub static ref BLOCKS_PROCESSED_COUNT: IntCounter = OP_COUNTERS.counter("blocks_processed_count");

    // The latest pubkey_expiry of a report that we published
    pub static ref LAST_PUBLISHED_PUBKEY_EXPIRY: IntGauge = OP_COUNTERS.gauge("last_published_pubkey_expiry");

    // Time it takes to process a single block.
    pub static ref PROCESS_NEXT_BLOCK_TIME: Histogram = OP_COUNTERS.histogram("process_next_block_time");

    // Time it takes to perform the enclave ingest_txs call.
    pub static ref INGEST_TXS_TIME: Histogram = OP_COUNTERS.histogram("ingest_txs_time");

    // Time it takes to perform the db add_block_data call.
    pub static ref DB_ADD_BLOCK_DATA_TIME: Histogram = OP_COUNTERS.histogram("db_add_block_data_time");

    // Ingest enclave report timestamp, represented as seconds of UTC time since Unix epoch 1970-01-01T00:00:00Z.
    pub static ref ENCLAVE_REPORT_TIMESTAMP: IntGauge = OP_COUNTERS.gauge("enclave_report_timestamp");

    // Whether this ingest server is currently in the Idle mode.
    pub static ref MODE_IS_IDLE: IntGauge = OP_COUNTERS.gauge("mode_is_idle");

    // Whether this ingest server is currently in the Active mode.
    pub static ref MODE_IS_ACTIVE: IntGauge = OP_COUNTERS.gauge("mode_is_active");

    // Current mode of ingest server (0=Idle, 1=Active).
    pub static ref MODE: IntGauge = OP_COUNTERS.gauge("mode");
}
