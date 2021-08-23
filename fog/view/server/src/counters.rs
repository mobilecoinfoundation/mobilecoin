// Copyright (c) 2018-2021 MobileCoin Inc.

use mc_util_metrics::{Histogram, IntCounter, IntGauge, OpMetrics};

lazy_static::lazy_static! {
    pub static ref OP_COUNTERS: OpMetrics = OpMetrics::new_and_registered("fog_view");

    // View enclave report timestamp, represented as seconds of UTC time since Unix epoch 1970-01-01T00:00:00Z.
    pub static ref ENCLAVE_REPORT_TIMESTAMP: IntGauge = OP_COUNTERS.gauge("enclave_report_timestamp");

    // Number of blocks fetched (from the database) since startup.
    pub static ref BLOCKS_FETCHED_COUNT: IntCounter = OP_COUNTERS.counter("blocks_fetched_count");

    // Number of txos fetched (from the database) since startup.
    pub static ref TXOS_FETCHED_COUNT: IntCounter = OP_COUNTERS.counter("txos_fetched_count");

    // Number of blocks added (to the enclave) since startup.
    pub static ref BLOCKS_ADDED_COUNT: IntCounter = OP_COUNTERS.counter("blocks_added_count");

    // Number of txos added (to the enclave) since startup.
    pub static ref TXOS_ADDED_COUNT: IntCounter = OP_COUNTERS.counter("txos_added_count");

    // Time it takes to perform the enclave add_records call.
    pub static ref ENCLAVE_ADD_RECORDS_TIME: Histogram = OP_COUNTERS.histogram("enclave_add_records_time");

    // Time it takes to perform the db get_tx_outs_by_block call.
    pub static ref GET_TX_OUTS_BY_BLOCK_TIME: Histogram = OP_COUNTERS.histogram("get_tx_outs_by_block_time");

    // Time it takes to perform the load_ingress_keys call.
    pub static ref LOAD_INGRESS_KEYS_TIME: Histogram = OP_COUNTERS.histogram("load_ingress_keys_time");

    // Time it takes to perform the load_missing_block_ranges call.
    pub static ref LOAD_MISSING_BLOCK_RANGES_TIME: Histogram = OP_COUNTERS.histogram("load_missing_block_ranges_time");

    // Highest procesed block count
    pub static ref HIGHEST_PROCESSED_BLOCK_COUNT: IntGauge = OP_COUNTERS.gauge("highest_processed_block_count");

    // Last known block count
    pub static ref LAST_KNOWN_BLOCK_COUNT: IntGauge = OP_COUNTERS.gauge("last_known_block_count");

    // Last known block cumulative txo count
    pub static ref LAST_KNOWN_BLOCK_CUMULATIVE_TXO_COUNT: IntGauge = OP_COUNTERS.gauge("last_known_block_cumulative_txo_count");

    // Number of records currently in the db fetcher fetched_records queue.
    pub static ref DB_FETCHER_NUM_QUEUED_RECORDS: IntGauge = OP_COUNTERS.gauge("db_fetcher_num_queued_records");
}
