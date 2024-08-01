// Copyright (c) 2018-2023 The MobileCoin Foundation

use mc_util_metrics::{Histogram, IntCounter, IntGauge, OpMetrics};

lazy_static::lazy_static! {
    pub static ref OP_COUNTERS: OpMetrics = OpMetrics::new_and_registered("light_client_relayer");

    // The last block index we processed.
    pub static ref LAST_PROCESSED_BLOCK_INDEX: IntGauge = OP_COUNTERS.gauge("last_processed_block_index");

    // Number of blocks processed since startup.
    pub static ref BLOCKS_PROCESSED_COUNT: IntCounter = OP_COUNTERS.counter("blocks_processed_count");

    // Time it takes to process a single block.
    pub static ref PROCESS_NEXT_BLOCK_TIME: Histogram = OP_COUNTERS.histogram("process_next_block_time");
}
