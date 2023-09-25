// Copyright (c) 2018-2022 The MobileCoin Foundation

use mc_util_metrics::{Histogram, IntCounter, OpMetrics};

lazy_static::lazy_static! {
          pub static ref OP_COUNTERS: OpMetrics = OpMetrics::new_and_registered("fog_ledger");
          // Time it takes to perform the enclave add_records call.
          pub static ref ENCLAVE_ADD_KEY_IMAGE_DATA_TIME: Histogram = OP_COUNTERS.histogram("enclave_add_records_time");
          // Number of blocks added (to the enclave) since startup.
          pub static ref BLOCKS_ADDED_COUNT: IntCounter = OP_COUNTERS.counter("blocks_added_count");
          // Number of keyimages fetched (from the database) since startup.
          pub static ref KEY_IMAGES_FETCHED_COUNT: IntCounter = OP_COUNTERS.counter("keyimages_fetched_count");
}
