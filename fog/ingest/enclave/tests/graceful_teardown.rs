// Copyright (c) 2018-2021 The MobileCoin Foundation

use mc_common::{
    logger::{log, test_with_logger, Logger},
    ResponderId,
};
use mc_fog_ingest_enclave::{IngestSgxEnclave, ENCLAVE_FILE};
use mc_fog_test_infra::get_enclave_path;
use std::str::FromStr;

const NUM_TRIALS: usize = 3;
const OMAP_CAP: u64 = 256;

/// Test that we can create and destroy the Ingest enclave repeatedly without
/// crashing
#[test_with_logger]
fn ingest_enclave_graceful_teardown(logger: Logger) {
    for reps in 0..NUM_TRIALS {
        log::info!(logger, "Trial {}/{}", reps + 1, NUM_TRIALS);
        let _enclave = IngestSgxEnclave::new(
            get_enclave_path(ENCLAVE_FILE),
            &ResponderId::from_str("127.0.0.1:3040").unwrap(),
            &None,
            OMAP_CAP,
        );
    }
}
