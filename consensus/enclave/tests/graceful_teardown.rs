// Copyright (c) 2018-2022 The MobileCoin Foundation

use mc_common::{
    logger::{log, test_with_logger, Logger},
    ResponderId,
};
use mc_consensus_enclave::{ConsensusServiceSgxEnclave, ENCLAVE_FILE};
use mc_fog_test_infra::get_enclave_path;
use std::str::FromStr;

const NUM_TRIALS: usize = 3;

/// Test that we can create and destroy the consensus enclave repeatedly without
/// crashing
#[test_with_logger]
fn consensus_enclave_graceful_teardown(logger: Logger) {
    let responder_id = ResponderId::from_str("127.0.0.1:3000").unwrap();
    let block_version = BlockVersion::MAX;
    let fee_map = FeeMap::default();

    let blockchain_config = BlockchainConfig {
        block_version,
        fee_map: fee_map.clone(),
        ..Default::default()
    };

    for reps in 0..NUM_TRIALS {
        log::info!(logger, "Trial {}/{}", reps + 1, NUM_TRIALS);
        let _enclave = ConsensusServiceSgxEnclave::new(
            get_enclave_path(ENCLAVE_FILE),
            &responder_id,
            &responder_id,
            None,
            blockchain_config,
            &logger,
        )
        .expect("could not initialize enclave");
    }
}
