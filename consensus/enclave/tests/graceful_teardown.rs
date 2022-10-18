// Copyright (c) 2018-2022 The MobileCoin Foundation

use mc_attest_net::{Client, RaClient};
use mc_common::{
    logger::{log, test_with_logger, Logger},
    ResponderId,
};
use mc_consensus_enclave::{ConsensusServiceSgxEnclave, ENCLAVE_FILE};
use mc_consensus_enclave_api::{BlockchainConfig, FeeMap};
use mc_fog_test_infra::get_enclave_path;
use mc_sgx_report_cache_untrusted::ReportCache;
use mc_transaction_core::BlockVersion;
use mc_util_metrics::IntGauge;
use std::str::FromStr;

const NUM_TRIALS: usize = 3;

lazy_static::lazy_static! {
    pub static ref DUMMY_INT_GAUGE: IntGauge = IntGauge::new("foo".to_string(), "bar".to_string()).unwrap();
}

/// Test that we can create and destroy the consensus enclave repeatedly without
/// crashing. Given the amount of unsafe C code involved, this is worth testing.
#[test_with_logger]
fn consensus_enclave_graceful_teardown(logger: Logger) {
    let responder_id = ResponderId::from_str("127.0.0.1:3000").unwrap();
    let block_version = BlockVersion::MAX;
    let fee_map = FeeMap::default();

    let blockchain_config = BlockchainConfig {
        block_version,
        fee_map,
        ..Default::default()
    };

    for reps in 0..NUM_TRIALS {
        log::info!(logger, "Trial {}/{}", reps + 1, NUM_TRIALS);
        let (enclave, _, _) = ConsensusServiceSgxEnclave::new(
            get_enclave_path(ENCLAVE_FILE),
            &responder_id,
            &responder_id,
            &None,
            blockchain_config.clone(),
        );

        // Update enclave report cache, using SIM or HW-mode RA client as appropriate
        let ias_spid = Default::default();
        let ias_api_key = core::str::from_utf8(&[0u8; 64]).unwrap();
        let ias_client = Client::new(ias_api_key).expect("Could not create IAS client");

        let report_cache = ReportCache::new(
            enclave.clone(),
            ias_client,
            ias_spid,
            &DUMMY_INT_GAUGE,
            logger.clone(),
        );
        report_cache.start_report_cache().unwrap();
        report_cache.update_enclave_report_cache().unwrap();
    }
}
