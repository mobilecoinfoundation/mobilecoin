// Copyright (c) 2018-2021 The MobileCoin Foundation

use mc_common::logger::{test_with_logger, Logger};
use mc_fog_sql_recovery_db::test_utils::SqlRecoveryDbTestContext;
use mc_fog_test_infra::db_tests::*;

#[test_with_logger]
fn sql_recovery_db_smoke_tests_new_apis(logger: Logger) {
    mc_util_test_helper::run_with_several_seeds(|mut rng| {
        let db_test_context = SqlRecoveryDbTestContext::new(logger.clone());
        let db = db_test_context.get_db_instance();

        recovery_db_smoke_tests_new_apis(&mut rng, &db);
    })
}

#[test_with_logger]
fn sql_recovery_db_missed_blocks_reporting(logger: Logger) {
    mc_util_test_helper::run_with_several_seeds(|mut rng| {
        let db_test_context = SqlRecoveryDbTestContext::new(logger.clone());
        let db = db_test_context.get_db_instance();

        recovery_db_missed_blocks_reporting(&mut rng, &db);
    })
}

#[test_with_logger]
fn sql_recovery_db_rng_records_decommissioning(logger: Logger) {
    mc_util_test_helper::run_with_several_seeds(|mut rng| {
        let db_test_context = SqlRecoveryDbTestContext::new(logger.clone());
        let db = db_test_context.get_db_instance();

        recovery_db_rng_records_decommissioning(&mut rng, &db);
    })
}

#[test_with_logger]
fn sql_recovery_db_ingress_keys(logger: Logger) {
    mc_util_test_helper::run_with_several_seeds(|mut rng| {
        let db_test_context = SqlRecoveryDbTestContext::new(logger.clone());
        let db = db_test_context.get_db_instance();

        test_recovery_db_ingress_keys(&mut rng, &db);
    })
}
