// Copyright (c) 2018-2020 MobileCoin Inc.

// Simplex style optimization over SCP TestOption parameters.

// Optimization takes a long time so we will ignore these tests by default
// example:
// export MC_LOG=warn; export OPTIMIZE=1; cargo test --release -- --test-threads=1 2>&1 | tee output.log

// We allow dead code because not all integration tests use all of the common code.
// https://github.com/rust-lang/rust/issues/46379
#![allow(dead_code)]

use crate::mock_network;
use mc_common::logger::{log, Logger};
use simplers_optimization::Optimizer;
use std::{
    convert::TryFrom,
    time::{Duration, Instant},
};

// we are using a fixed number of iterations for the optimizer
// this could be improved someday by observing the runtime settle
const OPTIMIZER_ITERATIONS: usize = 30;

// Optimization range limits
const MIN_SUBMISSIONS_PER_SEC: f64 = 5000.0;
const MAX_SUBMISSIONS_PER_SEC: f64 = 20000.0;

const MIN_VALUES_PER_SLOT: f64 = 50.0;
const MAX_VALUES_PER_SLOT: f64 = 2000.0;

const MIN_SCP_TIMEBASE_MSEC: f64 = 40.0;
const MAX_SCP_TIMEBASE_MSEC: f64 = 4000.0;

/// Support skipping optimization tests based on environment variables
pub fn skip_optimization() -> bool {
    std::env::var("OPTIMIZE").is_err()
}

/// Measures runtime in msec for a mock network
pub fn mock_network_optimizer(
    network: &mock_network::Network,
    parameters_to_vary: Vec<bool>,
    submissions_per_sec_f64: f64,
    max_pending_values_to_nominate_f64: f64,
    scp_timebase_millis_f64: f64,
    logger: Logger,
) -> f64 {
    let mut test_options = mock_network::TestOptions::new();
    test_options.values_to_submit = 1000;
    test_options.allowed_test_time = Duration::from_secs(600);

    if parameters_to_vary[0] {
        test_options.submissions_per_sec =
            u64::try_from(submissions_per_sec_f64.trunc() as i64).unwrap();
    }
    if parameters_to_vary[1] {
        test_options.max_pending_values_to_nominate =
            usize::try_from(max_pending_values_to_nominate_f64.trunc() as i64).unwrap();
    }
    if parameters_to_vary[2] {
        let scp_timebase_millis = u64::try_from(scp_timebase_millis_f64.trunc() as i64).unwrap();
        test_options.scp_timebase = Duration::from_millis(scp_timebase_millis);
    }

    // make copies of parameters
    let v0 = test_options.submissions_per_sec;
    let v1 = test_options.max_pending_values_to_nominate;
    let v2 = test_options.scp_timebase.as_millis();

    let start = Instant::now();
    mock_network::build_and_test(&network, &test_options, logger.clone());
    let runtime = start.elapsed().as_millis();

    // observe progress
    log::info!(logger, "optimizer: {}, {}, {}, {}", v0, v1, v2, runtime,);

    return runtime as f64;
}

// optimize performance over submission rate, submissions per slot, and scp timebase
pub fn optimize(network: &mock_network::Network, parameters_to_vary: Vec<bool>, logger: Logger) {
    let start = Instant::now();

    let f = |v: &[f64]| {
        mock_network_optimizer(
            &network,
            parameters_to_vary.clone(),
            v[0],
            v[1],
            v[2],
            logger.clone(),
        )
    };

    let input_interval: Vec<(f64, f64)> = vec![
        (MIN_SUBMISSIONS_PER_SEC, MAX_SUBMISSIONS_PER_SEC),
        (MIN_VALUES_PER_SLOT, MAX_VALUES_PER_SLOT),
        (MIN_SCP_TIMEBASE_MSEC, MAX_SCP_TIMEBASE_MSEC),
    ];

    let (min_value, coordinates) = Optimizer::minimize(&f, &input_interval, OPTIMIZER_ITERATIONS);

    let default_options = mock_network::TestOptions::new();
    let mut c0 = default_options.submissions_per_sec as f64;
    let mut c1 = default_options.max_pending_values_to_nominate as f64;
    let mut c2 = default_options.scp_timebase.as_millis() as f64;

    if parameters_to_vary[0] {
        c0 = coordinates[0];
    }
    if parameters_to_vary[1] {
        c1 = coordinates[1];
    }
    if parameters_to_vary[2] {
        c2 = coordinates[2];
    }

    log::warn!(
        logger,
        "{}, {}, {}, {}, {}, {}, {}, {}, {:?}",
        network.name,
        min_value,
        u64::try_from(c0.trunc() as i64).unwrap(),
        usize::try_from(c1.trunc() as i64).unwrap(),
        u64::try_from(c2.trunc() as i64).unwrap(),
        (default_options.values_to_submit as f64 * 1000.0) / min_value,
        start.elapsed().as_millis(),
        OPTIMIZER_ITERATIONS,
        input_interval,
    );
}
