// Copyright (c) 2018-2020 MobileCoin Inc.

mod mock_network;

use mc_common::logger::{log, test_with_logger, Logger};
use serial_test_derive::serial;

fn optimize_mesh_helper(parameters_to_vary: Vec<bool>, logger: Logger) {
    if mock_network::optimization::skip_optimization() {
        return;
    }

    log::warn!(logger, "varying: {:?}", parameters_to_vary);
    for num_nodes in 1..7 {
        for k in num_nodes / 2..num_nodes {
            let network = mock_network::mesh_topology::dense_mesh(num_nodes, k);
            mock_network::optimization::optimize(
                &network,
                parameters_to_vary.clone(),
                logger.clone(),
            );
        }
    }
}

#[test_with_logger]
#[serial]
fn optimize_submissions_per_sec(logger: Logger) {
    let parameters_to_vary = vec![true, false, false];
    optimize_mesh_helper(parameters_to_vary, logger);
}

#[test_with_logger]
#[serial]
fn optimize_max_pending_values_to_nominate(logger: Logger) {
    let parameters_to_vary = vec![true, false, false];
    optimize_mesh_helper(parameters_to_vary, logger);
}

#[test_with_logger]
#[serial]
fn optimize_scp_timebase(logger: Logger) {
    let parameters_to_vary = vec![false, false, true];
    optimize_mesh_helper(parameters_to_vary, logger);
}

#[test_with_logger]
#[serial]
fn optimize_11(logger: Logger) {
    let parameters_to_vary = vec![true, true, false];
    optimize_mesh_helper(parameters_to_vary, logger);
}

#[test_with_logger]
#[serial]
fn optimize_23(logger: Logger) {
    let parameters_to_vary = vec![false, true, true];
    optimize_mesh_helper(parameters_to_vary, logger);
}

#[test_with_logger]
#[serial]
fn optimize_31(logger: Logger) {
    let parameters_to_vary = vec![true, false, true];
    optimize_mesh_helper(parameters_to_vary, logger);
}

#[test_with_logger]
#[serial]
fn optimize_all(logger: Logger) {
    let parameters_to_vary = vec![true, true, true];
    optimize_mesh_helper(parameters_to_vary, logger);
}
