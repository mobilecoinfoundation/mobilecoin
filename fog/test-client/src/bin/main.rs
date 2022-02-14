// Copyright (c) 2018-2021 The MobileCoin Foundation

//! Test Client

use mc_common::logger::{create_app_logger, log, o};

use grpcio::{RpcStatus, RpcStatusCode};
use mc_fog_test_client::{
    config::TestClientConfig,
    error::TestClientError,
    test_client::{TestClient, TestClientPolicy},
};
use mc_util_grpc::AdminServer;
use mc_util_parse::{load_css_file, CssSignature};
use serde::Serialize;
use std::sync::Arc;
use structopt::StructOpt;

#[derive(Serialize, Debug, Clone)]
struct JsonData {
    pub policy: TestClientPolicy,
    pub config: TestClientConfig,
}

fn main() {
    mc_common::setup_panic_handler();
    let (logger, _global_logger_guard) = create_app_logger(o!());

    let config = TestClientConfig::from_args();

    let _tracer = mc_util_telemetry::setup_default_tracer(env!("CARGO_PKG_NAME"))
        .expect("Failed setting telemetry tracer");

    // Set up test client policy taking into account the runtime config values
    let policy = TestClientPolicy {
        fail_fast_on_deadline: !config.measure_after_deadline,
        // Don't test RTH memos when passed --no_memos
        test_rth_memos: !config.no_memos,
        tx_submit_deadline: config.consensus_wait,
        tx_receive_deadline: config.consensus_wait,
        double_spend_wait: config.ledger_sync_wait,
        transfer_amount: config.transfer_amount,
        ..Default::default()
    };

    let account_keys = config.load_accounts(&logger);

    // Start an admin server to publish prometheus metrics, if admin_listen_uri is
    // given
    let admin_server = config.admin_listen_uri.as_ref().map(|admin_listen_uri| {
        let json_data = JsonData {
            config: config.clone(),
            policy: policy.clone(),
        };

        let get_config_json = Arc::new(move || {
            serde_json::to_string(&json_data).map_err(|err| {
                RpcStatus::with_message(RpcStatusCode::INTERNAL, format!("{:?}", err))
            })
        });
        AdminServer::start(
            None,
            admin_listen_uri,
            "Fog Test Client".to_owned(),
            "".to_string(),
            Some(get_config_json),
            logger.clone(),
        )
        .expect("Failed starting admin server")
    });

    // Initialize test_client
    let test_client = TestClient::new(
        policy,
        account_keys,
        config.consensus_config.consensus_validators,
        config.fog_ledger,
        config.fog_view,
        config.grpc_retry_config,
        logger.clone(),
    )
    .consensus_sigstruct(maybe_load_css(&config.consensus_enclave_css))
    .fog_ingest_sigstruct(maybe_load_css(&config.ingest_enclave_css))
    .fog_ledger_sigstruct(maybe_load_css(&config.ledger_enclave_css))
    .fog_view_sigstruct(maybe_load_css(&config.view_enclave_css));

    // Run continuously or run as a fixed length test, according to config
    if config.continuous {
        log::info!(logger, "One tx / {:?}", config.transfer_period);

        if admin_server.is_none() {
            log::warn!(
                logger,
                "Admin not configured, metrics will not be available"
            );
        }

        test_client.run_continuously(config.transfer_period);
    } else {
        log::info!(logger, "Running {} test transfers", config.num_transactions);

        match test_client.run_test(config.num_transactions) {
            Ok(()) => log::info!(logger, "All tests passed"),
            Err(TestClientError::TxTimeout) => panic!(
                "Transactions could not clear in {:?} seconds",
                config.consensus_wait
            ),
            Err(e) => panic!("Unexpected error {:?}", e),
        }
    }
}

fn maybe_load_css(maybe_file: &Option<String>) -> Option<CssSignature> {
    maybe_file
        .as_ref()
        .map(|x| load_css_file(x).expect("Could not load css file"))
}
