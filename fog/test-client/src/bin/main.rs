// Copyright (c) 2018-2021 The MobileCoin Foundation

//! Test Client

use mc_common::logger::{create_app_logger, log, o};

use core::convert::TryFrom;
use grpcio::{RpcStatus, RpcStatusCode};
use mc_fog_test_client::{
    config::TestClientConfig,
    error::TestClientError,
    test_client::{TestClient, TestClientPolicy},
};
use mc_sgx_css::Signature;
use mc_util_grpc::AdminServer;
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

    // Set up test client policy taking into account the runtime config values
    let policy = TestClientPolicy {
        // Don't fail fast when running continuously, we want to keep measuring after the deadline
        fail_fast_on_deadline: !config.continuous,
        // Don't test RTH memos when passed --no_memos
        test_rth_memos: !config.no_memos,
        tx_submit_deadline: config.consensus_wait,
        tx_receive_deadline: config.consensus_wait,
        double_spend_wait: config.ledger_sync_wait,
        transfer_amount: config.transfer_amount,
        ..Default::default()
    };

    let account_keys = config.load_accounts(&logger);

    // Load any css from disk
    let consensus_sigstruct = config
        .consensus_enclave_css
        .as_ref()
        .map(load_css_file)
        .transpose()
        .expect("loading css failed");
    let fog_ingest_sigstruct = config
        .fog_ingest_enclave_css
        .as_ref()
        .map(load_css_file)
        .transpose()
        .expect("loading css failed");
    let fog_ledger_sigstruct = config
        .fog_ledger_enclave_css
        .as_ref()
        .map(load_css_file)
        .transpose()
        .expect("loading css failed");
    let fog_view_sigstruct = config
        .fog_view_enclave_css
        .as_ref()
        .map(load_css_file)
        .transpose()
        .expect("loading css failed");

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
        .expect("Failed starting admin server");
    });

    // Initialize test_client
    let test_client = TestClient::new(
        policy,
        account_keys,
        config.consensus_config.consensus_validators,
        config.fog_ledger,
        config.fog_view,
        logger.clone(),
    )
    .consensus_sigstruct(consensus_sigstruct)
    .fog_ingest_sigstruct(fog_ingest_sigstruct)
    .fog_ledger_sigstruct(fog_ledger_sigstruct)
    .fog_view_sigstruct(fog_view_sigstruct);

    // Run continuously or run as a fixed length test, according to config
    if config.continuous {
        log::info!(
            logger,
            "Test client will continuously transfer every {:?} seconds",
            config.transfer_period
        );

        if admin_server.is_none() {
            log::warn!(
                logger,
                "Admin server not configured, prometheus metrics will not be available"
            );
        }

        test_client.run_continuously(config.transfer_period);
    } else {
        log::info!(
            logger,
            "Test client will run {} test transfers and stop",
            config.num_transactions
        );

        match test_client.run_test(config.num_transactions) {
            Ok(()) => println!("All tests passed"),
            Err(TestClientError::TxTimeout) => panic!(
                "Transactions could not clear in {:?} seconds",
                config.consensus_wait
            ),
            Err(e) => panic!("Unexpected error {:?}", e),
        }
    }
}

// Note: clippy exception is needed because to use with `Option::<&String>::map`
// the function argument cannot be `&str` or it will fail type checking.
#[allow(clippy::ptr_arg)]
fn load_css_file(filename: &String) -> Result<Signature, String> {
    let bytes = std::fs::read(filename)
        .map_err(|err| format!("Failed reading file '{}': {}", filename, err))?;
    let signature = Signature::try_from(&bytes[..])
        .map_err(|err| format!("Failed parsing CSS file '{}': {}", filename, err))?;
    Ok(signature)
}
