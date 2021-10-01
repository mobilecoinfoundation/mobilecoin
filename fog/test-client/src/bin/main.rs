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

    let account_keys = config.load_accounts(&logger);

    if let Some(admin_listen_uri) = config.admin_listen_uri.as_ref() {
        log::info!(
            logger,
            "Test client will continuously transfer every {:?} seconds and host prometheus metrics",
            config.transfer_period
        );

        let policy = TestClientPolicy {
            fail_fast_on_deadline: false,
            test_rth_memos: false,
            tx_submit_deadline: config.consensus_wait,
            tx_receive_deadline: config.consensus_wait,
            double_spend_wait: config.ledger_sync_wait,
            transfer_amount: config.transfer_amount,
            ..Default::default()
        };

        let json_data = JsonData {
            config: config.clone(),
            policy: policy.clone(),
        };

        let get_config_json = Arc::new(move || {
            serde_json::to_string(&json_data).map_err(|err| {
                RpcStatus::with_message(RpcStatusCode::INTERNAL, format!("{:?}", err))
            })
        });
        let _admin_server = AdminServer::start(
            None,
            admin_listen_uri,
            "Fog Test Client".to_owned(),
            "".to_string(),
            Some(get_config_json),
            logger.clone(),
        )
        .expect("Failed starting admin server");

        TestClient::new(
            policy,
            account_keys,
            config.consensus_config.consensus_validators,
            config.fog_ledger,
            config.fog_view,
            logger,
        )
        .run_continuously(config.transfer_period);
    } else {
        log::info!(
            logger,
            "Test client will run {} test transfers and stop",
            config.num_transactions
        );

        let policy = TestClientPolicy {
            fail_fast_on_deadline: true,
            test_rth_memos: true,
            tx_submit_deadline: config.consensus_wait,
            tx_receive_deadline: config.consensus_wait,
            double_spend_wait: config.ledger_sync_wait,
            transfer_amount: config.transfer_amount,
            ..Default::default()
        };

        match TestClient::new(
            policy,
            account_keys,
            config.consensus_config.consensus_validators,
            config.fog_ledger,
            config.fog_view,
            logger,
        )
        .run_test(config.num_transactions)
        {
            Ok(()) => println!("All tests passed"),
            Err(TestClientError::TxTimeout) => panic!(
                "Transactions could not clear in {:?} seconds",
                config.consensus_wait
            ),
            Err(e) => panic!("Unexpected error {:?}", e),
        }
    }
}
