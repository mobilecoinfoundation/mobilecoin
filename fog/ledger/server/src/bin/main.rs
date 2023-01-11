// Copyright (c) 2018-2022 The MobileCoin Foundation
#![deny(missing_docs)]

//! Ledger Server target

use grpcio::{RpcStatus, RpcStatusCode};
use mc_attest_net::{Client, RaClient};
use mc_common::{
    logger::{create_app_logger, log, o},
    time::SystemTimeProvider,
};
use mc_fog_ledger_enclave::{LedgerSgxEnclave, ENCLAVE_FILE};
use mc_fog_ledger_server::{LedgerServer, LedgerServerConfig};
use mc_ledger_db::LedgerDB;
use mc_util_cli::ParserWithBuildInfo;
use mc_util_grpc::AdminServer;
use mc_watcher::watcher_db::WatcherDB;
use std::{env, sync::Arc};

fn main() {
    let _sentry_guard = mc_common::sentry::init();
    let (logger, _global_logger_guard) = create_app_logger(o!());
    mc_common::setup_panic_handler();

    let config = LedgerServerConfig::parse();

    let _tracer = mc_util_telemetry::setup_default_tracer_with_tags(
        env!("CARGO_PKG_NAME"),
        &[(
            "client_responser_id",
            config.client_responder_id.to_string(),
        )],
    )
    .expect("Failed setting telemetry tracer");

    let enclave_path = env::current_exe()
        .expect("Could not get the path of our executable")
        .with_file_name(ENCLAVE_FILE);
    log::info!(
        logger,
        "enclave path {}, responder ID {}",
        enclave_path.to_str().expect("Could not get enclave path"),
        &config.client_responder_id
    );
    let enclave = LedgerSgxEnclave::new(
        enclave_path,
        &config.client_responder_id,
        config.omap_capacity,
        logger.clone(),
    );

    let db = LedgerDB::open(&config.ledger_db).expect("Could not read ledger DB");
    let watcher =
        WatcherDB::open_ro(&config.watcher_db, logger.clone()).expect("Could not open watcher DB");
    let ias_client = Client::new(&config.ias_api_key).expect("Could not create IAS client");
    let mut server = LedgerServer::new(
        config.clone(),
        enclave,
        db,
        watcher,
        ias_client,
        SystemTimeProvider::default(),
        logger.clone(),
    );

    server.start().expect("Server failed to start");

    let config2 = config.clone();
    let get_config_json = Arc::new(move || {
        serde_json::to_string(&config2)
            .map_err(|err| RpcStatus::with_message(RpcStatusCode::INTERNAL, format!("{err:?}")))
    });
    let _admin_server = config.admin_listen_uri.as_ref().map(|admin_listen_uri| {
        AdminServer::start(
            None,
            admin_listen_uri,
            "Fog Ledger".to_owned(),
            config.client_responder_id.to_string(),
            Some(get_config_json),
            logger,
        )
        .expect("Failed starting admin server")
    });

    loop {
        std::thread::sleep(std::time::Duration::from_millis(1000));
    }
}
