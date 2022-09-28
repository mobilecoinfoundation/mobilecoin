// Copyright (c) 2018-2022 The MobileCoin Foundation

use clap::Parser;
use grpcio::{RpcStatus, RpcStatusCode};
use mc_common::{logger::log, time::SystemTimeProvider};
use mc_fog_ledger_enclave::{LedgerSgxEnclave, ENCLAVE_FILE};
use mc_fog_ledger_server::{LedgerStoreConfig, KeyImageStoreServer};
use mc_ledger_db::LedgerDB;
use mc_util_grpc::AdminServer;
use mc_watcher::watcher_db::WatcherDB;

use std::{env, sync::Arc};

fn main() {
    mc_common::setup_panic_handler();
    let config = LedgerStoreConfig::parse();
    let (logger, _global_logger_guard) =
        mc_common::logger::create_app_logger(mc_common::logger::o!());

    let enclave_path = env::current_exe()
        .expect("Could not get the path of our executable")
        .with_file_name(ENCLAVE_FILE);
    log::info!(
        logger,
        "enclave path {}, responder ID {}",
        enclave_path.to_str().unwrap(),
        &config.client_responder_id
    );
    let enclave = LedgerSgxEnclave::new(
        enclave_path,
        &config.client_responder_id,
        config.omap_capacity,
        logger.clone(),
    );

    //Get our ledger connection started. 
    let db = LedgerDB::open(&config.ledger_db).expect("Could not read ledger DB");
    let watcher =
        WatcherDB::open_ro(&config.watcher_db, logger.clone()).expect("Could not open watcher DB");

    let mut router_server =
        KeyImageStoreServer::new(config.clone(), 
            enclave, 
            db, 
            watcher, 
            SystemTimeProvider::default(), 
            logger.clone(),
        );
    router_server.start();

    //Initialize the admin api
    let config2 = config.clone();
    let get_config_json = Arc::new(move || {
        serde_json::to_string(&config2)
            .map_err(|err| RpcStatus::with_message(RpcStatusCode::INTERNAL, format!("{:?}", err)))
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
