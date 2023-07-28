// Copyright (c) 2018-2022 The MobileCoin Foundation

use std::env;

use clap::Parser;
use mc_common::logger::log;
use mc_fog_ledger_enclave::{LedgerSgxEnclave, ENCLAVE_FILE};
use mc_fog_ledger_server::{LedgerRouterConfig, LedgerRouterServer};
use mc_ledger_db::LedgerDB;
use mc_watcher::watcher_db::WatcherDB;

fn main() {
    let (logger, _global_logger_guard) =
        mc_common::logger::create_app_logger(mc_common::logger::o!());
    mc_common::setup_panic_handler();
    let config = LedgerRouterConfig::parse();

    let enclave_path = env::current_exe()
        .expect("Could not get the path of our executable")
        .with_file_name(ENCLAVE_FILE);

    if let Some(enclave_path_str) = enclave_path.to_str() {
        log::info!(
            logger,
            "enclave path {}, responder ID {}",
            enclave_path_str,
            &config.client_responder_id
        );
    } else {
        log::info!(
            logger,
            "enclave path {:?}, responder ID {}",
            enclave_path,
            &config.client_responder_id
        );
        log::warn!(
            logger,
            "enclave path {:?} is not valid Unicode!",
            enclave_path
        );
    }

    let enclave = LedgerSgxEnclave::new(
        enclave_path,
        &config.client_responder_id,
        config.omap_capacity,
        logger.clone(),
    );

    let ledger_db = LedgerDB::open(&config.ledger_db).expect("Could not read ledger DB");
    let watcher_db =
        WatcherDB::open_ro(&config.watcher_db, logger.clone()).expect("Could not open watcher DB");

    let mut router_server =
        LedgerRouterServer::new(config, enclave, ledger_db, watcher_db, logger);
    router_server.start();

    loop {
        std::thread::sleep(std::time::Duration::from_millis(1000));
    }
}
