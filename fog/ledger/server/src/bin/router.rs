// Copyright (c) 2018-2022 The MobileCoin Foundation

use std::env;

use clap::Parser;
use mc_attest_net::{Client, RaClient};
use mc_common::logger::log;
use mc_fog_block_provider::{BlockProvider, LocalBlockProvider, MobilecoindBlockProvider};
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

    let (block_provider, ledger_db) = match (
        config.ledger_db.as_ref(),
        config.watcher_db.as_ref(),
        config.mobilecoind_uri.as_ref(),
    ) {
        (Some(ledger_db_path), Some(watcher_db_path), None) => {
            let ledger_db = LedgerDB::open(ledger_db_path).expect("Could not read ledger DB");
            let watcher = WatcherDB::open_ro(watcher_db_path, logger.clone())
                .expect("Could not open watcher DB");

            (
                LocalBlockProvider::new(ledger_db.clone(), watcher) as Box<dyn BlockProvider>,
                Some(ledger_db),
            )
        }

        (None, None, Some(mobilecoind_uri)) => (
            MobilecoindBlockProvider::new(mobilecoind_uri, &logger) as Box<dyn BlockProvider>,
            None,
        ),

        _ => panic!("invalid configuration, need either ledger_db+watcher_db or mobilecoind_uri"),
    };

    let ias_client = Client::new(&config.ias_api_key).expect("Could not create IAS client");
    let mut router_server =
        LedgerRouterServer::new(config, enclave, ias_client, block_provider, logger.clone());
    router_server.start();

    loop {
        if let Some(ledger_db) = ledger_db.as_ref() {
            // The ledger database is read by this service, but updated by another service.
            // In order to keep this service's metrics up to date, we need to update them
            // periodically.
            if let Err(e) = ledger_db.update_metrics() {
                log::error!(logger, "Error updating ledger metrics: {:?}", e);
            }
        }

        std::thread::sleep(std::time::Duration::from_millis(1000));
    }
}
