// Copyright (c) 2018-2022 The MobileCoin Foundation

use clap::Parser;
use grpcio::{RpcStatus, RpcStatusCode};
use mc_attest_net::{Client, RaClient};
use mc_common::{logger::log, time::SystemTimeProvider};
use mc_fog_block_provider::{BlockProvider, LocalBlockProvider, MobilecoindBlockProvider};
use mc_fog_ledger_enclave::{LedgerSgxEnclave, ENCLAVE_FILE};
use mc_fog_ledger_server::{KeyImageStoreServer, LedgerStoreConfig, ShardingStrategy};
use mc_ledger_db::LedgerDB;
use mc_util_grpc::AdminServer;
use mc_watcher::watcher_db::WatcherDB;

use std::{env, sync::Arc};

fn main() {
    let (logger, _global_logger_guard) =
        mc_common::logger::create_app_logger(mc_common::logger::o!());
    mc_common::setup_panic_handler();
    let config = LedgerStoreConfig::parse();

    let enclave_path = env::current_exe()
        .expect("Could not get the path of our executable")
        .with_file_name(ENCLAVE_FILE);
    log::info!(
        logger,
        "enclave path {}, responder ID {}",
        enclave_path
            .to_str()
            .expect("enclave path is not valid UTF-8"),
        &config.client_responder_id
    );
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

    let mut store_server = match config.sharding_strategy.clone() {
        ShardingStrategy::Epoch(sharding_strategy) => KeyImageStoreServer::new_from_config(
            config.clone(),
            enclave,
            ias_client,
            block_provider,
            sharding_strategy,
            SystemTimeProvider::default(),
            logger.clone(),
        ),
    };
    store_server.start();

    //Initialize the admin api
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
            vec![],
            logger.clone(),
        )
        .expect("Failed starting admin server")
    });

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
