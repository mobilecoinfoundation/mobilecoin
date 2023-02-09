// Copyright (c) 2018-2022 The MobileCoin Foundation

use std::{
    collections::HashMap,
    env,
    str::FromStr,
    sync::{Arc, RwLock},
};

use clap::Parser;
use grpcio::ChannelBuilder;
use mc_attest_net::{Client, RaClient};
use mc_common::logger::log;
use mc_fog_api::ledger_grpc::KeyImageStoreApiClient;
use mc_fog_ledger_enclave::{LedgerSgxEnclave, ENCLAVE_FILE};
use mc_fog_ledger_server::{LedgerRouterConfig, LedgerRouterServer};
use mc_fog_uri::{KeyImageStoreScheme, KeyImageStoreUri};
use mc_ledger_db::LedgerDB;
use mc_util_grpc::ConnectionUriGrpcioChannel;
use mc_util_uri::UriScheme;
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

    let mut ledger_store_grpc_clients = HashMap::new();
    let grpc_env = Arc::new(
        grpcio::EnvBuilder::new()
            .name_prefix("Main-RPC".to_string())
            .build(),
    );
    for i in 0..50 {
        let shard_uri_string = format!(
            "{}://node{}.test.mobilecoin.com:3225",
            KeyImageStoreScheme::SCHEME_INSECURE,
            i
        );
        let shard_uri = KeyImageStoreUri::from_str(&shard_uri_string)
            .unwrap_or_else(|_| panic!("Invalid shard URI string {}!", shard_uri_string));
        let ledger_store_grpc_client = KeyImageStoreApiClient::new(
            ChannelBuilder::default_channel_builder(grpc_env.clone())
                .connect_to_uri(&shard_uri, &logger),
        );
        ledger_store_grpc_clients.insert(shard_uri, Arc::new(ledger_store_grpc_client));
    }
    let ledger_store_grpc_clients = Arc::new(RwLock::new(ledger_store_grpc_clients));

    let ledger_db = LedgerDB::open(&config.ledger_db).expect("Could not read ledger DB");
    let watcher_db =
        WatcherDB::open_ro(&config.watcher_db, logger.clone()).expect("Could not open watcher DB");

    let ias_client = Client::new(&config.ias_api_key).expect("Could not create IAS client");
    let mut router_server = LedgerRouterServer::new(
        config,
        enclave,
        ias_client,
        ledger_store_grpc_clients,
        ledger_db,
        watcher_db,
        logger,
    );
    router_server.start();

    loop {
        std::thread::sleep(std::time::Duration::from_millis(1000));
    }
}
