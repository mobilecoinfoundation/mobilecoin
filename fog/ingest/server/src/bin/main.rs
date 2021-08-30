// Copyright (c) 2018-2021 The MobileCoin Foundation

//! Fog Ingest target

use grpcio::{RpcStatus, RpcStatusCode};
use mc_attest_net::{Client, RaClient};
use mc_common::logger::{log, o};
use mc_fog_ingest_enclave::ENCLAVE_FILE;
use mc_fog_ingest_server::{
    config::IngestConfig,
    server::{IngestServer, IngestServerConfig},
    state_file::StateFile,
};
use mc_fog_sql_recovery_db::SqlRecoveryDb;
use mc_ledger_db::LedgerDB;
use mc_util_grpc::AdminServer;
use mc_watcher::watcher_db::WatcherDB;
use std::{env, sync::Arc};
use structopt::StructOpt;

fn main() {
    mc_common::setup_panic_handler();
    let _sentry_guard = mc_common::sentry::init();
    let config = IngestConfig::from_args();
    let (logger, _global_logger_guard) = mc_common::logger::create_app_logger(
        o!("mc.local_node_id" => config.local_node_id.to_string()),
    );

    // Get path to our state file.
    let state_file_path = config.state_file.clone().unwrap_or_else(|| {
        let mut home_dir = dirs::home_dir().unwrap_or_else(|| panic!("Unable to get home directory, please specify state file explicitly with --state-file"));
        home_dir.push(".mc-fog-ingest-state");
        home_dir
    });

    log::info!(logger, "State file is {:?}", state_file_path);

    // Create IAS client.
    let ias_client = Client::new(&config.ias_api_key).expect("Could not create IAS client");

    // Get enclave path
    let enclave_path = env::current_exe()
        .expect("Could not get the path of our executable")
        .with_file_name(ENCLAVE_FILE);
    log::info!(logger, "Enclave path is: {:?}", enclave_path);

    // Open databases.
    let recovery_db = SqlRecoveryDb::new_from_url(
        &std::env::var("DATABASE_URL").expect("DATABASE_URL environment variable missing"),
        logger.clone(),
    )
    .expect("Failed connecting to database");

    let ledger_db = LedgerDB::open(&config.ledger_db).expect("Could not read ledger DB");

    let watcher =
        WatcherDB::open_ro(&config.watcher_db, logger.clone()).expect("Could not open watcher DB");

    // Start ingest server.
    let server_config = IngestServerConfig {
        max_transactions: config.max_transactions,
        omap_capacity: config.user_capacity,
        ias_spid: config.ias_spid,
        local_node_id: config.local_node_id.clone(),
        client_listen_uri: config.client_listen_uri.clone(),
        peer_listen_uri: config.peer_listen_uri.clone(),
        peers: config.peers.iter().cloned().collect(),
        pubkey_expiry_window: config.pubkey_expiry_window,
        peer_checkup_period: Some(config.peer_checkup_period),
        watcher_timeout: config.watcher_timeout,
        fog_report_id: config.fog_report_id.clone(),
        state_file: Some(StateFile::new(state_file_path)),
        enclave_path,
    };

    let mut server = IngestServer::new(
        server_config,
        ias_client,
        recovery_db,
        watcher,
        ledger_db,
        logger.clone(),
    );

    server.start().expect("Failed starting Ingest Service");

    // Start admin server.
    let config2 = config.clone();
    let get_config_json = Arc::new(move || {
        serde_json::to_string(&config2)
            .map_err(|err| RpcStatus::with_message(RpcStatusCode::INTERNAL, format!("{:?}", err)))
    });
    let _admin_server = config.admin_listen_uri.as_ref().map(|admin_listen_uri| {
        AdminServer::start(
            None,
            admin_listen_uri,
            "Fog Ingest".to_owned(),
            config.local_node_id.to_string(),
            Some(get_config_json),
            logger,
        )
        .expect("Failed starting admin server")
    });

    loop {
        std::thread::sleep(std::time::Duration::from_millis(1000));
    }
}
