// Copyright (c) 2018-2022 The MobileCoin Foundation
#![deny(missing_docs)]

//! Fog Ingest target

use mc_common::logger::{log, o};
use mc_fog_block_provider::{BlockProvider, LocalBlockProvider, MobilecoindBlockProvider};
use mc_fog_ingest_enclave::ENCLAVE_FILE;
use mc_fog_ingest_server::{
    config::IngestConfig,
    server::{IngestServer, IngestServerConfig},
    state_file::StateFile,
};
use mc_fog_sql_recovery_db::SqlRecoveryDb;
use mc_ledger_db::LedgerDB;
use mc_util_cli::ParserWithBuildInfo;
use mc_util_grpc::AdminServer;
use mc_watcher::watcher_db::WatcherDB;
use std::{env, sync::Arc};

fn main() {
    let _sentry_guard = mc_common::sentry::init();
    let config = IngestConfig::parse();
    let (logger, _global_logger_guard) = mc_common::logger::create_app_logger(
        o!("mc.local_node_id" => config.local_node_id.to_string()),
    );
    mc_common::setup_panic_handler();

    let _tracer = mc_util_telemetry::setup_default_tracer_with_tags(
        env!("CARGO_PKG_NAME"),
        &[("local_node_id", config.local_node_id.to_string())],
    )
    .expect("Failed setting telemetry tracer");

    // Get path to our state file.
    let state_file_path = config.state_file.clone().unwrap_or_else(|| {
        let mut home_dir = dirs::home_dir().unwrap_or_else(|| panic!("Unable to get home directory, please specify state file explicitly with --state-file"));
        home_dir.push(".mc-fog-ingest-state");
        home_dir
    });

    log::info!(logger, "State file is {:?}", state_file_path);

    // Get enclave path
    let enclave_path = env::current_exe()
        .expect("Could not get the path of our executable")
        .with_file_name(ENCLAVE_FILE);
    log::info!(logger, "Enclave path is: {:?}", enclave_path);

    // Open databases.
    let database_url =
        std::env::var("DATABASE_URL").expect("DATABASE_URL environment variable missing");
    let recovery_db = SqlRecoveryDb::new_from_url(
        &database_url,
        config.postgres_config.clone(),
        logger.clone(),
    )
    .unwrap_or_else(|err| {
        panic!("fog-ingest cannot connect to database '{database_url}': {err:?}")
    });

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

    // Start ingest server.
    let server_config = IngestServerConfig {
        max_transactions: config.max_transactions,
        omap_capacity: config.user_capacity,
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
        poll_interval: config.poll_interval,
    };

    let mut server = IngestServer::new(server_config, recovery_db, block_provider, logger.clone());

    server.start().expect("Failed starting Ingest Service");

    // Start admin server.
    let config_json = serde_json::to_string(&config).expect("failed to serialize config to JSON");
    let get_config_json = Arc::new(move || Ok(config_json.clone()));
    let _admin_server = config.admin_listen_uri.as_ref().map(|admin_listen_uri| {
        AdminServer::start(
            None,
            admin_listen_uri,
            "Fog Ingest".to_owned(),
            config.local_node_id.to_string(),
            Some(get_config_json),
            vec![],
            logger.clone(),
        )
        .expect("Failed starting fog-ingest admin server")
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
