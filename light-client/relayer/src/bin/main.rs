// Copyright (c) 2018-2023 The MobileCoin Foundation

//! Main Method for the light client relayer

use mc_common::{logger, sentry};
use mc_ledger_db::LedgerDB;
use mc_light_client_relayer::{Config, Relayer, TestSender, TestVerifier};
use mc_util_cli::ParserWithBuildInfo;
use mc_util_grpc::AdminServer;
use mc_watcher::watcher_db::WatcherDB;
use std::{sync::Arc, thread, time};

fn main() {
    std::env::set_var("MC_LOG_STDERR", "1");
    let (logger, _global_logger_guard) = logger::create_app_logger(logger::o!());

    mc_common::setup_panic_handler();
    let _sentry_guard = sentry::init();

    let config = Config::parse();

    let config_json = serde_json::to_string(&config).expect("failed to serialize config to JSON");
    let get_config_json = Arc::new(move || Ok(config_json.clone()));
    let _admin_server = config.admin_listen_uri.as_ref().map(|admin_listen_uri| {
        AdminServer::start(
            None,
            admin_listen_uri,
            "Light Client Relayer".to_owned(),
            "".to_string(),
            Some(get_config_json),
            vec![],
            logger.clone(),
        )
        .expect("Failed starting light client relayer admin server")
    });

    let ledger_db = LedgerDB::open(&config.ledger_db).expect("Could not read ledger DB");

    let watcher =
        WatcherDB::open_ro(&config.watcher_db, logger.clone()).expect("Could not open watcher DB");

    Relayer::new(
        config,
        ledger_db,
        watcher,
        TestSender {
            logger: logger.clone(),
            sent: Default::default(),
        },
        TestVerifier {
            logger: logger.clone(),
        },
        logger,
    );
    // run forever, no stopping condition at the moment
    loop {
        thread::sleep(time::Duration::from_secs(1));
    }
}
