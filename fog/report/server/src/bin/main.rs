// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Main Method for the Fog Report Server

use mc_common::{logger, sentry};
use mc_fog_report_server::{Config, Materials, Server};
use mc_fog_sql_recovery_db::SqlRecoveryDb;
use mc_util_cli::ParserWithBuildInfo;
use mc_util_grpc::AdminServer;
use std::{convert::TryFrom, env, sync::Arc};

fn main() {
    mc_common::setup_panic_handler();
    let _sentry_guard = sentry::init();

    let (logger, _global_logger_guard) = logger::create_app_logger(logger::o!());

    let config = Config::parse();

    let materials = Materials::try_from(&config).expect("Could not read cryptographic materials");

    let database_url = env::var("DATABASE_URL").expect("DATABASE_URL environment variable missing");
    let db = SqlRecoveryDb::new_from_url(
        &database_url,
        config.postgres_config.clone(),
        logger.clone(),
    )
    .unwrap_or_else(|err| {
        panic!(
            "fog-report cannot connect to database '{}': {:?}",
            database_url, err
        )
    });

    let mut server = Server::new(db, &config.client_listen_uri, materials, logger.clone());
    server.start();

    let config_json = serde_json::to_string(&config).expect("failed to serialize config to JSON");
    let get_config_json = Arc::new(move || Ok(config_json.clone()));
    let _admin_server = config.admin_listen_uri.as_ref().map(|admin_listen_uri| {
        AdminServer::start(
            None,
            admin_listen_uri,
            "Fog Report".to_owned(),
            config.client_listen_uri.to_string(),
            Some(get_config_json),
            logger,
        )
        .expect("Failed starting fog-report admin server")
    });

    loop {
        std::thread::sleep(std::time::Duration::from_millis(1000));
    }
}
