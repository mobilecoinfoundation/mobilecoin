// Copyright 2018-2021 MobileCoin, Inc.

//! Main Method for the Fog Report Server

use grpcio::{RpcStatus, RpcStatusCode};
use mc_common::{logger, sentry};
use mc_fog_report_server::{Config, Materials, Server};
use mc_fog_sql_recovery_db::SqlRecoveryDb;
use mc_util_grpc::AdminServer;
use std::{convert::TryFrom, env, sync::Arc};
use structopt::StructOpt;

fn main() {
    mc_common::setup_panic_handler();
    let _sentry_guard = sentry::init();

    let (logger, _global_logger_guard) = logger::create_app_logger(logger::o!());

    let config = Config::from_args();

    let materials = Materials::try_from(&config).expect("Could not read cryptographic materials");

    let db = SqlRecoveryDb::new_from_url(
        &env::var("DATABASE_URL").expect("DATABASE_URL environment variable missing"),
        logger.clone(),
    )
    .expect("Failed connecting to database");

    let mut server = Server::new(db, &config.client_listen_uri, materials, logger.clone());
    server.start();

    let config2 = config.clone();
    let get_config_json = Arc::new(move || {
        serde_json::to_string(&config2)
            .map_err(|err| RpcStatus::with_message(RpcStatusCode::INTERNAL, format!("{:?}", err)))
    });
    let _admin_server = config.admin_listen_uri.as_ref().map(|admin_listen_uri| {
        AdminServer::start(
            None,
            admin_listen_uri,
            "Fog Report".to_owned(),
            config.client_listen_uri.to_string(),
            Some(get_config_json),
            logger,
        )
        .expect("Failed starting admin server")
    });

    loop {
        std::thread::sleep(std::time::Duration::from_millis(1000));
    }
}
