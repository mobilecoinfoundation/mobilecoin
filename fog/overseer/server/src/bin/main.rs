// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Starts a Rocket server that allows clients to access Fog Overseer APIs
//! over HTTP.

use mc_common::{
    logger::{log, o},
    sentry,
};
use mc_fog_overseer_server::{config::OverseerConfig, server, service::OverseerService};
use mc_fog_sql_recovery_db::SqlRecoveryDb;
use structopt::StructOpt;

fn main() {
    mc_common::setup_panic_handler();
    let _sentry_guard = sentry::init();
    let config = OverseerConfig::from_args();
    let (logger, _global_logger_guard) = mc_common::logger::create_app_logger(o!());

    // Open the database.
    let recovery_db = SqlRecoveryDb::new_from_url(
        &std::env::var("DATABASE_URL").expect("DATABASE_URL environment variable missing"),
        config.postgres_config.clone(),
        logger.clone(),
    )
    .expect("Failed connecting to database");

    let mut overseer_service =
        OverseerService::new(config.ingest_cluster_uris, recovery_db, logger.clone());

    overseer_service
        .start()
        .expect("OverseerService failed to start");
    log::info!(logger, "OverseerService successfully started.");

    let overseer_state = server::OverseerState { overseer_service };

    let rocket_config: rocket::Config =
        rocket::Config::build(rocket::config::Environment::Development)
            .address(config.overseer_listen_host)
            .port(config.overseer_listen_port)
            .unwrap();

    let rocket = server::initialize_rocket_server(rocket_config, overseer_state);
    rocket.launch();
}
