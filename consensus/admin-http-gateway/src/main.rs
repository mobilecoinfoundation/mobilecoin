// Copyright (c) 2018-2020 MobileCoin Inc.

//! An HTTP frontend for a Consensus Service's admin GRPC interface.

#![feature(proc_macro_hygiene, decl_macro)]

use mc_common::logger::{create_app_logger, log, o};
use mc_util_uri::ConsensusAdminUri;
use rocket::{get, routes};
use structopt::StructOpt;

#[derive(Clone, Debug, StructOpt)]
#[structopt(
    name = "mc-consensus-admin-http-gateway",
    about = "An HTTP frontend for a Consensus Service's admin GRPC interface."
)]
pub struct Config {
    /// Host to listen on.
    #[structopt(long, default_value = "127.0.0.1")]
    pub listen_host: String,

    /// Post to start webserver on.
    #[structopt(long, default_value = "9090")]
    pub listen_port: u16,

    /// Consensus service admin URI to connect to.
    #[structopt(long)]
    pub admin_uri: ConsensusAdminUri,
}

#[get("/")]
fn index() -> &'static str {
    "Hello, world!"
}

fn main() {
    mc_common::setup_panic_handler();
    let _sentry_guard = mc_common::sentry::init();

    let config = Config::from_args();

    let (logger, _global_logger_guard) = create_app_logger(o!());
    log::info!(
        logger,
        "Starting consensus admin HTTP gateway on {}:{}, connecting to {}",
        config.listen_host,
        config.listen_port,
        config.admin_uri
    );

    let rocket_config = rocket::Config::build(rocket::config::Environment::Production)
        .address(&config.listen_host)
        .port(config.listen_port)
        .unwrap();

    rocket::custom(rocket_config)
        .mount("/", routes![index])
        .launch();
}
