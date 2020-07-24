// Copyright (c) 2018-2020 MobileCoin Inc.

//! The public side of mobilecoind-mirror.
//! This program opens two listening ports:
//! 1) A GRPC server for receiving incoming poll requests from the private side of the mirror
//! 2) An http(s) server for receiving client requests which will then be forwarded to the
//!    mobilecoind instance sitting behind the private part of the mirror.

use grpcio::{EnvBuilder, ServerBuilder};
use mc_common::logger::{create_app_logger, log, o};
use mc_mobilecoind_mirror::uri::MobilecoindMirrorUri;
use mc_util_grpc::{BuildInfoService, ConnectionUriGrpcioServer, HealthService};
use mc_util_uri::{ConnectionUri, Uri, UriScheme};
use rocket::{
    config::{Config as RocketConfig, Environment as RocketEnvironment},
    routes,
};
use std::sync::Arc;
use structopt::StructOpt;

pub type ClientUri = Uri<ClientUriScheme>;

/// Mobilecoind Mirror Uri Scheme
#[derive(Debug, Hash, Ord, PartialOrd, Eq, PartialEq, Clone)]
pub struct ClientUriScheme {}
impl UriScheme for ClientUriScheme {
    /// The part before the '://' of a URL.
    const SCHEME_SECURE: &'static str = "https";
    const SCHEME_INSECURE: &'static str = "http";

    /// Default port numbers
    const DEFAULT_SECURE_PORT: u16 = 8443;
    const DEFAULT_INSECURE_PORT: u16 = 8000;
}

/// Command line config
#[derive(Clone, Debug, StructOpt)]
#[structopt(
    name = "mobilecoind-mirror-public",
    about = "The public side of mobilecoind-mirror, receiving requests from clients and forwarding them to mobilecoind through the private side of the mirror"
)]
pub struct Config {
    /// Listening URI for the private-public interface connection (GRPC).
    #[structopt(long)]
    pub mirror_listen_uri: MobilecoindMirrorUri,

    /// Listening URI for client requests (HTTP(S)).
    #[structopt(long)]
    pub client_listen_uri: ClientUri,

    /// Override the number of workers used for the client http server.
    /// This controls how many concurrent requests the server can process.
    #[structopt(long)]
    pub num_workers: Option<u16>,
}

fn main() {
    mc_common::setup_panic_handler();
    let _sentry_guard = mc_common::sentry::init();

    let config = Config::from_args();

    let (logger, _global_logger_guard) = create_app_logger(o!());
    log::info!(
        logger,
        "Starting mobilecoind mirror public forwarder, listening for mirror requests on {} and client requests on {}",
        config.mirror_listen_uri.addr(),
        config.client_listen_uri.addr(),
    );

    // Start the mirror-facing GRPC server.
    log::info!(logger, "Starting mirror GRPC server");

    let build_info_service = BuildInfoService::new(logger.clone()).into_service();
    let health_service = HealthService::new(None, logger.clone()).into_service();

    let env = Arc::new(
        EnvBuilder::new()
            .name_prefix("Mirror-RPC".to_string())
            .build(),
    );

    let server_builder = ServerBuilder::new(env)
        .register_service(build_info_service)
        .register_service(health_service)
        .bind_using_uri(&config.mirror_listen_uri);

    let mut server = server_builder.build().unwrap();
    server.start();

    // Start the client-facing webserver.
    let mut rocket_config = RocketConfig::build(
        RocketEnvironment::active().expect("Failed getitng rocket environment"),
    )
    .address(config.client_listen_uri.host())
    .port(config.client_listen_uri.port());
    if config.client_listen_uri.use_tls() {
        rocket_config = rocket_config.tls(
            config
                .client_listen_uri
                .tls_chain_path()
                .expect("failed getting tls chain path"),
            config
                .client_listen_uri
                .tls_key_path()
                .expect("failed getting tls key path"),
        );
    }
    if let Some(num_workers) = config.num_workers {
        rocket_config = rocket_config.workers(num_workers);
    }
    let rocket_config = rocket_config
        .finalize()
        .expect("Failed creating client http server config");

    log::info!(logger, "Starting client web server");
    rocket::custom(rocket_config).mount("/", routes![]).launch();
}
