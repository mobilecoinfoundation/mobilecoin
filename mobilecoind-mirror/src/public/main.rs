// Copyright (c) 2018-2020 MobileCoin Inc.

//! The public side of mobilecoind-mirror.
//! This program opens two listening ports:
//! 1) A GRPC server for receiving incoming poll requests from the private side of the mirror
//! 2) An http(s) server for receiving client requests which will then be forwarded to the
//!    mobilecoind instance sitting behind the private part of the mirror.

#![feature(decl_macro)]

mod mirror_service;
mod query;

use grpcio::{EnvBuilder, ServerBuilder};
use mc_common::logger::{create_app_logger, log, o, Logger};
use mc_mobilecoind_api::GetBlockRequest;
use mc_mobilecoind_json::data_types::{JsonBlockDetailsResponse, JsonProcessedBlockResponse};
use mc_mobilecoind_mirror::{
    mobilecoind_mirror_api::{GetProcessedBlockRequest, QueryRequest},
    uri::MobilecoindMirrorUri,
};
use mc_util_grpc::{BuildInfoService, ConnectionUriGrpcioServer, HealthService};
use mc_util_uri::{ConnectionUri, Uri, UriScheme};
use mirror_service::MirrorService;
use query::QueryManager;
use rocket::{
    config::{Config as RocketConfig, Environment as RocketEnvironment},
    get, routes,
};
use rocket_contrib::json::Json;
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

/// State that is accessible by all rocket requests
struct State {
    query_manager: QueryManager,
    logger: Logger,
}

/// Retreive processed block information.
#[get("/processed-block/<block_num>")]
fn processed_block(
    state: rocket::State<State>,
    block_num: u64,
) -> Result<Json<JsonProcessedBlockResponse>, String> {
    let mut get_processed_block = GetProcessedBlockRequest::new();
    get_processed_block.set_block(block_num);

    let mut query_request = QueryRequest::new();
    query_request.set_get_processed_block(get_processed_block);

    log::debug!(
        state.logger,
        "Enqueueing GetProcessedBlockRequest({})",
        block_num
    );
    let query = state.query_manager.enqueue_query(query_request);
    let query_response = query.wait()?;

    if query_response.has_error() {
        log::error!(
            state.logger,
            "GetProcessedBlockRequest({}) failed: {}",
            block_num,
            query_response.get_error()
        );
        return Err(query_response.get_error().into());
    }
    if !query_response.has_get_processed_block() {
        log::error!(
            state.logger,
            "GetProcessedBlockRequest({}) returned incorrect response type",
            block_num
        );
        return Err("Incorrect response type received".into());
    }

    let response = query_response.get_get_processed_block();
    Ok(Json(JsonProcessedBlockResponse::from(response)))
}

/// Retreive a single block.
#[get("/block/<block_num>")]
fn block(
    state: rocket::State<State>,
    block_num: u64,
) -> Result<Json<JsonBlockDetailsResponse>, String> {
    let mut get_block = GetBlockRequest::new();
    get_block.set_block(block_num);

    let mut query_request = QueryRequest::new();
    query_request.set_get_block(get_block);

    log::debug!(state.logger, "Enqueueing GetBlockRequest({})", block_num);
    let query = state.query_manager.enqueue_query(query_request);
    let query_response = query.wait()?;

    if query_response.has_error() {
        log::error!(
            state.logger,
            "GetBlockRequest({}) failed: {}",
            block_num,
            query_response.get_error()
        );
        return Err(query_response.get_error().into());
    }
    if !query_response.has_get_block() {
        log::error!(
            state.logger,
            "GetBlockRequest({}) returned incorrect response type",
            block_num
        );
        return Err("Incorrect response type received".into());
    }

    log::info!(
        state.logger,
        "GetBlockRequest({}) completed successfully",
        block_num
    );

    let response = query_response.get_get_block();
    Ok(Json(JsonBlockDetailsResponse::from(response)))
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

    // Common state.
    let query_manager = QueryManager::default();

    // Start the mirror-facing GRPC server.
    log::info!(logger, "Starting mirror GRPC server");

    let build_info_service = BuildInfoService::new(logger.clone()).into_service();
    let health_service = HealthService::new(None, logger.clone()).into_service();
    let mirror_service = MirrorService::new(query_manager.clone(), logger.clone()).into_service();

    let env = Arc::new(
        EnvBuilder::new()
            .name_prefix("Mirror-RPC".to_string())
            .build(),
    );

    let server_builder = ServerBuilder::new(env)
        .register_service(build_info_service)
        .register_service(health_service)
        .register_service(mirror_service)
        .bind_using_uri(&config.mirror_listen_uri);

    let mut server = server_builder.build().unwrap();
    server.start();

    // Start the client-facing webserver.
    if config.client_listen_uri.use_tls() {
        panic!("Client-listening using TLS is currently not supported due to `ring` crate version compatibility issues.");
    }

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
    rocket::custom(rocket_config)
        .mount("/", routes![processed_block, block])
        .manage(State {
            query_manager,
            logger,
        })
        .launch();
}
