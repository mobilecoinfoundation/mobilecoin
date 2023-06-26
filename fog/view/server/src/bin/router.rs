// Copyright (c) 2018-2022 The MobileCoin Foundation
#![allow(missing_docs)]

//! MobileCoin Fog View Router target
use grpcio::ChannelBuilder;
use mc_attest_net::{Client, RaClient};
use mc_common::{logger::log, time::SystemTimeProvider};
use mc_fog_api::view_grpc::FogViewStoreApiClient;
use mc_fog_view_enclave::{SgxViewEnclave, ENCLAVE_FILE};
use mc_fog_view_server::{
    config::FogViewRouterConfig,
    fog_view_router_server::{FogViewRouterServer, Shard},
    sharding_strategy::{EpochShardingStrategy, ShardingStrategy},
};
use mc_util_cli::ParserWithBuildInfo;
use mc_util_grpc::ConnectionUriGrpcioChannel;
use prometheus::{Encoder, TextEncoder};
use std::{
    env,
    sync::{Arc, RwLock},
};
use warp::Filter;

#[tokio::main]
async fn main() {
    let (logger, _global_logger_guard) =
        mc_common::logger::create_app_logger(mc_common::logger::o!());
    mc_common::setup_panic_handler();
    let config = FogViewRouterConfig::parse();

    let enclave_path = env::current_exe()
        .expect("Could not get the path of our executable")
        .with_file_name(ENCLAVE_FILE);
    log::info!(
        logger,
        "enclave path {}, responder ID {}",
        enclave_path.to_str().unwrap(),
        &config.client_responder_id
    );
    let sgx_enclave = SgxViewEnclave::new(
        enclave_path,
        config.client_responder_id.clone(),
        config.omap_capacity,
        logger.clone(),
    );

    let _tracer = mc_util_telemetry::setup_default_tracer_with_tags(
        env!("CARGO_PKG_NAME"),
        &[(
            "client_responser_id",
            config.client_responder_id.to_string(),
        )],
    )
    .expect("Failed setting telemetry tracer");
    let mut shards = Vec::new();
    let grpc_env = Arc::new(
        grpcio::EnvBuilder::new()
            .name_prefix("Main-RPC".to_string())
            .build(),
    );
    for shard_uri in config.shard_uris.clone() {
        let fog_view_store_grpc_client = FogViewStoreApiClient::new(
            ChannelBuilder::default_channel_builder(grpc_env.clone())
                .keepalive_permit_without_calls(false)
                .connect_to_uri(&shard_uri, &logger),
        );

        // TODO: update this logic once we introduce other types of sharding strategies.
        let epoch_sharding_strategy = EpochShardingStrategy::try_from(shard_uri.clone())
            .unwrap_or_else(|_| panic!("Could not get sharding strategy for uri: {shard_uri:?}"));
        let block_range = epoch_sharding_strategy.get_block_range();
        let shard = Shard::new(shard_uri, Arc::new(fog_view_store_grpc_client), block_range);
        shards.push(shard);
    }
    let shards = Arc::new(RwLock::new(shards));

    let ias_client = Client::new(&config.ias_api_key).expect("Could not create IAS client");
    let mut router_server = FogViewRouterServer::new(
        config.clone(),
        sgx_enclave,
        ias_client,
        shards,
        SystemTimeProvider::default(),
        logger.clone(),
    );
    router_server.start();

    let metrics_path = warp::path!("metrics").and_then(metrics_handler);
    log::info!(logger.clone(), "Metrics API listening on :3030");
    warp::serve(metrics_path).run(([0, 0, 0, 0], 3030)).await;

    loop {
        std::thread::sleep(std::time::Duration::from_millis(1000));
    }
}

async fn metrics_handler() -> Result<impl warp::Reply, warp::Rejection> {
    let encoder = TextEncoder::new();
    let mut buffer = Vec::new();
    let metrics_families = prometheus::gather();
    encoder
        .encode(&metrics_families, &mut buffer)
        .expect("could not encode prometheus metrics");

    let response = String::from_utf8(buffer.clone()).expect("unable to format utf8");
    Ok(warp::reply::with_status(
        response,
        warp::http::StatusCode::OK,
    ))
}
