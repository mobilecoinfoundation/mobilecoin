// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Server object containing a view node
//! Constructible from config (for testability) and with a mechanism for
//! stopping it

use crate::{
    config::{FogViewRouterConfig, RouterClientListenUri},
    counters,
    fog_view_router_service::FogViewRouterService,
    router_admin_service::FogViewRouterAdminService,
};
use futures::executor::block_on;
use hyper::Response;
use mc_attest_net::RaClient;
use mc_common::{
    logger::{log, Logger},
    time::TimeProvider,
};
use mc_fog_api::view_grpc;
use mc_fog_types::common::BlockRange;
use mc_fog_uri::{ConnectionUri, FogViewStoreUri};
use mc_fog_view_enclave::ViewEnclaveProxy;
use mc_sgx_report_cache_untrusted::ReportCacheThread;
use mc_util_grpc::{
    AnonymousAuthenticator, Authenticator, ConnectionUriGrpcioServer, TokenAuthenticator,
};
use prometheus::{opts, register_counter, Counter, Encoder, TextEncoder};
use std::{
    net::{Ipv4Addr, SocketAddr},
    sync::{Arc, RwLock},
};
use warp::Filter;

pub struct FogViewRouterServer<E, RC>
where
    E: ViewEnclaveProxy,
    RC: RaClient + Send + Sync + 'static,
{
    metrics_path: warp::filters::BoxedFilter<(impl warp::Reply)>,
    router_server: grpcio::Server,
    admin_server: grpcio::Server,
    enclave: E,
    config: FogViewRouterConfig,
    logger: Logger,
    ra_client: RC,
    report_cache_thread: Option<ReportCacheThread>,
}

/// A shard that fulfills a portion of the router's query requests.
#[derive(Clone)]
pub struct Shard {
    /// The uri that this shard listens on.
    pub uri: FogViewStoreUri,

    /// The gRPC client that is used to communicate with the shard.
    pub grpc_client: Arc<view_grpc::FogViewStoreApiClient>,

    /// The `BlockRange` that this shard is responsible for providing.
    pub block_range: BlockRange,
}

impl Shard {
    pub fn new(
        uri: FogViewStoreUri,
        grpc_client: Arc<view_grpc::FogViewStoreApiClient>,
        block_range: BlockRange,
    ) -> Self {
        Self {
            uri,
            grpc_client,
            block_range,
        }
    }
}

impl<E, RC> FogViewRouterServer<E, RC>
where
    E: ViewEnclaveProxy,
    RC: RaClient + Send + Sync + 'static,
{
    /// Creates a new view router server instance
    pub fn new(
        config: FogViewRouterConfig,
        enclave: E,
        ra_client: RC,
        shards: Arc<RwLock<Vec<Shard>>>,
        time_provider: impl TimeProvider + 'static,
        logger: Logger,
    ) -> FogViewRouterServer<E, RC>
    where
        E: ViewEnclaveProxy,
    {
        let env = Arc::new(
            grpcio::EnvBuilder::new()
                .name_prefix("Fog-view-router-server".to_string())
                .build(),
        );

        let client_authenticator: Arc<dyn Authenticator + Sync + Send> =
            if let Some(shared_secret) = config.client_auth_token_secret.as_ref() {
                Arc::new(TokenAuthenticator::new(
                    *shared_secret,
                    config.client_auth_token_max_lifetime,
                    time_provider,
                ))
            } else {
                Arc::new(AnonymousAuthenticator::default())
            };

        let fog_view_router_admin_service = view_grpc::create_fog_view_router_admin_api(
            FogViewRouterAdminService::new(shards.clone(), logger.clone()),
        );
        log::debug!(logger, "Constructed Fog View Router Admin GRPC Service");

        // Health check service
        let health_service = mc_util_grpc::HealthService::new(None, logger.clone()).into_service();

        let router_server = match config.client_listen_uri {
            RouterClientListenUri::Streaming(ref streaming_uri) => {
                let fog_view_router_service =
                    view_grpc::create_fog_view_router_api(FogViewRouterService::new(
                        enclave.clone(),
                        shards,
                        config.chain_id.clone(),
                        client_authenticator,
                        logger.clone(),
                    ));
                log::debug!(logger, "Constructed Fog View Router streaming GRPC Service");
                log::info!(
                    logger,
                    "Starting Fog View Router streaming server on {}",
                    streaming_uri.addr(),
                );

                grpcio::ServerBuilder::new(env.clone())
                    .register_service(fog_view_router_service)
                    .register_service(health_service)
                    .build_using_uri(streaming_uri, logger.clone())
                    .expect("Unable to build streaming Fog View Router server")
            }
            RouterClientListenUri::Unary(ref unary_uri) => {
                let fog_view_router_service =
                    view_grpc::create_fog_view_api(FogViewRouterService::new(
                        enclave.clone(),
                        shards,
                        config.chain_id.clone(),
                        client_authenticator,
                        logger.clone(),
                    ));
                log::debug!(logger, "Constructed Fog View Router unary GRPC Service");
                log::info!(
                    logger,
                    "Starting Fog View Router unary server on {}",
                    unary_uri.addr(),
                );
                grpcio::ServerBuilder::new(env.clone())
                    .register_service(fog_view_router_service)
                    .register_service(health_service)
                    .build_using_uri(unary_uri, logger.clone())
                    .expect("Unable to build unary Fog View Router server")
            }
        };

        let admin_server = grpcio::ServerBuilder::new(env)
            .register_service(fog_view_router_admin_service)
            .build_using_uri(&config.admin_listen_uri, logger.clone())
            .expect("Unable to build Fog View Router admin server");

        let metrics_path = warp::path!("metrics").map(|| {
            let metric_families = prometheus::gather();
            let mut buffer = vec![];
            let encoder = TextEncoder::new();
            encoder.encode(&metric_families, &mut buffer).unwrap();

            Response::builder()
                .header("Content-Type", encoder.format_type())
                .body(buffer)
                .unwrap()
        });

        Self {
            metrics_path,
            router_server,
            admin_server,
            enclave,
            config,
            logger,
            ra_client,
            report_cache_thread: None,
        }
    }

    /// Starts the server
    pub fn start(&mut self) {
        // TODO make addr & port configurable
        let addr = Ipv4Addr::new(0, 0, 0, 0);
        let server = warp::serve(self.metrics_route)
            .run(SocketAddr::new(addr, 3030))
            .expect("failed starting metrics server");
        log::info!(self.logger, "Metrics API listening on :3030",);

        self.report_cache_thread = Some(
            ReportCacheThread::start(
                self.enclave.clone(),
                self.ra_client.clone(),
                self.config.ias_spid,
                &counters::ENCLAVE_REPORT_TIMESTAMP,
                self.logger.clone(),
            )
            .expect("failed starting report cache thread"),
        );
        self.router_server.start();
        match &self.config.client_listen_uri {
            RouterClientListenUri::Streaming(uri) => {
                log::info!(
                    self.logger,
                    "Router streaming GRPC API listening on {}",
                    uri.addr(),
                );
            }
            RouterClientListenUri::Unary(uri) => {
                log::info!(
                    self.logger,
                    "Router unary GRPC API listening on {}",
                    uri.addr(),
                );
            }
        }
        self.admin_server.start();
        log::info!(
            self.logger,
            "Router Admin API listening on {}",
            self.config.admin_listen_uri.addr(),
        );
    }

    /// Stops the server
    pub fn stop(&mut self) {
        if let Some(ref mut thread) = self.report_cache_thread.take() {
            thread.stop().expect("Could not stop report cache thread");
        }
        block_on(self.router_server.shutdown()).expect("Could not stop router grpc server");
        block_on(self.admin_server.shutdown()).expect("Could not stop admin router server");
    }
}

impl<E, RC> Drop for FogViewRouterServer<E, RC>
where
    E: ViewEnclaveProxy,
    RC: RaClient + Send + Sync + 'static,
{
    fn drop(&mut self) {
        self.stop();
    }
}
