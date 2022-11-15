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
use mc_attest_net::RaClient;
use mc_common::{
    logger::{log, Logger},
    time::TimeProvider,
};
use mc_fog_api::view_grpc;
use mc_fog_uri::{ConnectionUri, FogViewStoreUri};
use mc_fog_view_enclave::ViewEnclaveProxy;
use mc_sgx_report_cache_untrusted::ReportCacheThread;
use mc_util_grpc::{
    AnonymousAuthenticator, Authenticator, ConnectionUriGrpcioServer, ReadinessIndicator,
    TokenAuthenticator,
};
use std::{
    collections::HashMap,
    sync::{Arc, RwLock},
};

pub struct FogViewRouterServer<E, RC>
where
    E: ViewEnclaveProxy,
    RC: RaClient + Send + Sync + 'static,
{
    router_server: grpcio::Server,
    admin_server: grpcio::Server,
    enclave: E,
    config: FogViewRouterConfig,
    logger: Logger,
    ra_client: RC,
    report_cache_thread: Option<ReportCacheThread>,
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
        shards: Arc<RwLock<HashMap<FogViewStoreUri, Arc<view_grpc::FogViewStoreApiClient>>>>,
        time_provider: impl TimeProvider + 'static,
        logger: Logger,
    ) -> FogViewRouterServer<E, RC>
    where
        E: ViewEnclaveProxy,
    {
        let readiness_indicator = ReadinessIndicator::default();

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
        let health_service =
            mc_util_grpc::HealthService::new(Some(readiness_indicator.into()), logger.clone())
                .into_service();

        let router_server_builder = match config.client_listen_uri {
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
                    .bind_using_uri(streaming_uri, logger.clone())
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
                    .bind_using_uri(unary_uri, logger.clone())
            }
        };

        let admin_server_builder = grpcio::ServerBuilder::new(env)
            .register_service(fog_view_router_admin_service)
            .bind_using_uri(&config.admin_listen_uri, logger.clone());

        let router_server = router_server_builder.build().unwrap();
        let admin_server = admin_server_builder.build().unwrap();

        Self {
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
        for (host, port) in self.router_server.bind_addrs() {
            log::info!(self.logger, "Router API listening on {}:{}", host, port);
        }
        self.admin_server.start();
        for (host, port) in self.admin_server.bind_addrs() {
            log::info!(
                self.logger,
                "Router Admin API listening on {}:{}",
                host,
                port
            );
        }
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
