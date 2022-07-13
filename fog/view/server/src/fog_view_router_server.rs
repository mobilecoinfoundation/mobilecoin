// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Server object containing a view node
//! Constructible from config (for testability) and with a mechanism for
//! stopping it

use crate::{config::FogViewRouterConfig, fog_view_router_service::FogViewRouterService};
use futures::executor::block_on;
use mc_common::logger::{log, Logger};
use mc_fog_api::view_grpc;
use mc_fog_uri::{ConnectionUri, FogViewStoreUri};
use mc_fog_view_enclave::ViewEnclaveProxy;
use mc_util_grpc::{ConnectionUriGrpcioServer, ReadinessIndicator};
use std::sync::Arc;

pub struct FogViewRouterServer<E>
where
    E: ViewEnclaveProxy,
{
    server: grpcio::Server,
    _enclave: E,
    logger: Logger,
}

impl<E> FogViewRouterServer<E>
where
    E: ViewEnclaveProxy,
{
    /// Creates a new view router server instance
    pub fn new(
        config: FogViewRouterConfig,
        enclave: E,
        shards: Vec<FogViewStoreUri>,
        logger: Logger,
    ) -> FogViewRouterServer<E> {
        let readiness_indicator = ReadinessIndicator::default();

        let env = Arc::new(
            grpcio::EnvBuilder::new()
                .name_prefix("Main-RPC".to_string())
                .build(),
        );

        let fog_view_router_service = view_grpc::create_fog_view_router_api(
            FogViewRouterService::new(enclave.clone(), shards, logger.clone()),
        );
        log::debug!(logger, "Constructed Fog View Router GRPC Service");

        // Health check service
        let health_service =
            mc_util_grpc::HealthService::new(Some(readiness_indicator.into()), logger.clone())
                .into_service();

        // Package service into grpc server
        log::info!(
            logger,
            "Starting Fog View Router server on {}",
            config.client_listen_uri.addr(),
        );
        let server_builder = grpcio::ServerBuilder::new(env)
            .register_service(fog_view_router_service)
            .register_service(health_service)
            .bind_using_uri(&config.client_listen_uri, logger.clone());

        let server = server_builder.build().unwrap();

        Self {
            server,
            _enclave: enclave,
            logger,
        }
    }

    /// Starts the server
    pub fn start(&mut self) {
        self.server.start();
        for (host, port) in self.server.bind_addrs() {
            log::info!(self.logger, "API listening on {}:{}", host, port);
        }
    }

    /// Stops the server
    pub fn stop(&mut self) {
        block_on(self.server.shutdown()).expect("Could not stop grpc server");
    }
}

impl<E> Drop for FogViewRouterServer<E>
where
    E: ViewEnclaveProxy,
{
    fn drop(&mut self) {
        self.stop();
    }
}
