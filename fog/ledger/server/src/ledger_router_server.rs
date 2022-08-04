// Copyright (c) 2018-2022 The MobileCoin Foundation

use std::sync::Arc;

use futures::executor::block_on;
use mc_common::logger::{log, Logger};
use mc_fog_api::ledger_grpc;
use mc_fog_ledger_enclave::LedgerEnclaveProxy;
use mc_fog_uri::ConnectionUri;
use mc_util_grpc::{ReadinessIndicator, ConnectionUriGrpcioServer};

use crate::{ledger_router_service::LedgerRouterService, config::LedgerRouterConfig};

#[allow(dead_code)] // FIXME
pub struct LedgerRouterServer {
    server: grpcio::Server,
    logger: Logger,
}

impl LedgerRouterServer {
    /// Creates a new ledger router server instance
    #[allow(dead_code)] // FIXME
    pub fn new<E> (
        config: LedgerRouterConfig,
        enclave: E,
        shards: Vec<ledger_grpc::LedgerStoreApiClient>,
        logger: Logger,
    ) -> LedgerRouterServer
    where
        E: LedgerEnclaveProxy,
    {
        let readiness_indicator = ReadinessIndicator::default();

        let env = Arc::new(
            grpcio::EnvBuilder::new()
                .name_prefix("Fog-ledger-router-server".to_string())
                .build(),
        );

        // Init ledger router service.
        let fog_view_router_service = ledger_grpc::create_ledger_api(
            LedgerRouterService::new(enclave, shards, logger.clone()),
        );
        log::debug!(logger, "Constructed Fog Ledger Router GRPC Service");

        // Health check service
        let health_service =
            mc_util_grpc::HealthService::new(
                Some(readiness_indicator.into()), logger.clone()
            ).into_service();

        match config.client_listen_uri {
            crate::config::ClientListenUri::ClientFacing(_ledger_router_uri) => todo!(),
            crate::config::ClientListenUri::Store(ledger_store_uri) => {
                // Package service into grpc server
                log::info!(
                    logger,
                    "Starting Fog View Router server on {}",
                    ledger_store_uri.addr(),
                );
                let server_builder = grpcio::ServerBuilder::new(env)
                    .register_service(fog_view_router_service)
                    .register_service(health_service)
                    .bind_using_uri(&ledger_store_uri, logger.clone());
        
                let server = server_builder.build().unwrap();
        
                Self { server, logger }
            },
        }
    }

    #[allow(dead_code)] // FIXME
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

impl Drop for LedgerRouterServer {
    fn drop(&mut self) {
        self.stop();
    }
}
