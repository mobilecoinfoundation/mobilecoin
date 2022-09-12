// Copyright (c) 2018-2022 The MobileCoin Foundation

use std::sync::Arc;

use futures::executor::block_on;
use mc_common::logger::{log, Logger};
use mc_fog_api::ledger_grpc;
use mc_fog_ledger_enclave::LedgerEnclaveProxy;
use mc_fog_uri::ConnectionUri;
use mc_util_grpc::{ConnectionUriGrpcioServer, ReadinessIndicator};

use crate::{config::LedgerRouterConfig, key_image_router_service::KeyImageRouterService};

#[allow(dead_code)] // FIXME
pub struct KeyImageRouterServer {
    server: grpcio::Server,
    logger: Logger,
}

impl KeyImageRouterServer {
    /// Creates a new ledger router server instance
    #[allow(dead_code)] // FIXME
    pub fn new<E>(
        config: LedgerRouterConfig,
        enclave: E,
        shards: Vec<ledger_grpc::KeyImageStoreApiClient>,
        logger: Logger,
    ) -> KeyImageRouterServer
    where
        E: LedgerEnclaveProxy,
    {
        let readiness_indicator = ReadinessIndicator::default();

        let env = Arc::new(
            grpcio::EnvBuilder::new()
                .name_prefix("key-image-router-and-store-server".to_string())
                .build(),
        );

        // Health check service - will be used in both cases
        let health_service =
            mc_util_grpc::HealthService::new(Some(readiness_indicator.into()), logger.clone())
                .into_service();

        match config.client_listen_uri {
            // Router server
            crate::config::KeyImageClientListenUri::ClientFacing(ledger_router_uri) => {
                // Init ledger router service.
                let ledger_router_service = ledger_grpc::create_ledger_api(
                    KeyImageRouterService::new(enclave, shards, logger.clone()),
                );
                log::debug!(logger, "Constructed Key Image Store GRPC Service");

                // Package service into grpc server
                log::info!(
                    logger,
                    "Starting Key Image Store server on {}",
                    ledger_router_uri.addr(),
                );
                let server_builder = grpcio::ServerBuilder::new(env)
                    .register_service(ledger_router_service)
                    .register_service(health_service)
                    .bind_using_uri(&ledger_router_uri, logger.clone());

                let server = server_builder.build().unwrap();

                Self { server, logger }
            }
            // Store server.
            crate::config::KeyImageClientListenUri::Store(_ledger_store_uri) => {
                todo!()
            }
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

impl Drop for KeyImageRouterServer {
    fn drop(&mut self) {
        self.stop();
    }
}
