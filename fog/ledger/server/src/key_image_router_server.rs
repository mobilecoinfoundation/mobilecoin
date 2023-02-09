// Copyright (c) 2018-2022 The MobileCoin Foundation

use std::{
    collections::HashMap,
    sync::{Arc, RwLock},
};

use futures::executor::block_on;
use mc_common::logger::{log, Logger};
use mc_fog_api::ledger_grpc;
use mc_fog_ledger_enclave::LedgerEnclaveProxy;
use mc_fog_uri::{ConnectionUri, KeyImageStoreUri};
use mc_util_grpc::{ConnectionUriGrpcioServer, ReadinessIndicator};

use crate::{
    config::LedgerRouterConfig, key_image_router_service::KeyImageRouterService,
    router_admin_service::LedgerRouterAdminService,
};

pub struct KeyImageRouterServer {
    router_server: grpcio::Server,
    admin_server: grpcio::Server,
    logger: Logger,
}

impl KeyImageRouterServer {
    pub fn new<E>(
        config: LedgerRouterConfig,
        enclave: E,
        shards: Arc<RwLock<HashMap<KeyImageStoreUri, Arc<ledger_grpc::KeyImageStoreApiClient>>>>,
        logger: Logger,
    ) -> KeyImageRouterServer
    where
        E: LedgerEnclaveProxy,
    {
        let readiness_indicator = ReadinessIndicator::default();

        let env = Arc::new(
            grpcio::EnvBuilder::new()
                .name_prefix("key-image-router-server".to_string())
                .build(),
        );

        // Health check service - will be used in both cases
        let health_service =
            mc_util_grpc::HealthService::new(Some(readiness_indicator.into()), logger.clone())
                .into_service();

        // Build our router server.
        // Init ledger router service.
        let ledger_router_service = ledger_grpc::create_ledger_api(KeyImageRouterService::new(
            enclave,
            shards.clone(),
            logger.clone(),
        ));
        log::debug!(logger, "Constructed Key Image Router GRPC Service");

        // Init ledger router admin service.
        let ledger_router_admin_service = ledger_grpc::create_ledger_router_admin_api(
            LedgerRouterAdminService::new(shards, logger.clone()),
        );
        log::debug!(logger, "Constructed Key Image Router Admin GRPC Service");

        // Package service into grpc server
        log::info!(
            logger,
            "Starting Key Image Router server on {}",
            config.client_listen_uri.addr(),
        );

        let router_server_builder = grpcio::ServerBuilder::new(env.clone())
            .register_service(ledger_router_service)
            .register_service(health_service)
            .bind_using_uri(&config.client_listen_uri, logger.clone());
        let admin_server_builder = grpcio::ServerBuilder::new(env)
            .register_service(ledger_router_admin_service)
            .bind_using_uri(&config.admin_listen_uri, logger.clone());

        let router_server = router_server_builder.build().unwrap();
        let admin_server = admin_server_builder.build().unwrap();

        Self {
            router_server,
            admin_server,
            logger,
        }
    }

    /// Starts the server
    pub fn start(&mut self) {
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
        block_on(self.router_server.shutdown()).expect("Could not stop router grpc server");
        block_on(self.admin_server.shutdown()).expect("Could not stop router admin grpc server");
    }
}

impl Drop for KeyImageRouterServer {
    fn drop(&mut self) {
        self.stop();
    }
}
