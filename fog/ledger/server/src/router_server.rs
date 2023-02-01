// Copyright (c) 2018-2022 The MobileCoin Foundation

use std::{
    collections::HashMap,
    sync::{Arc, RwLock},
};

use futures::executor::block_on;
use mc_common::logger::{log, Logger};
use mc_fog_api::ledger_grpc;
use mc_fog_ledger_enclave::LedgerEnclaveProxy;
use mc_fog_uri::{ConnectionUri, FogLedgerUri, KeyImageStoreUri};
use mc_util_grpc::{ConnectionUriGrpcioServer, ReadinessIndicator};
use mc_util_uri::AdminUri;

use crate::{
    config::LedgerRouterConfig, router_admin_service::LedgerRouterAdminService,
    router_service::LedgerRouterService,
};

pub struct LedgerRouterServer {
    router_server: grpcio::Server,
    admin_server: grpcio::Server,
    client_listen_uri: FogLedgerUri,
    admin_listen_uri: AdminUri,
    logger: Logger,
}

impl LedgerRouterServer {
    pub fn new<E>(
        config: LedgerRouterConfig,
        enclave: E,
        shards: Arc<RwLock<HashMap<KeyImageStoreUri, Arc<ledger_grpc::KeyImageStoreApiClient>>>>,
        logger: Logger,
    ) -> LedgerRouterServer
    where
        E: LedgerEnclaveProxy,
    {
        let readiness_indicator = ReadinessIndicator::default();

        let env = Arc::new(
            grpcio::EnvBuilder::new()
                .name_prefix("ledger-router-server".to_string())
                .build(),
        );

        // Health check service - will be used in both router + admin interface
        let health_service =
            mc_util_grpc::HealthService::new(Some(readiness_indicator.into()), logger.clone())
                .into_service();

        // Build our router server.
        // Init ledger router service.
        let ledger_router_service = ledger_grpc::create_ledger_api(LedgerRouterService::new(
            enclave,
            shards.clone(),
            config.query_retries,
            logger.clone(),
        ));
        log::debug!(logger, "Constructed Ledger Router GRPC Service");

        // Init ledger router admin service.
        let ledger_router_admin_service = ledger_grpc::create_ledger_router_admin_api(
            LedgerRouterAdminService::new(shards, logger.clone()),
        );
        log::debug!(logger, "Constructed Ledger Router Admin GRPC Service");

        // Package service into grpc server
        log::info!(
            logger,
            "Starting Ledger Router server on {}",
            config.client_listen_uri.addr(),
        );

        let router_server = grpcio::ServerBuilder::new(env.clone())
            .register_service(ledger_router_service)
            .register_service(health_service)
            .build_using_uri(&config.client_listen_uri, logger.clone())
            .expect("Could not build Ledger Router Server");
        let admin_server = grpcio::ServerBuilder::new(env)
            .register_service(ledger_router_admin_service)
            .build_using_uri(&config.admin_listen_uri, logger.clone())
            .expect("Could not build Ledger Router Admin Server");

        Self {
            router_server,
            admin_server,
            client_listen_uri: config.client_listen_uri,
            admin_listen_uri: config.admin_listen_uri,
            logger,
        }
    }

    /// Starts the server
    pub fn start(&mut self) {
        self.router_server.start();
        log::info!(
            self.logger,
            "Router API listening on {}",
            self.client_listen_uri.addr()
        );

        self.admin_server.start();
        log::info!(
            self.logger,
            "Router Admin API listening on {}",
            self.admin_listen_uri.addr()
        );
    }

    /// Stops the server
    pub fn stop(&mut self) {
        block_on(self.router_server.shutdown()).expect("Could not stop router grpc server");
        block_on(self.admin_server.shutdown()).expect("Could not stop router admin grpc server");
    }
}

impl Drop for LedgerRouterServer {
    fn drop(&mut self) {
        self.stop();
    }
}
