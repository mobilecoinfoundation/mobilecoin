// Copyright (c) 2018-2022 The MobileCoin Foundation

use std::{
    collections::HashMap,
    sync::{Arc, RwLock},
};

use futures::executor::block_on;
use grpcio::ChannelBuilder;
use mc_attest_net::RaClient;
use mc_common::{
    logger::{log, Logger},
    time::SystemTimeProvider,
};
use mc_fog_api::ledger_grpc;
use mc_fog_ledger_enclave::LedgerEnclaveProxy;
use mc_fog_uri::{ConnectionUri, FogLedgerUri};
use mc_ledger_db::LedgerDB;
use mc_sgx_report_cache_untrusted::ReportCacheThread;
use mc_util_grpc::{
    AnonymousAuthenticator, Authenticator, ConnectionUriGrpcioChannel, ConnectionUriGrpcioServer,
    TokenAuthenticator,
};
use mc_util_uri::AdminUri;
use mc_watcher::watcher_db::WatcherDB;

use crate::{
    config::LedgerRouterConfig, counters, router_admin_service::LedgerRouterAdminService,
    router_service::LedgerRouterService, BlockService, MerkleProofService, UntrustedTxOutService,
};

pub struct LedgerRouterServer<E, RC>
where
    E: LedgerEnclaveProxy,
    RC: RaClient + Send + Sync + 'static,
{
    router_server: grpcio::Server,
    admin_server: grpcio::Server,
    client_listen_uri: FogLedgerUri,
    admin_listen_uri: AdminUri,
    config: LedgerRouterConfig,
    enclave: E,
    ra_client: RC,
    report_cache_thread: Option<ReportCacheThread>,
    logger: Logger,
}

impl<E, RC> LedgerRouterServer<E, RC>
where
    E: LedgerEnclaveProxy,
    RC: RaClient + Send + Sync + 'static,
{
    pub fn new(
        config: LedgerRouterConfig,
        enclave: E,
        ra_client: RC,
        ledger: LedgerDB,
        watcher: WatcherDB,
        logger: Logger,
    ) -> LedgerRouterServer<E, RC> {
        let mut ledger_store_grpc_clients = HashMap::new();
        let grpc_env = Arc::new(
            grpcio::EnvBuilder::new()
                .name_prefix("Main-RPC".to_string())
                .build(),
        );
        for shard_uri in config.shard_uris.clone() {
            let ledger_store_grpc_client = ledger_grpc::KeyImageStoreApiClient::new(
                ChannelBuilder::default_channel_builder(grpc_env.clone())
                    .keepalive_permit_without_calls(false)
                    .connect_to_uri(&shard_uri, &logger),
            );
            ledger_store_grpc_clients.insert(shard_uri, Arc::new(ledger_store_grpc_client));
        }
        let ledger_store_grpc_clients = Arc::new(RwLock::new(ledger_store_grpc_clients));

        let client_authenticator: Arc<dyn Authenticator + Sync + Send> =
            if let Some(shared_secret) = config.client_auth_token_secret.as_ref() {
                Arc::new(TokenAuthenticator::new(
                    *shared_secret,
                    config.client_auth_token_max_lifetime,
                    SystemTimeProvider::default(),
                ))
            } else {
                Arc::new(AnonymousAuthenticator::default())
            };

        let env = Arc::new(
            grpcio::EnvBuilder::new()
                .name_prefix("ledger-router-server".to_string())
                .build(),
        );

        // Health check service - will be used in both router + admin interface
        let health_service = mc_util_grpc::HealthService::new(None, logger.clone()).into_service();

        // Build our router server.
        // Init ledger router service.
        let ledger_service = LedgerRouterService::new(
            enclave.clone(),
            ledger_store_grpc_clients.clone(),
            config.query_retries,
            logger.clone(),
        );

        let ledger_router_service = ledger_grpc::create_ledger_api(ledger_service.clone());
        log::debug!(logger, "Constructed Ledger Router GRPC Service");

        let unary_key_image_service = ledger_grpc::create_fog_key_image_api(ledger_service);

        // Init ledger router admin service.
        let ledger_router_admin_service = ledger_grpc::create_ledger_router_admin_api(
            LedgerRouterAdminService::new(ledger_store_grpc_clients, logger.clone()),
        );
        log::debug!(logger, "Constructed Ledger Router Admin GRPC Service");

        // Non-routed servers and services
        // Init merkle proof service
        let merkle_proof_service =
            ledger_grpc::create_fog_merkle_proof_api(MerkleProofService::new(
                config.chain_id.clone(),
                ledger.clone(),
                enclave.clone(),
                client_authenticator.clone(),
                logger.clone(),
            ));
        // Init untrusted tx out service
        let untrusted_tx_out_service =
            ledger_grpc::create_fog_untrusted_tx_out_api(UntrustedTxOutService::new(
                config.chain_id.clone(),
                ledger.clone(),
                watcher.clone(),
                client_authenticator.clone(),
                logger.clone(),
            ));
        // Init block service
        let block_service = ledger_grpc::create_fog_block_api(BlockService::new(
            config.chain_id.clone(),
            ledger,
            watcher,
            client_authenticator,
            logger.clone(),
        ));

        // Package service into grpc server
        log::info!(
            logger,
            "Starting Ledger Router server on {}",
            config.client_listen_uri.addr(),
        );

        let router_server = grpcio::ServerBuilder::new(env.clone())
            .register_service(ledger_router_service)
            .register_service(unary_key_image_service)
            .register_service(merkle_proof_service)
            .register_service(untrusted_tx_out_service)
            .register_service(block_service)
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
            client_listen_uri: config.client_listen_uri.clone(),
            admin_listen_uri: config.admin_listen_uri.clone(),
            config,
            enclave,
            ra_client,
            report_cache_thread: None,
            logger,
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

impl<E, RC> Drop for LedgerRouterServer<E, RC>
where
    E: LedgerEnclaveProxy,
    RC: RaClient + Send + Sync + 'static,
{
    fn drop(&mut self) {
        self.stop();
    }
}
