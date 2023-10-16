// Copyright (c) 2018-2022 The MobileCoin Foundation

use std::{
    collections::HashMap,
    sync::{Arc, RwLock},
};

use futures::executor::block_on;
use grpcio::ChannelBuilder;
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
    AdminServer, AnonymousAuthenticator, Authenticator, ConnectionUriGrpcioChannel,
    ConnectionUriGrpcioServer, TokenAuthenticator,
};
use mc_util_uri::AdminUri;
use mc_watcher::watcher_db::WatcherDB;

use crate::{
    config::LedgerRouterConfig, counters, router_admin_service::LedgerRouterAdminService,
    router_service::LedgerRouterService, BlockService, MerkleProofService, UntrustedTxOutService,
};

pub struct LedgerRouterServer<E>
where
    E: LedgerEnclaveProxy,
{
    router_server: grpcio::Server,
    admin_service: LedgerRouterAdminService,
    client_listen_uri: FogLedgerUri,
    admin_listen_uri: AdminUri,
    config: LedgerRouterConfig,
    enclave: E,
    report_cache_thread: Option<ReportCacheThread>,
    logger: Logger,
    admin_server: Option<AdminServer>,
}

impl<E> LedgerRouterServer<E>
where
    E: LedgerEnclaveProxy,
{
    pub fn new(
        config: LedgerRouterConfig,
        enclave: E,
        ledger: LedgerDB,
        watcher: WatcherDB,
        logger: Logger,
    ) -> LedgerRouterServer<E> {
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
        let admin_service =
            LedgerRouterAdminService::new(ledger_store_grpc_clients, logger.clone());
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

        let router_server = grpcio::ServerBuilder::new(env)
            .register_service(ledger_router_service)
            .register_service(unary_key_image_service)
            .register_service(merkle_proof_service)
            .register_service(untrusted_tx_out_service)
            .register_service(block_service)
            .register_service(health_service)
            .build_using_uri(&config.client_listen_uri, logger.clone())
            .expect("Could not build Ledger Router Server");

        Self {
            router_server,
            admin_service,
            client_listen_uri: config.client_listen_uri.clone(),
            admin_listen_uri: config.admin_listen_uri.clone(),
            config,
            enclave,
            report_cache_thread: None,
            logger,
            admin_server: None,
        }
    }

    /// Starts the server
    pub fn start(&mut self) {
        self.report_cache_thread = Some(
            ReportCacheThread::start(
                self.enclave.clone(),
                &counters::ENCLAVE_ATTESTATION_EVIDENCE_TIMESTAMP,
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

        let config_json =
            serde_json::to_string(&self.config).expect("failed to serialize config to JSON");
        let get_config_json = Arc::new(move || Ok(config_json.clone()));
        let admin_service = ledger_grpc::create_ledger_router_admin_api(self.admin_service.clone());

        // Prevent from being dropped
        self.admin_server = AdminServer::start(
            None,
            &self.config.admin_listen_uri,
            "Fog Ledger Router".to_owned(),
            self.config.client_responder_id.to_string(),
            Some(get_config_json),
            vec![admin_service],
            self.logger.clone(),
        )
        .expect("Failed starting fog-view admin server")
        .into();

        log::info!(
            self.logger,
            "Router Admin API listening on {}",
            self.admin_listen_uri.addr()
        );
    }

    /// Stops the server
    pub fn stop(&mut self) {
        block_on(self.router_server.shutdown()).expect("Could not stop router grpc server");
    }
}

impl<E> Drop for LedgerRouterServer<E>
where
    E: LedgerEnclaveProxy,
{
    fn drop(&mut self) {
        self.stop();
    }
}
