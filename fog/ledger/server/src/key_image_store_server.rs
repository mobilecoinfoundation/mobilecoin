// Copyright (c) 2018-2022 The MobileCoin Foundation

use std::sync::{Arc, Mutex};

use futures::executor::block_on;
use mc_common::{logger::{Logger, log}, time::TimeProvider};
use mc_fog_api::ledger_grpc;
use mc_fog_ledger_enclave::LedgerEnclaveProxy;
use mc_fog_uri::ConnectionUri;
use mc_ledger_db::LedgerDB;
use mc_util_grpc::{ReadinessIndicator, Authenticator, TokenAuthenticator, AnonymousAuthenticator, ConnectionUriGrpcioServer};
use mc_watcher::watcher_db::WatcherDB;

use crate::{KeyImageService, server::DbPollSharedState, config::LedgerStoreConfig};

#[allow(dead_code)] // FIXME
pub struct KeyImageStoreServer {
    server: grpcio::Server,
    logger: Logger,
}

impl KeyImageStoreServer {
    /// Creates a new ledger router server instance
    #[allow(dead_code)] // FIXME
    pub fn new<E>(
        config: LedgerStoreConfig,
        enclave: E,
        ledger: LedgerDB,
        watcher: WatcherDB,
        time_provider: impl TimeProvider + 'static,
        logger: Logger,
    ) -> KeyImageStoreServer
        where E: LedgerEnclaveProxy
    {
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

        let shared_state = Arc::new(Mutex::new(DbPollSharedState::default()));

        let key_image_service = KeyImageService::new(
            ledger.clone(),
            watcher.clone(),
            enclave,
            shared_state,
            client_authenticator.clone(),
            logger.clone(),
        );

        let readiness_indicator = ReadinessIndicator::default();

        let env = Arc::new(
            grpcio::EnvBuilder::new()
                .name_prefix("key-image-store-server".to_string())
                .build(),
        );

        // Health check service
        let health_service =
            mc_util_grpc::HealthService::new(Some(readiness_indicator.into()), logger.clone())
                .into_service();
        
        // Build our router server.
        // Init ledger router service.
        let ledger_router_service = ledger_grpc::create_key_image_store_api(
            key_image_service,
        );
        log::debug!(logger, "Constructed Key Image Router GRPC Service");

        // Package service into grpc server
        log::info!(
            logger,
            "Starting Key Image Router server on {}",
            config.client_listen_uri.addr(),
        );
        
        let server_builder = grpcio::ServerBuilder::new(env)
            .register_service(ledger_router_service)
            .register_service(health_service)
            .bind_using_uri(&config.client_listen_uri, logger.clone());
        let server = server_builder.build().unwrap();

        Self { server, logger }
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

impl Drop for KeyImageStoreServer {
    fn drop(&mut self) {
        self.stop();
    }
}
