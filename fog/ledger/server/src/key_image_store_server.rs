// Copyright (c) 2018-2022 The MobileCoin Foundation

use std::sync::{Arc, Mutex};

use futures::executor::block_on;
use mc_common::{
    logger::{log, Logger},
    time::TimeProvider,
};
use mc_fog_api::ledger_grpc;
use mc_fog_ledger_enclave::LedgerEnclaveProxy;
use mc_fog_uri::{ConnectionUri, KeyImageStoreUri};
use mc_ledger_db::LedgerDB;
use mc_util_grpc::{
    AnonymousAuthenticator, Authenticator, ConnectionUriGrpcioServer, ReadinessIndicator,
    TokenAuthenticator,
};
use mc_watcher::watcher_db::WatcherDB;

use crate::{
    config::LedgerStoreConfig, server::DbPollSharedState, KeyImageClientListenUri, KeyImageService,
};

pub struct KeyImageStoreServer {
    server: grpcio::Server,
    client_listen_uri: KeyImageStoreUri,
    logger: Logger,
}

impl KeyImageStoreServer {
    /// Creates a new key image store server instance
    pub fn new_from_config<E>(
        config: LedgerStoreConfig,
        enclave: E,
        ledger: LedgerDB,
        watcher: WatcherDB,
        time_provider: impl TimeProvider + 'static,
        logger: Logger,
    ) -> KeyImageStoreServer
    where
        E: LedgerEnclaveProxy,
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

        Self::new(
            config.chain_id,
            client_authenticator,
            config.client_listen_uri,
            enclave,
            ledger,
            watcher,
            logger,
        )
    }

    pub fn new<E>(
        chain_id: String,
        client_authenticator: Arc<dyn Authenticator + Sync + Send>,
        client_listen_uri: KeyImageStoreUri,
        enclave: E,
        ledger: LedgerDB,
        watcher: WatcherDB,
        logger: Logger,
    ) -> KeyImageStoreServer
    where
        E: LedgerEnclaveProxy,
    {
        let shared_state = Arc::new(Mutex::new(DbPollSharedState::default()));

        let key_image_service = KeyImageService::new(
            KeyImageClientListenUri::Store(client_listen_uri.clone()),
            chain_id,
            ledger,
            watcher,
            enclave,
            shared_state,
            client_authenticator.clone(),
            logger.clone(),
        );
        Self::new_from_service(key_image_service, client_listen_uri, logger)
    }

    pub fn new_from_service<E>(
        key_image_service: KeyImageService<LedgerDB, E>,
        client_listen_uri: KeyImageStoreUri,
        logger: Logger,
    ) -> KeyImageStoreServer
    where
        E: LedgerEnclaveProxy,
    {
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

        // Build our store server.
        // Init ledger store service.
        let ledger_store_service = ledger_grpc::create_key_image_store_api(key_image_service);
        log::debug!(logger, "Constructed Key Image Store GRPC Service");

        // Package service into grpc server
        log::info!(
            logger,
            "Starting Key Image Store server on {}",
            client_listen_uri.addr(),
        );

        let server = grpcio::ServerBuilder::new(env)
            .register_service(ledger_store_service)
            .register_service(health_service)
            .build_using_uri(&client_listen_uri, logger.clone())
            .unwrap();

        Self {
            server,
            client_listen_uri,
            logger,
        }
    }

    /// Starts the server
    pub fn start(&mut self) {
        self.server.start();
        log::info!(
            self.logger,
            "API listening on {}",
            self.client_listen_uri.addr()
        );
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
