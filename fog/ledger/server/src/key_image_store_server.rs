// Copyright (c) 2018-2022 The MobileCoin Foundation

use crate::{
    config::LedgerStoreConfig, counters, db_fetcher::DbFetcher,
    sharding_strategy::ShardingStrategy, DbPollSharedState, KeyImageService,
};
use futures::executor::block_on;
use mc_attest_core::ProviderId;
use mc_attest_net::RaClient;
use mc_common::{
    logger::{log, Logger},
    time::TimeProvider,
};
use mc_fog_api::ledger_grpc;
use mc_fog_block_provider::BlockProvider;
use mc_fog_ledger_enclave::LedgerEnclaveProxy;
use mc_fog_uri::{ConnectionUri, KeyImageStoreUri};
use mc_sgx_report_cache_untrusted::ReportCacheThread;
use mc_util_grpc::{
    AnonymousAuthenticator, Authenticator, ConnectionUriGrpcioServer, ReadinessIndicator,
    TokenAuthenticator,
};
use std::{
    sync::{Arc, Mutex},
    time::Duration,
};

pub struct KeyImageStoreServer<E, SS, RC>
where
    E: LedgerEnclaveProxy,
    SS: ShardingStrategy + Send + Sync + 'static,
    RC: RaClient + Send + Sync + 'static,
{
    server: grpcio::Server,
    client_listen_uri: KeyImageStoreUri,
    db_fetcher: DbFetcher<E, SS>,
    enclave: E,
    ra_client: RC,
    report_cache_thread: Option<ReportCacheThread>,
    ias_spid: ProviderId,
    logger: Logger,
}

impl<E, SS, RC> KeyImageStoreServer<E, SS, RC>
where
    E: LedgerEnclaveProxy,
    SS: ShardingStrategy + Send + Sync + 'static,
    RC: RaClient + Send + Sync + 'static,
{
    /// Creates a new key image store server instance
    pub fn new_from_config(
        config: LedgerStoreConfig,
        enclave: E,
        ra_client: RC,
        block_provider: Box<dyn BlockProvider>,
        sharding_strategy: SS,
        time_provider: impl TimeProvider + 'static,
        logger: Logger,
    ) -> KeyImageStoreServer<E, SS, RC> {
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
            client_authenticator,
            config.client_listen_uri,
            enclave,
            ra_client,
            config.ias_spid,
            block_provider,
            sharding_strategy,
            config.poll_interval,
            logger,
        )
    }

    pub fn new(
        client_authenticator: Arc<dyn Authenticator + Sync + Send>,
        client_listen_uri: KeyImageStoreUri,
        enclave: E,
        ra_client: RC,
        ias_spid: ProviderId,
        block_provider: Box<dyn BlockProvider>,
        sharding_strategy: SS,
        poll_interval: Duration,
        logger: Logger,
    ) -> KeyImageStoreServer<E, SS, RC> {
        let shared_state = Arc::new(Mutex::new(DbPollSharedState::default()));

        let use_tls = client_listen_uri.use_tls();
        let responder_id = client_listen_uri
            .responder_id()
            .expect("Could not get store responder ID");
        let uri = KeyImageStoreUri::try_from_responder_id(responder_id, use_tls)
            .expect("Could not create URI from Responder ID");

        let key_image_service = KeyImageService::new(
            uri,
            enclave.clone(),
            shared_state,
            client_authenticator,
            logger.clone(),
        );
        Self::new_from_service(
            key_image_service,
            client_listen_uri,
            enclave,
            block_provider,
            ra_client,
            ias_spid,
            sharding_strategy,
            poll_interval,
            logger,
        )
    }

    pub fn new_from_service(
        mut key_image_service: KeyImageService<E>,
        client_listen_uri: KeyImageStoreUri,
        enclave: E,
        block_provider: Box<dyn BlockProvider>,
        ra_client: RC,
        ias_spid: ProviderId,
        sharding_strategy: SS,
        poll_interval: Duration,
        logger: Logger,
    ) -> KeyImageStoreServer<E, SS, RC> {
        let readiness_indicator = ReadinessIndicator::default();

        let env = Arc::new(
            grpcio::EnvBuilder::new()
                .name_prefix("key-image-store-server".to_string())
                .build(),
        );

        // Health check service
        let health_service = mc_util_grpc::HealthService::new(
            Some(readiness_indicator.clone().into()),
            logger.clone(),
        )
        .into_service();

        // Build our store server.
        // Init ledger store service.
        let ledger_store_service =
            ledger_grpc::create_key_image_store_api(key_image_service.clone());
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
            .expect("Could not build Key Image Store Server");

        let db_fetcher = DbFetcher::new(
            block_provider,
            enclave.clone(),
            sharding_strategy,
            key_image_service.get_db_poll_shared_state(),
            readiness_indicator,
            poll_interval,
            logger.clone(),
        );

        Self {
            server,
            client_listen_uri,
            db_fetcher,
            enclave,
            ra_client,
            ias_spid,
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
                self.ias_spid,
                &counters::ENCLAVE_REPORT_TIMESTAMP,
                self.logger.clone(),
            )
            .expect("failed starting report cache thread"),
        );

        self.server.start();
        log::info!(
            self.logger,
            "API listening on {}",
            self.client_listen_uri.addr()
        );
        self.db_fetcher.start();
    }

    /// Stops the server
    pub fn stop(&mut self) {
        block_on(self.server.shutdown()).expect("Could not stop grpc server");
        self.db_fetcher.stop().expect("Could not stop DbFetcher");
    }
}

impl<E, SS, RC> Drop for KeyImageStoreServer<E, SS, RC>
where
    E: LedgerEnclaveProxy,
    SS: ShardingStrategy + Send + Sync + 'static,
    RC: RaClient + Send + Sync + 'static,
{
    fn drop(&mut self) {
        self.stop();
    }
}
