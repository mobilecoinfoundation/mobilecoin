// Copyright (c) 2018-2021 The MobileCoin Foundation

use crate::{
    config::LedgerServerConfig, counters, db_fetcher::DbFetcher, BlockService, KeyImageService,
    MerkleProofService, UntrustedTxOutService,
};
use displaydoc::Display;
use futures::executor::block_on;
use grpcio::Error as GrpcError;
use mc_attest_net::RaClient;
use mc_common::{
    logger::{log, Logger},
    time::TimeProvider,
};
use mc_fog_api::ledger_grpc;
use mc_fog_ledger_enclave::{Error as EnclaveError, LedgerEnclaveProxy};
use mc_ledger_db::LedgerDB;
use mc_sgx_report_cache_untrusted::{Error as ReportCacheError, ReportCacheThread};
use mc_util_encodings::Error as EncodingError;
use mc_util_grpc::{
    AnonymousAuthenticator, Authenticator, ConnectionUriGrpcioServer, TokenAuthenticator,
};
use mc_util_uri::ConnectionUri;
use mc_watcher::watcher_db::WatcherDB;
use std::sync::{Arc, Mutex};

#[derive(Debug, Display)]
pub enum LedgerServerError {
    /// Ledger enclave error: {0}
    Enclave(EnclaveError),
    /// Failed to join thread: {0}
    ThreadJoin(String),
    /// RPC shutdown failure: {0}
    RpcShutdown(String),
    /// Attest convert error: {0}
    Encoding(EncodingError),
    /// Report cache error: {0}
    ReportCache(ReportCacheError),
    /// GRPC Error: {0}
    Grpc(GrpcError),
}

impl From<EnclaveError> for LedgerServerError {
    fn from(src: EnclaveError) -> Self {
        LedgerServerError::Enclave(src)
    }
}

impl From<EncodingError> for LedgerServerError {
    fn from(src: EncodingError) -> Self {
        LedgerServerError::Encoding(src)
    }
}

impl From<ReportCacheError> for LedgerServerError {
    fn from(src: ReportCacheError) -> Self {
        Self::ReportCache(src)
    }
}

impl From<GrpcError> for LedgerServerError {
    fn from(src: GrpcError) -> Self {
        Self::Grpc(src)
    }
}

pub struct LedgerServer<E: LedgerEnclaveProxy, R: RaClient + Send + Sync + 'static> {
    config: LedgerServerConfig,
    server: Option<grpcio::Server>,
    key_image_service: KeyImageService<LedgerDB, E>,
    merkle_proof_service: MerkleProofService<LedgerDB, E>,
    block_service: BlockService<LedgerDB>,
    untrusted_tx_out_service: UntrustedTxOutService<LedgerDB>,
    enclave: E,
    ra_client: R,
    report_cache_thread: Option<ReportCacheThread>,
    logger: Logger,
    db_fetcher: Option<DbFetcher>,
}

impl<E: LedgerEnclaveProxy, R: RaClient + Send + Sync + 'static> LedgerServer<E, R> {
    pub fn new(
        config: LedgerServerConfig,
        enclave: E,
        ledger: LedgerDB,
        watcher: WatcherDB,
        ra_client: R,
        time_provider: impl TimeProvider + 'static,
        logger: Logger,
    ) -> Self {
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
            enclave.clone(),
            shared_state,
            client_authenticator.clone(),
            logger.clone(),
        );
        let merkle_proof_service = MerkleProofService::new(
            ledger.clone(),
            enclave.clone(),
            client_authenticator.clone(),
            logger.clone(),
        );
        let block_service = BlockService::new(
            ledger.clone(),
            watcher.clone(),
            client_authenticator.clone(),
            logger.clone(),
        );
        let untrusted_tx_out_service = UntrustedTxOutService::new(
            ledger,
            watcher,
            client_authenticator.clone(),
            logger.clone(),
        );

        Self {
            config,
            server: None,
            key_image_service,
            merkle_proof_service,
            block_service,
            untrusted_tx_out_service,
            enclave,
            ra_client,
            report_cache_thread: None,
            logger,
            db_fetcher: None,
        }
    }

    pub fn start(&mut self) -> Result<(), LedgerServerError> {
        let ret = {
            self.report_cache_thread = Some(ReportCacheThread::start(
                self.enclave.clone(),
                self.ra_client.clone(),
                self.config.ias_spid,
                &counters::ENCLAVE_REPORT_TIMESTAMP,
                self.logger.clone(),
            )?);

            self.db_fetcher = Some(DbFetcher::new(
                self.key_image_service.get_ledger(),
                self.logger.clone(),
                self.enclave.clone(),
                self.key_image_service.get_watcher(),
                self.key_image_service.get_db_poll_shared_state(),
            ));

            let env = Arc::new(
                grpcio::EnvBuilder::new()
                    .name_prefix("LedgerServer-RPC".to_string())
                    .build(),
            );

            // Package endpoints into grpc service
            let key_image_service =
                ledger_grpc::create_fog_key_image_api(self.key_image_service.clone());
            let merkle_proof_service =
                ledger_grpc::create_fog_merkle_proof_api(self.merkle_proof_service.clone());
            let block_service = ledger_grpc::create_fog_block_api(self.block_service.clone());
            let untrusted_tx_out_service =
                ledger_grpc::create_fog_untrusted_tx_out_api(self.untrusted_tx_out_service.clone());

            // Health check service
            let health_service =
                mc_util_grpc::HealthService::new(None, self.logger.clone()).into_service();

            // Package service into grpc server
            log::info!(
                self.logger,
                "Starting Ledger server on {}",
                self.config.client_listen_uri.addr(),
            );
            let server_builder = grpcio::ServerBuilder::new(env)
                .register_service(key_image_service)
                .register_service(merkle_proof_service)
                .register_service(block_service)
                .register_service(untrusted_tx_out_service)
                .register_service(health_service)
                .bind_using_uri(&self.config.client_listen_uri, self.logger.clone());

            let mut server = server_builder.build()?;
            server.start();

            self.server = Some(server);

            // Success.
            Ok(())
        };
        if ret.is_err() {
            self.stop();
        }
        ret
    }

    pub fn stop(&mut self) {
        if let Some(ref mut server) = self.server {
            block_on(server.shutdown()).expect("Could not stop grpc server");
        }

        if let Some(ref mut report_cache_thread) = self.report_cache_thread.take() {
            report_cache_thread
                .stop()
                .expect("Could not stop report cache thread");
        }

        if let Some(ref mut db_fetcher) = self.db_fetcher.take() {
            db_fetcher.stop().expect("Could not stop db fetcher");
        }
    }
}

impl<E: LedgerEnclaveProxy, R: RaClient + Send + Sync + 'static> Drop for LedgerServer<E, R> {
    fn drop(&mut self) {
        self.stop();
    }
}

/// State that we want to expose from the db poll thread
#[derive(Debug, Default)]
pub struct DbPollSharedState {
    /// The highest block count for which we can guarantee we have loaded all
    /// available data.
    pub highest_processed_block_count: u64,

    /// The cumulative txo count of the last known block.
    pub last_known_block_cumulative_txo_count: u64,
}
