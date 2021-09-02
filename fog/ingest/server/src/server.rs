// Copyright (c) 2018-2021 The MobileCoin Foundation

//! Server object containing ingest node + thread that polls for input.

use crate::{
    attested_api_service::AttestedApiService,
    controller::IngestController,
    error::IngestServiceError,
    ingest_peer_service::IngestPeerService,
    ingest_service::IngestService,
    state_file::StateFile,
    worker::{IngestWorker, PeerCheckupWorker, ReportCacheWorker},
    SeqDisplay,
};
use futures::executor::block_on;
use mc_attest_api::attest_grpc::create_attested_api;
use mc_attest_core::ProviderId;
use mc_attest_net::RaClient;
use mc_common::{
    logger::{log, Logger},
    ResponderId,
};
use mc_fog_api::{
    ingest_common::{IngestControllerMode, IngestSummary},
    ingest_grpc, ingest_peer_grpc,
};
use mc_fog_recovery_db_iface::{RecoveryDb, ReportDb};
use mc_fog_uri::{FogIngestUri, IngestPeerUri};
use mc_ledger_db::{Ledger, LedgerDB};
use mc_util_grpc::ConnectionUriGrpcioServer;
use mc_util_uri::ConnectionUri;
use mc_watcher::watcher_db::WatcherDB;
use std::{collections::BTreeSet, path::PathBuf, sync::Arc, time::Duration};

/// The configuration options accepted by the IngestServer
/// This is slightly different from the struct_opt config for obscure reasons
#[derive(Clone, Debug)]
pub struct IngestServerConfig {
    /// Max number of transactions ingest can eat at one time.  This is mostly
    /// determined by SGX memory allocation limits, so it must be configurable
    pub max_transactions: usize,

    /// Number of transactions that can be processed before oblivious map
    /// overflows. When overflow occurs, the server continues operating as
    /// normal, but egress key must be rotated. This will cause the users to
    /// each have an additional RNG and download some additional data from
    /// fog-view
    ///
    /// This should be a bit less than total available memory / 40 bytes
    /// Overflow will occur at ~70% utilization
    /// FIXME: The unit here should probably just be bytes
    pub omap_capacity: u64,

    /// The IAS SPID to use when getting a quote
    pub ias_spid: ProviderId,

    /// Local Ingest Node ID
    pub local_node_id: ResponderId,

    /// gRPC listening URI for client requests.
    pub client_listen_uri: FogIngestUri,

    /// gRPC listening URI for peer requests.
    pub peer_listen_uri: IngestPeerUri,

    /// All uri's that should be in our peers list on startup.
    /// It is not require to include or omit peer_listen_uri in this set.
    pub peers: BTreeSet<IngestPeerUri>,

    /// The number of blocks after which we check up on each of our peer backups
    /// if we are active
    ///
    /// If omitted then peer checkups don't happen
    pub peer_checkup_period: Option<Duration>,

    /// The amount we add to current block height to compute pubkey_expiry in
    /// reports
    pub pubkey_expiry_window: u64,

    /// The amount of time we wait for the watcher db to catchup if it falls
    /// behind If this timeout is exceeded then the ETxOut's will have no
    /// timestamp
    pub watcher_timeout: Duration,

    /// report_id associated the reports produced by this ingest service.
    /// This should match what appears in users' public addresses.
    /// Defaults to empty string.
    pub fog_report_id: String,

    /// Optional state file path.
    pub state_file: Option<StateFile>,

    /// Enclave path
    /// This should generally be, next to current exe, in production.
    /// During cargo tests we use a helper that searches the target/ dir for the
    /// enclave.so file.
    pub enclave_path: PathBuf,
}

/// All of the state and grpcio objects and threads associated to the ingest
/// server
pub struct IngestServer<
    R: RaClient + Send + Sync + 'static,
    DB: RecoveryDb + ReportDb + Clone + Send + Sync + 'static,
> where
    IngestServiceError: From<<DB as RecoveryDb>::Error>,
{
    config: IngestServerConfig,
    ledger_db: LedgerDB,
    watcher: WatcherDB,
    controller: Arc<IngestController<R, DB>>,
    server: Option<grpcio::Server>,
    peer_server: Option<grpcio::Server>,
    ingest_worker: Option<IngestWorker>,
    peer_checkup_worker: Option<PeerCheckupWorker>,
    report_cache_worker: Option<ReportCacheWorker>,
    logger: Logger,
}

impl<
        R: RaClient + Send + Sync + 'static,
        DB: RecoveryDb + ReportDb + Clone + Send + Sync + 'static,
    > IngestServer<R, DB>
where
    IngestServiceError: From<<DB as RecoveryDb>::Error>,
{
    /// Create a new ingest server from config object, enclave, and a series of
    /// db's
    pub fn new(
        config: IngestServerConfig,
        ra_client: R,
        recovery_db: DB,
        watcher: WatcherDB,
        ledger_db: LedgerDB,
        logger: Logger,
    ) -> Self {
        // Validate peer list in config:
        // - Each peers responder id should be unique
        // - Our responder id ("local-node-id") should be one of them
        let peer_responder_ids: BTreeSet<ResponderId> = config
            .peers
            .iter()
            .map(|uri| {
                uri.responder_id()
                    .expect("Could not compute responder id for one of our peers")
            })
            .collect();
        if peer_responder_ids.len() != config.peers.len() {
            panic!("Invalid configuration: Had {} peer uris, but only {} unique responder id's among them. Peers: {}, Responder Ids: {:?}", config.peers.len(), peer_responder_ids.len(), SeqDisplay(config.peers.iter()), peer_responder_ids);
        }

        if !peer_responder_ids.contains(&config.local_node_id) {
            panic!("Invaild configuration: Our local node id does not appear as one of the respond ids of one of the uris in the peer list, but that is required.");
        }

        let controller = Arc::new(IngestController::new(
            config.clone(),
            ra_client,
            recovery_db,
            logger.clone(),
        ));

        Self {
            config,
            ledger_db,
            watcher,
            controller,
            server: None,
            peer_server: None,
            ingest_worker: None,
            peer_checkup_worker: None,
            report_cache_worker: None,
            logger,
        }
    }

    /// Start all the grpc services and threads in the server
    pub fn start(&mut self) -> Result<(), IngestServiceError> {
        let ret = self.start_helper();
        if let Err(ref err) = ret {
            log::error!(self.logger, "Stopping ingest server due to {}", err);
            self.stop();
        }
        ret
    }

    /// Helper which gathers errors when starting server
    fn start_helper(&mut self) -> Result<(), IngestServiceError> {
        // Ensure that the report cache is updated successfully before anything else
        // happens
        self.controller.update_enclave_report_cache()?;
        self.start_ingest_rpc_server()?;
        self.start_peer_rpc_server()?;
        self.start_ingest_worker()?;
        self.start_peer_checkup_worker()?;
        self.start_report_cache_worker()?;
        Ok(())
    }

    /// Start the ingest rpc server
    fn start_ingest_rpc_server(&mut self) -> Result<(), IngestServiceError> {
        log::info!(self.logger, "Starting RPC server.");
        // Package it into grpc service
        let ingest_service = ingest_grpc::create_account_ingest_api(IngestService::new(
            self.controller.clone(),
            self.ledger_db.clone(),
            self.logger.clone(),
        ));

        let health_service =
            mc_util_grpc::HealthService::new(None, self.logger.clone()).into_service();

        // Package service into grpc server
        log::info!(
            self.logger,
            "Starting Ingest server on {}",
            self.config.client_listen_uri.addr(),
        );

        let grpc_env = Arc::new(
            grpcio::EnvBuilder::new()
                .name_prefix("Ingest-RPC".to_string())
                .build(),
        );

        let server_builder = grpcio::ServerBuilder::new(grpc_env)
            .register_service(ingest_service)
            .register_service(health_service)
            .bind_using_uri(&self.config.client_listen_uri, self.logger.clone());

        let mut server = server_builder.build()?;
        server.start();

        for (host, port) in server.bind_addrs() {
            log::info!(
                self.logger,
                "Ingest GRPC API listening on {}:{}",
                host,
                port
            );
        }

        self.server = Some(server);
        Ok(())
    }

    /// Start the peering rpc server
    fn start_peer_rpc_server(&mut self) -> Result<(), IngestServiceError> {
        log::info!(self.logger, "Starting Peer RPC server.");

        let ingest_peer_service = ingest_peer_grpc::create_account_ingest_peer_api(
            IngestPeerService::new(self.controller.clone(), self.logger.clone()),
        );

        let health_service =
            mc_util_grpc::HealthService::new(None, self.logger.clone()).into_service();

        let attested_service = create_attested_api(AttestedApiService::<R, DB>::new(
            self.controller.clone(),
            self.logger.clone(),
        ));

        // Package service into grpc server
        log::info!(
            self.logger,
            "Starting Peer Ingest server on {}",
            self.config.peer_listen_uri.addr(),
        );

        let grpc_env = Arc::new(
            grpcio::EnvBuilder::new()
                .name_prefix("Ingest-Peer-RPC".to_string())
                .build(),
        );

        let server_builder = grpcio::ServerBuilder::new(grpc_env)
            .register_service(attested_service)
            .register_service(ingest_peer_service)
            .register_service(health_service)
            .bind_using_uri(&self.config.peer_listen_uri, self.logger.clone());

        let mut server = server_builder.build()?;
        server.start();

        for (host, port) in server.bind_addrs() {
            log::info!(self.logger, "Peer GRPC API listening on {}:{}", host, port);
        }

        self.peer_server = Some(server);
        Ok(())
    }

    /// Start the ingest_worker thread
    fn start_ingest_worker(&mut self) -> Result<(), IngestServiceError> {
        assert!(self.ingest_worker.is_none());
        log::info!(self.logger, "Starting ingest worker");
        self.ingest_worker = Some(IngestWorker::new(
            self.controller.clone(),
            self.ledger_db.clone(),
            self.watcher.clone(),
            self.config.watcher_timeout,
            self.logger.clone(),
        ));

        Ok(())
    }

    /// Start the peer checkup worker thread
    fn start_peer_checkup_worker(&mut self) -> Result<(), IngestServiceError> {
        assert!(self.peer_checkup_worker.is_none());
        log::info!(self.logger, "Starting peer checkup worker");
        if let Some(period) = self.config.peer_checkup_period {
            self.peer_checkup_worker = Some(PeerCheckupWorker::new(
                self.controller.clone(),
                period,
                self.logger.clone(),
            ));
        }
        Ok(())
    }

    /// Start the report cache worker thread
    fn start_report_cache_worker(&mut self) -> Result<(), IngestServiceError> {
        assert!(self.report_cache_worker.is_none());
        log::info!(self.logger, "Starting report cache worker");
        self.report_cache_worker = Some(ReportCacheWorker::new(
            self.controller.clone(),
            self.logger.clone(),
        ));
        Ok(())
    }

    /// Stop the servers and threads
    /// They cannot be restarted, so this should normally be done only just
    /// before tearing down the whole server.
    pub fn stop(&mut self) {
        // This blocks on teardown of ingest_worker
        self.ingest_worker = None;
        // This blocks on teardown of peer checkup worker
        self.peer_checkup_worker = None;
        // This blocks on teardown of report cache worker
        self.report_cache_worker = None;
        if let Some(mut server) = self.peer_server.take() {
            block_on(server.shutdown()).expect("Could not stop peer grpc server");
        }
        if let Some(mut server) = self.server.take() {
            block_on(server.shutdown()).expect("Could not stop grpc server");
        }
    }

    /// Get the summary describing the state of the server
    pub fn get_ingest_summary(&self) -> IngestSummary {
        self.controller.get_ingest_summary()
    }

    /// Ask if the server is active
    /// This is a convenience wrapper used in tests
    pub fn is_active(&self) -> bool {
        self.get_ingest_summary().mode == IngestControllerMode::Active
    }

    /// Tell the server to activate.
    /// This is used in tests when it would be simpler than making an RPC client
    pub fn activate(&self) -> Result<IngestSummary, IngestServiceError> {
        self.controller.activate(self.ledger_db.num_blocks()?)
    }

    /// Tell the server to retire
    /// This is used in tests when it would be simpler than making an RPC client
    pub fn retire(&self) -> Result<IngestSummary, IngestServiceError> {
        self.controller.retire()
    }

    /// Attest to another ingest node and store the private key from its enclave
    /// in our enclave
    /// This is used in tests when it would be simpler than making an RPC client
    pub fn sync_keys_from_remote(
        &mut self,
        remote_peer_uri: &IngestPeerUri,
    ) -> Result<IngestSummary, IngestServiceError> {
        self.controller.sync_keys_from_remote(remote_peer_uri)
    }
}

impl<
        R: RaClient + Send + Sync + 'static,
        DB: RecoveryDb + ReportDb + Clone + Send + Sync + 'static,
    > Drop for IngestServer<R, DB>
where
    IngestServiceError: From<<DB as RecoveryDb>::Error>,
{
    fn drop(&mut self) {
        self.stop();
    }
}
