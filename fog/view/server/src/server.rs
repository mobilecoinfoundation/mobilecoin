// Copyright (c) 2018-2021 The MobileCoin Foundation

//! Server object containing a view node
//! Constructible from config (for testability) and with a mechanism for
//! stopping it

use crate::{
    block_tracker::BlockTracker, config::MobileAcctViewConfig, counters, db_fetcher::DbFetcher,
    fog_view_service::FogViewService,
};
use futures::executor::block_on;
use mc_attest_net::RaClient;
use mc_common::{
    logger::{log, Logger},
    time::TimeProvider,
    trace_time,
};
use mc_crypto_keys::CompressedRistrettoPublic;
use mc_fog_api::view_grpc;
use mc_fog_recovery_db_iface::RecoveryDb;
use mc_fog_types::ETxOutRecord;
use mc_fog_uri::ConnectionUri;
use mc_fog_view_enclave::ViewEnclaveProxy;
use mc_sgx_report_cache_untrusted::ReportCacheThread;
use mc_util_grpc::{
    AnonymousAuthenticator, Authenticator, ConnectionUriGrpcioServer, TokenAuthenticator,
};
use std::{
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    thread::{sleep, Builder as ThreadBuilder, JoinHandle},
    time::{Duration, Instant},
};

pub struct ViewServer<E, RC, DB>
where
    E: ViewEnclaveProxy,
    RC: RaClient + Send + Sync + 'static,
    DB: RecoveryDb + Clone + Send + Sync + 'static,
{
    config: MobileAcctViewConfig,
    server: grpcio::Server,
    enclave: E,
    ra_client: RC,
    report_cache_thread: Option<ReportCacheThread>,
    db_poll_thread: DbPollThread<E, DB>,
    logger: Logger,
}

impl<E, RC, DB> ViewServer<E, RC, DB>
where
    E: ViewEnclaveProxy,
    RC: RaClient + Send + Sync + 'static,
    DB: RecoveryDb + Clone + Send + Sync + 'static,
{
    /// Make a new view server instance
    pub fn new(
        config: MobileAcctViewConfig,
        enclave: E,
        recovery_db: DB,
        ra_client: RC,
        time_provider: impl TimeProvider + 'static,
        logger: Logger,
    ) -> ViewServer<E, RC, DB> {
        let db_poll_thread =
            DbPollThread::new(enclave.clone(), recovery_db.clone(), logger.clone());

        let env = Arc::new(
            grpcio::EnvBuilder::new()
                .name_prefix("Main-RPC".to_string())
                .build(),
        );

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

        let fog_view_service = view_grpc::create_fog_view_api(FogViewService::new(
            enclave.clone(),
            Arc::new(recovery_db),
            db_poll_thread.get_shared_state(),
            client_authenticator,
            logger.clone(),
        ));
        log::debug!(logger, "Constructed View GRPC Service");

        // Health check service
        let health_service = mc_util_grpc::HealthService::new(None, logger.clone()).into_service();

        // Package service into grpc server
        log::info!(
            logger,
            "Starting View server on {}",
            config.client_listen_uri.addr(),
        );
        let server_builder = grpcio::ServerBuilder::new(env)
            .register_service(fog_view_service)
            .register_service(health_service)
            .bind_using_uri(&config.client_listen_uri, logger.clone());

        let server = server_builder.build().unwrap();

        Self {
            config,
            server,
            enclave,
            ra_client,
            report_cache_thread: None,
            db_poll_thread,
            logger,
        }
    }

    /// Start the server, which starts all the worker threads
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

        self.db_poll_thread.start();

        self.server.start();
        for (host, port) in self.server.bind_addrs() {
            log::info!(self.logger, "API listening on {}:{}", host, port);
        }
    }

    /// Stop the server and all worker threads
    pub fn stop(&mut self) {
        if let Some(ref mut thread) = self.report_cache_thread.take() {
            thread.stop().expect("Could not stop report cache thread");
        }

        self.db_poll_thread
            .stop()
            .expect("Could not stop db poll thread");

        block_on(self.server.shutdown()).expect("Could not stop grpc server");
    }

    /// Get the highest block count for which we can guarantee we have loaded
    /// all available data.
    pub fn highest_processed_block_count(&self) -> u64 {
        let state = self.db_poll_thread.get_shared_state();
        let locked_state = state.lock().expect("mutex poisoned");
        locked_state.highest_processed_block_count
    }
}

impl<E, RC, DB> Drop for ViewServer<E, RC, DB>
where
    E: ViewEnclaveProxy,
    RC: RaClient + Send + Sync + 'static,
    DB: RecoveryDb + Clone + Send + Sync + 'static,
{
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

    /// A block signature timestamp for the highest processed block
    pub highest_processed_block_signature_timestamp: u64,

    /// The last block count for which we were able to load data.
    pub last_known_block_count: u64,

    /// The cumulative txo count of the last known block.
    pub last_known_block_cumulative_txo_count: u64,
}

/// A thread that periodically pushes new tx data from db to enclave
struct DbPollThread<E, DB>
where
    E: ViewEnclaveProxy,
    DB: RecoveryDb + Clone + Send + Sync + 'static,
{
    /// Enclave.
    enclave: E,

    /// Recovery db.
    db: DB,

    /// Join handle used to wait for the thread to terminate.
    join_handle: Option<JoinHandle<()>>,

    /// Stop request trigger, used to signal the thread to stop.
    stop_requested: Arc<AtomicBool>,

    /// Shared state.
    shared_state: Arc<Mutex<DbPollSharedState>>,

    /// Logger.
    logger: Logger,
}

/// How long to wait between polling db
const DB_POLL_INTERNAL: Duration = Duration::from_millis(100);

impl<E, DB> DbPollThread<E, DB>
where
    E: ViewEnclaveProxy,
    DB: RecoveryDb + Clone + Send + Sync + 'static,
{
    /// Get the shared state.
    pub fn get_shared_state(&self) -> Arc<Mutex<DbPollSharedState>> {
        self.shared_state.clone()
    }

    /// Initialize a new DbPollThread object.
    pub fn new(enclave: E, db: DB, logger: Logger) -> Self {
        let stop_requested = Arc::new(AtomicBool::new(false));
        let shared_state = Arc::new(Mutex::new(DbPollSharedState::default()));

        Self {
            enclave,
            db,
            join_handle: None,
            stop_requested,
            shared_state,
            logger,
        }
    }

    /// Start the worker thread.
    pub fn start(&mut self) {
        assert!(self.join_handle.is_none());

        {
            let mut shared_state = self.shared_state.lock().expect("mutex poisoned");
            *shared_state = DbPollSharedState::default();
        }

        let thread_enclave = self.enclave.clone();
        let thread_db = self.db.clone();
        let thread_stop_requested = self.stop_requested.clone();
        let thread_shared_state = self.shared_state.clone();
        let thread_logger = self.logger.clone();

        self.join_handle = Some(
            ThreadBuilder::new()
                .name(format!("DbPoll-{}", std::any::type_name::<E>()))
                .spawn(move || {
                    Self::thread_entrypoint(
                        thread_enclave,
                        thread_db,
                        thread_stop_requested,
                        thread_shared_state,
                        thread_logger,
                    )
                })
                .expect("Could not spawn thread"),
        );
    }

    /// Stop and join the db poll thread
    pub fn stop(&mut self) -> Result<(), ()> {
        if let Some(join_handle) = self.join_handle.take() {
            self.stop_requested.store(true, Ordering::SeqCst);
            join_handle.join().map_err(|_| ())?;
        }

        Ok(())
    }

    fn thread_entrypoint(
        enclave: E,
        db: DB,
        stop_requested: Arc<AtomicBool>,
        shared_state: Arc<Mutex<DbPollSharedState>>,
        logger: Logger,
    ) {
        log::debug!(logger, "Db poll thread started");

        let mut worker =
            DbPollThreadWorker::new(stop_requested, enclave, db, shared_state, logger.clone());
        loop {
            match worker.tick() {
                WorkerTickResult::StopRequested => {
                    log::info!(logger, "stop requested");
                    break;
                }

                WorkerTickResult::HasMoreWork => {}

                WorkerTickResult::Sleep => {
                    sleep(DB_POLL_INTERNAL);
                }
            }
        }
    }
}

impl<E, DB> Drop for DbPollThread<E, DB>
where
    E: ViewEnclaveProxy,
    DB: RecoveryDb + Clone + Send + Sync + 'static,
{
    fn drop(&mut self) {
        let _ = self.stop();
    }
}

struct DbPollThreadWorker<E, DB>
where
    E: ViewEnclaveProxy,
    DB: RecoveryDb + Clone + Send + Sync + 'static,
{
    /// Stop request trigger, used to signal the thread to stop.
    stop_requested: Arc<AtomicBool>,

    /// Enclave.
    enclave: E,

    /// Recovery database.
    db: DB,

    /// Shared state.
    shared_state: Arc<Mutex<DbPollSharedState>>,

    /// Database fetcher - a background thread that attempts to fetch as much
    /// data from the database as possible.
    db_fetcher: DbFetcher,

    /// Keeps track of which blocks we have fed into the enclave.
    enclave_block_tracker: BlockTracker,

    /// Keeps track how long ago it since we made progress, (or complained about
    /// not making progress) When this gets too distant in the past, we log
    /// a warning
    last_unblocked_at: Instant,

    /// Logger
    logger: Logger,
}

pub enum WorkerTickResult {
    StopRequested,
    HasMoreWork,
    Sleep,
}

impl<E, DB> DbPollThreadWorker<E, DB>
where
    E: ViewEnclaveProxy,
    DB: RecoveryDb + Clone + Send + Sync + 'static,
{
    pub fn new(
        stop_requested: Arc<AtomicBool>,
        enclave: E,
        db: DB,
        shared_state: Arc<Mutex<DbPollSharedState>>,
        logger: Logger,
    ) -> Self {
        Self {
            stop_requested,
            enclave,
            db: db.clone(),
            shared_state,
            db_fetcher: DbFetcher::new(db, logger.clone()),
            enclave_block_tracker: BlockTracker::new(logger.clone()),
            last_unblocked_at: Instant::now(),
            logger,
        }
    }

    pub fn tick(&mut self) -> WorkerTickResult {
        if self.stop_requested.load(Ordering::SeqCst) {
            log::debug!(self.logger, "Db poll thread stop requested.");

            if let Err(err) = self.db_fetcher.stop() {
                log::warn!(self.logger, "Failed stopping db fetcher: {:?}", err);
            }

            return WorkerTickResult::StopRequested;
        }

        // Grab whatever fetched records have shown up since the last time we ran.
        let fetched_records_list = self.db_fetcher.get_pending_fetched_records();
        for fetched_records in fetched_records_list.into_iter() {
            // Early exit if stop as requested.
            if self.stop_requested.load(Ordering::SeqCst) {
                break;
            }

            // Insert the records into the enclave.
            self.add_records_to_enclave(
                fetched_records.ingress_key,
                fetched_records.block_index,
                fetched_records.records,
            );
        }

        // Figure out the highest fully processed block count and put that in the shared
        // state.
        let ingress_keys = self.db_fetcher.get_highest_processed_block_context();
        let (highest_processed_block_count, reason_we_stopped) = self
            .enclave_block_tracker
            .highest_fully_processed_block_count(&ingress_keys);

        let mut shared_state = self.shared_state.lock().expect("mutex poisoned");
        if shared_state.highest_processed_block_count != highest_processed_block_count {
            shared_state.highest_processed_block_count = highest_processed_block_count;
            self.last_unblocked_at = Instant::now();
        } else if self.last_unblocked_at.elapsed() >= Duration::from_secs(60) {
            if let Some(reason_we_stopped) = reason_we_stopped {
                log::warn!(self.logger, "We seem to be stuck at highest_processed_block_count = {} for at least a minute... we are blocked on an ingress key making progress: {:?}", highest_processed_block_count, reason_we_stopped);
            } else {
                log::debug!(self.logger, "We seem to be stuck at highest_processed_block_count = {} for at least a minute... we have processed all blocks known to the recovery database", highest_processed_block_count);
            }
            // We are still blocked but we don't need to log for another minute
            self.last_unblocked_at = Instant::now();
        }

        counters::HIGHEST_PROCESSED_BLOCK_COUNT
            .set(shared_state.highest_processed_block_count as i64);

        // Try to update the timestamp associated to highest_processed_block_count
        if let Some(timestamp) =
            self.get_block_signature_timestamp_for_block_count(highest_processed_block_count)
        {
            shared_state.highest_processed_block_signature_timestamp = timestamp;
        }

        // Figure out if the highest known block count has changed, and if so update it
        // + the txo count in the shared state.
        let cur_highest_known_block_count = self.enclave_block_tracker.highest_known_block_count();
        if shared_state.last_known_block_count != cur_highest_known_block_count {
            // We should only move forward.
            assert!(cur_highest_known_block_count > shared_state.last_known_block_count);

            // We need to report to the client the number of cumulative txo count in that
            // block, so query the database for this information.
            match self
                .db
                .get_cumulative_txo_count_for_block(cur_highest_known_block_count - 1)
            {
                Ok(Some(cumulative_txo_count)) => {
                    log::info!(self.logger, "Updating last known block shared data: block count: {}, cumulative txo count: {}",
                            cur_highest_known_block_count,
                            cumulative_txo_count,
                        );
                    shared_state.last_known_block_count = cur_highest_known_block_count;
                    shared_state.last_known_block_cumulative_txo_count = cumulative_txo_count;

                    counters::LAST_KNOWN_BLOCK_COUNT.set(cur_highest_known_block_count as i64);
                    counters::LAST_KNOWN_BLOCK_CUMULATIVE_TXO_COUNT
                        .set(cumulative_txo_count as i64);
                }

                Ok(None) => {
                    log::warn!(self.logger, "Unable to update last known block shared data: no cumulative txo count available for block count {}", cur_highest_known_block_count);
                }

                Err(err) => {
                    log::warn!(self.logger, "Unable to update last known block shared data: error while querying block count {}: {}", cur_highest_known_block_count, err);
                }
            };
        }

        // Done with this tick.
        WorkerTickResult::Sleep
    }

    fn add_records_to_enclave(
        &mut self,
        ingress_key: CompressedRistrettoPublic,
        block_index: u64,
        records: Vec<ETxOutRecord>,
    ) {
        let num_records = records.len();

        let add_records_result = {
            trace_time!(
                self.logger,
                "Added {} records into the enclave",
                num_records
            );
            let _metrics_timer = counters::ENCLAVE_ADD_RECORDS_TIME.start_timer();
            self.enclave.add_records(records)
        };

        match add_records_result {
            Err(err) => {
                // Failing to add records to the enclave is unrecoverable, but we don't want to
                // crash the server since it can still serve old requests.
                // When we encounter this failure mode we will begin logging a high-priority log
                // message every ten minutes indefinitely. The server can still serve client
                // requests in the meantime since those execute on a separate thread.
                loop {
                    log::crit!(
                        self.logger,
                        "Failed adding {} tx_outs for {:?}/{} into enclave: {}",
                        num_records,
                        ingress_key,
                        block_index,
                        err
                    );
                    sleep(Duration::from_secs(600));
                }
            }

            Ok(_) => {
                log::info!(
                    self.logger,
                    "Added {} tx outs for {:?}/{} into the enclave",
                    num_records,
                    ingress_key,
                    block_index
                );

                // Track that this block was processed.
                self.enclave_block_tracker
                    .block_processed(ingress_key, block_index);

                // Update metrics
                counters::BLOCKS_ADDED_COUNT.inc();
                counters::TXOS_ADDED_COUNT.inc_by(num_records as i64);
            }
        }
    }

    // The client needs a timestamp for the highest processed block, because the
    // highest processed block lets them know up to when they have accurate
    // balance information, and they may want to tell the user e.g. this was
    // your balance at 8:45 PM. So, ask the database.
    // If it doesn't work, hopefully it will work next time.
    fn get_block_signature_timestamp_for_block_count(&self, block_count: u64) -> Option<u64> {
        // The origin block has no block signature and hence no timestamp
        if block_count <= 1 {
            return None;
        }
        match self
            .db
            .get_block_signature_timestamp_for_block(block_count - 1)
        {
            Ok(Some(timestamp)) => Some(timestamp),
            Ok(None) => {
                log::warn!(self.logger, "Unable to update last known block shared data: no block signature timestamp for block count {}", block_count);
                None
            }

            Err(err) => {
                log::warn!(self.logger, "Unable to update last known block shared data: error while querying timestamp for block count {}: {}", block_count, err);
                None
            }
        }
    }
}
