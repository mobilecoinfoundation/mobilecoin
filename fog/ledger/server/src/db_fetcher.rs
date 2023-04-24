// Copyright (c) 2018-2022 The MobileCoin Foundation

//! A background thread, in the server side, that continuously checks the
//! LedgerDB for new blocks, then gets all the key images associated to those
//! blocks and adds them to the enclave.
use crate::{counters, sharding_strategy::ShardingStrategy, DbPollSharedState};
use mc_common::{
    logger::{log, Logger},
    trace_time,
};
use mc_fog_ledger_enclave::LedgerEnclaveProxy;
use mc_fog_ledger_enclave_api::KeyImageData;
use mc_fog_types::common::BlockRange;
use mc_ledger_db::{self, Error as LedgerError, Ledger};
use mc_util_grpc::ReadinessIndicator;
use mc_util_telemetry::{
    block_span_builder, mark_span_as_active, telemetry_static_key, tracer, Key, Span, Tracer,
};
use mc_watcher::watcher_db::WatcherDB;
use retry::{delay, retry, OperationResult};
use std::{
    cmp::min,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    thread::{Builder as ThreadBuilder, JoinHandle},
    time::{Duration, SystemTime},
};

/// Telemetry: block index currently being worked on.
const TELEMETRY_BLOCK_INDEX_KEY: Key = telemetry_static_key!("block-index");

/// The number of unloaded available blocks which causes the DbFetcher to be
/// marked unready
const BLOCKS_BEHIND: u64 = 100;

/// An object for managing background data fetches from the ledger database.
pub struct DbFetcher<
    DB: Ledger + 'static,
    E: LedgerEnclaveProxy + Clone + Send + Sync + 'static,
    SS: ShardingStrategy + Send + Sync + 'static,
> {
    /// Struct representing the thread and its context.
    thread: Option<DbFetcherThread<DB, E, SS>>,
    /// Join handle used to wait for the thread to terminate.
    join_handle: Option<JoinHandle<()>>,

    /// Stop request trigger, used to signal the thread to stop.
    stop_requested: Arc<AtomicBool>,
}

impl<
        DB: Ledger + 'static,
        E: LedgerEnclaveProxy + Clone + Send + Sync + 'static,
        SS: ShardingStrategy + Send + Sync + 'static,
    > DbFetcher<DB, E, SS>
{
    pub fn new(
        db: DB,
        enclave: E,
        sharding_strategy: SS,
        watcher: WatcherDB,
        db_poll_shared_state: Arc<Mutex<DbPollSharedState>>,
        readiness_indicator: ReadinessIndicator,
        logger: Logger,
    ) -> Self {
        let stop_requested = Arc::new(AtomicBool::new(false));
        let thread_stop_requested = stop_requested.clone();
        let thread_shared_state = db_poll_shared_state;
        let thread = Some(DbFetcherThread::new(
            db,
            thread_stop_requested,
            sharding_strategy,
            enclave,
            watcher,
            thread_shared_state,
            readiness_indicator,
            logger,
        ));

        Self {
            thread,
            join_handle: None,
            stop_requested,
        }
    }

    /// Start running the DbFetcher thread.
    pub fn start(&mut self) {
        let thread = self
            .thread
            .take()
            .expect("No DbFetcher thread to attempt to spawn");
        self.join_handle = Some(
            ThreadBuilder::new()
                .name("LedgerDbFetcher".to_owned())
                .spawn(move || thread.run())
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
}

impl<
        DB: Ledger + 'static,
        E: LedgerEnclaveProxy + Clone + Send + Sync + 'static,
        SS: ShardingStrategy + Send + Sync + 'static,
    > Drop for DbFetcher<DB, E, SS>
{
    fn drop(&mut self) {
        let _ = self.stop();
    }
}

struct DbFetcherThread<
    DB: Ledger,
    E: LedgerEnclaveProxy + Clone + Send + Sync + 'static,
    SS: ShardingStrategy + Send + Sync + 'static,
> {
    db: DB,
    stop_requested: Arc<AtomicBool>,
    sharding_strategy: SS,
    enclave: E,
    watcher: WatcherDB,
    db_poll_shared_state: Arc<Mutex<DbPollSharedState>>,
    readiness_indicator: ReadinessIndicator,
    logger: Logger,
}

/// Background worker thread implementation that takes care of periodically
/// polling data out of the database. Add join handle
impl<
        DB: Ledger,
        E: LedgerEnclaveProxy + Clone + Send + Sync + 'static,
        SS: ShardingStrategy + Send + Sync + 'static,
    > DbFetcherThread<DB, E, SS>
{
    const POLLING_FREQUENCY: Duration = Duration::from_millis(10);
    const ERROR_RETRY_FREQUENCY: Duration = Duration::from_millis(1000);

    pub fn new(
        db: DB,
        stop_requested: Arc<AtomicBool>,
        sharding_strategy: SS,
        enclave: E,
        watcher: WatcherDB,
        db_poll_shared_state: Arc<Mutex<DbPollSharedState>>,
        readiness_indicator: ReadinessIndicator,
        logger: Logger,
    ) -> Self {
        Self {
            db,
            stop_requested,
            sharding_strategy,
            enclave,
            watcher,
            db_poll_shared_state,
            readiness_indicator,
            logger,
        }
    }

    pub fn run(mut self) {
        log::info!(self.logger, "Db fetcher thread started.");
        let block_range = self.sharding_strategy.get_block_range();
        let mut next_block_index = 0;
        loop {
            if self.stop_requested.load(Ordering::SeqCst) {
                log::info!(self.logger, "Db fetcher thread stop requested.");
                break;
            }

            // Each call to load_block_data attempts to load one block for each known
            // invocation. We want to keep loading blocks as long as we have data to load,
            // but that could take some time which is why the loop is also gated
            // on the stop trigger in case a stop is requested during loading.
            while self.load_block_data(&mut next_block_index, &block_range)
                && !self.stop_requested.load(Ordering::SeqCst)
            {
                // Hack: If we notice that we are way behind the ledger, set ourselves unready
                match self.db.num_blocks() {
                    Ok(num_blocks) => {
                        // if there are > BLOCKS_BEHIND *available* blocks we haven't loaded yet,
                        // set unready
                        if min(num_blocks, block_range.end_block) > next_block_index + BLOCKS_BEHIND
                        {
                            self.readiness_indicator.set_unready();
                        }
                    }
                    Err(err) => {
                        log::error!(self.logger, "Could not get num blocks from db: {}", err);
                    }
                };
            }

            // If we get this far then we loaded all available block data from the DB into
            // the enclave.
            //
            // However, it is possible that mobilecoind is slow to sync, and then we may
            // think we are ready when we haven't actually loaded anything.
            // It would be better if we could somehow couple this with a probe to
            // mobilecoind to ensure that mobilecoind thinks it is caught up.
            // Setting ourselves unready when we notice we are way behind is a workaround.
            self.readiness_indicator.set_ready();

            std::thread::sleep(Self::POLLING_FREQUENCY);
        }
    }

    /// Attempt to load the next block that we
    /// are aware of and tracking.
    /// Returns true if we might have more block data to load.
    fn load_block_data(&mut self, next_block_index: &mut u64, block_range: &BlockRange) -> bool {
        // Default to true: if there is an error, we may have more work, we don't know
        let mut may_have_more_work = true;
        let watcher_timeout: Duration = Duration::from_millis(5000);

        let start_time = SystemTime::now();

        match self.db.get_block_contents(*next_block_index) {
            Err(LedgerError::NotFound) => may_have_more_work = false,
            Err(e) => {
                log::error!(
                    self.logger,
                    "Unexpected error when checking for block data {}: {:?}",
                    next_block_index,
                    e
                );
                std::thread::sleep(Self::ERROR_RETRY_FREQUENCY);
            }
            Ok(block_contents) => {
                // Tracing
                let tracer = tracer!();

                let mut span = block_span_builder(&tracer, "poll_block", *next_block_index)
                    .with_start_time(start_time)
                    .start(&tracer);

                span.set_attribute(TELEMETRY_BLOCK_INDEX_KEY.i64(*next_block_index as i64));

                let _active = mark_span_as_active(span);

                // Only add blocks within the epoch to the ORAM
                if block_range.contains(*next_block_index) {
                    // Get the timestamp for the block.
                    let timestamp = tracer.in_span("poll_block_timestamp", |_cx| {
                        self.watcher
                            .poll_block_timestamp(*next_block_index, watcher_timeout)
                    });

                    // Add block to enclave.
                    let records = block_contents
                        .key_images
                        .iter()
                        .map(|key_image| KeyImageData {
                            key_image: *key_image,
                            block_index: *next_block_index,
                            timestamp,
                        })
                        .collect();

                    tracer.in_span("add_records_to_enclave", |_cx| {
                        self.add_records_to_enclave(*next_block_index, records);
                    });
                }

                // Update shared state.
                tracer.in_span("update_shared_state", |_cx| {
                    let mut shared_state =
                        self.db_poll_shared_state.lock().expect("mutex poisoned");
                    // this is next_block_index + 1 because next_block_index is actually the block
                    // we just processed, so we have fully processed next_block_index + 1 blocks
                    shared_state.highest_processed_block_count = *next_block_index + 1;
                    match self.db.num_txos() {
                        Err(e) => {
                            log::error!(
                                self.logger,
                                "Unexpected error when checking for ledger num txos {}: {:?}",
                                next_block_index,
                                e
                            );
                        }
                        Ok(global_txo_count) => {
                            // keep track of count for ledger enclave untrusted
                            shared_state.last_known_block_cumulative_txo_count = global_txo_count;
                        }
                    }
                    match self.db.get_latest_block() {
                        Err(e) => {
                            log::error!(
                                self.logger,
                                "Unexpected error when checking for ledger latest block version {}: {:?}",
                                next_block_index,
                                e
                            );
                        }
                        Ok(block) => {
                            shared_state.latest_block_version = block.version;
                        }
                    }
                });

                *next_block_index += 1;
            }
        }
        may_have_more_work
    }

    fn add_records_to_enclave(&mut self, block_index: u64, records: Vec<KeyImageData>) {
        let num_records = records.len();

        let _info = retry(delay::Fixed::from_millis(5000).map(delay::jitter), || {
            trace_time!(
                self.logger,
                "Added {} records into the enclave",
                num_records
            );
            let metrics_timer = counters::ENCLAVE_ADD_KEY_IMAGE_DATA_TIME.start_timer();

            match self.enclave.add_key_image_data(records.clone()) {
                Ok(info) => {
                    // Update metrics
                    counters::BLOCKS_ADDED_COUNT.inc();
                    counters::KEY_IMAGES_FETCHED_COUNT.inc_by(num_records as u64);
                    OperationResult::Ok(info)
                }
                Err(err) => {
                    let _ = metrics_timer.stop_and_discard();
                    // Failing to add records to the enclave is unrecoverable,
                    // When we encounter this failure mode we will begin logging a high-priority log
                    // message every ten minutes indefinitely.
                    log::crit!(
                        self.logger,
                        "Failed adding {} keyimage_outs for {} into enclave: {}",
                        num_records,
                        block_index,
                        err
                    );
                    OperationResult::Retry(err)
                }
            }
        });

        log::info!(
            self.logger,
            "Added {} keyimage outs for block with index {} into the enclave",
            num_records,
            block_index
        );
    }
}
