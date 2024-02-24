// Copyright (c) 2018-2022 The MobileCoin Foundation

//! A background thread, in the server side, that continuously checks the
//! LedgerDB for new blocks, then gets all the key images associated to those
//! blocks and adds them to the enclave.
use crate::{counters, sharding_strategy::ShardingStrategy, DbPollSharedState};
use mc_blockchain_types::Block;
use mc_common::{
    logger::{log, Logger},
    trace_time,
};
use mc_fog_block_provider::BlockProvider;
use mc_fog_ledger_enclave::LedgerEnclaveProxy;
use mc_fog_ledger_enclave_api::KeyImageData;
use mc_fog_types::common::BlockRange;
use mc_util_grpc::ReadinessIndicator;
use mc_util_telemetry::{
    block_span_builder, mark_span_as_active, telemetry_static_key, tracer, Key, Span, Tracer,
};
use mc_watcher_api::TimestampResultCode;
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
    E: LedgerEnclaveProxy + Clone + Send + Sync + 'static,
    SS: ShardingStrategy + Send + Sync + 'static,
> {
    /// Struct representing the thread and its context.
    thread: Option<DbFetcherThread<E, SS>>,

    /// Join handle used to wait for the thread to terminate.
    join_handle: Option<JoinHandle<()>>,

    /// Stop request trigger, used to signal the thread to stop.
    stop_requested: Arc<AtomicBool>,
}

impl<
        E: LedgerEnclaveProxy + Clone + Send + Sync + 'static,
        SS: ShardingStrategy + Send + Sync + 'static,
    > DbFetcher<E, SS>
{
    pub fn new(
        block_provider: Box<dyn BlockProvider>,
        enclave: E,
        sharding_strategy: SS,
        db_poll_shared_state: Arc<Mutex<DbPollSharedState>>,
        readiness_indicator: ReadinessIndicator,
        poll_interval: Duration,
        logger: Logger,
    ) -> Self {
        let stop_requested = Arc::new(AtomicBool::new(false));
        let thread_stop_requested = stop_requested.clone();
        let thread_shared_state = db_poll_shared_state;
        let thread = Some(DbFetcherThread::new(
            block_provider,
            thread_stop_requested,
            sharding_strategy,
            enclave,
            thread_shared_state,
            readiness_indicator,
            poll_interval,
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
        E: LedgerEnclaveProxy + Clone + Send + Sync + 'static,
        SS: ShardingStrategy + Send + Sync + 'static,
    > Drop for DbFetcher<E, SS>
{
    fn drop(&mut self) {
        let _ = self.stop();
    }
}

struct DbFetcherThread<
    E: LedgerEnclaveProxy + Clone + Send + Sync + 'static,
    SS: ShardingStrategy + Send + Sync + 'static,
> {
    block_provider: Box<dyn BlockProvider>,
    stop_requested: Arc<AtomicBool>,
    sharding_strategy: SS,
    enclave: E,
    db_poll_shared_state: Arc<Mutex<DbPollSharedState>>,
    readiness_indicator: ReadinessIndicator,
    poll_interval: Duration,
    logger: Logger,
}

/// Background worker thread implementation that takes care of periodically
/// polling data out of the database. Add join handle
impl<
        E: LedgerEnclaveProxy + Clone + Send + Sync + 'static,
        SS: ShardingStrategy + Send + Sync + 'static,
    > DbFetcherThread<E, SS>
{
    const ERROR_RETRY_FREQUENCY: Duration = Duration::from_millis(1000);

    pub fn new(
        block_provider: Box<dyn BlockProvider>,
        stop_requested: Arc<AtomicBool>,
        sharding_strategy: SS,
        enclave: E,
        db_poll_shared_state: Arc<Mutex<DbPollSharedState>>,
        readiness_indicator: ReadinessIndicator,
        poll_interval: Duration,
        logger: Logger,
    ) -> Self {
        Self {
            block_provider,
            stop_requested,
            sharding_strategy,
            enclave,
            db_poll_shared_state,
            readiness_indicator,
            poll_interval,
            logger,
        }
    }

    pub fn run(mut self) {
        log::info!(self.logger, "Db fetcher thread started.");
        let block_range = self.sharding_strategy.get_block_range();
        let mut next_block_index = block_range.start_block;
        loop {
            loop {
                let num_blocks = self.load_block_data(&mut next_block_index);

                let end = min(num_blocks, block_range.end_block);

                if next_block_index < end.saturating_sub(BLOCKS_BEHIND) {
                    self.readiness_indicator.set_unready();
                } else {
                    self.readiness_indicator.set_ready();
                }

                if end <= next_block_index {
                    break;
                }

                if self.stop_requested.load(Ordering::SeqCst) {
                    break;
                }
            }

            if !block_range.contains(next_block_index) {
                log::info!(self.logger, "Db fetcher thread reached end of block range.");
                break;
            }

            if self.stop_requested.load(Ordering::SeqCst) {
                log::info!(self.logger, "Db fetcher thread stop requested.");
                break;
            }

            std::thread::sleep(self.poll_interval);
        }
    }

    /// Attempt to load the next block that we are aware of and tracking.
    ///
    /// The `next_block_index` will be incremented if the block is successfully
    /// loaded.
    ///
    /// Returns the number of blocks in the block provider.
    fn load_block_data(&mut self, next_block_index: &mut u64) -> u64 {
        let watcher_timeout: Duration = Duration::from_millis(5000);

        let start_time = SystemTime::now();

        let blocks = match self.block_provider.get_blocks_data(&[*next_block_index]) {
            Err(e) => {
                log::error!(
                    self.logger,
                    "Unexpected error when checking for block data {}: {:?}",
                    next_block_index,
                    e
                );
                std::thread::sleep(Self::ERROR_RETRY_FREQUENCY);
                // We errored so we don't know how many blocks are in the ledger
                return 0;
            }
            Ok(blocks) => blocks,
        };

        let latest_block = blocks.latest_block;

        if let Some(next_block) = blocks.results.get(0).and_then(|r| r.as_ref()) {
            let tracer = tracer!();

            let mut span = block_span_builder(&tracer, "poll_block", *next_block_index)
                .with_start_time(start_time)
                .start(&tracer);

            span.set_attribute(TELEMETRY_BLOCK_INDEX_KEY.i64(*next_block_index as i64));

            let _active = mark_span_as_active(span);

            // Get the timestamp for the block.
            let timestamp =
                if next_block.block_timestamp_result_code == TimestampResultCode::TimestampFound {
                    next_block.block_timestamp
                } else {
                    tracer.in_span("poll_block_timestamp", |_cx| {
                        self.block_provider
                            .poll_block_timestamp(*next_block_index, watcher_timeout)
                    })
                };

            // Add block to enclave.
            let records = next_block
                .block_data
                .contents()
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

            *next_block_index += 1;
            let mut processed_block_range = self.sharding_strategy.get_block_range();
            processed_block_range.end_block = *next_block_index;
            self.update_db_poll_shared_state(&latest_block, processed_block_range);
        }
        // Adding 1 as indices are 0 based, but "number of blocks" is 1 based.
        latest_block.index + 1
    }

    fn update_db_poll_shared_state(
        &mut self,
        latest_block: &Block,
        processed_block_range: BlockRange,
    ) {
        tracer!().in_span("update_shared_state", |_cx| {
            let mut shared_state = self.db_poll_shared_state.lock().expect("mutex poisoned");
            shared_state.processed_block_range = processed_block_range;
            shared_state.last_known_block_cumulative_txo_count = latest_block.cumulative_txo_count;
            shared_state.latest_block_version = latest_block.version;
        });
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
