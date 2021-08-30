// Copyright (c) 2018-2021 The MobileCoin Foundation

//! A background thread, in the server side, that continuously checks the
//! LedgerDB for new blocks, then gets all the key images associated to those
//! blocks and adds them to the enclave.
use crate::{counters, server::DbPollSharedState};
use mc_common::{
    logger::{log, Logger},
    trace_time,
};
use mc_fog_ledger_enclave::LedgerEnclaveProxy;
use mc_fog_ledger_enclave_api::KeyImageData;
use mc_ledger_db::{self, Error as LedgerError, Ledger};
use mc_watcher::watcher_db::WatcherDB;
use retry::{delay, retry, OperationResult};
use std::{
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    thread::{Builder as ThreadBuilder, JoinHandle},
    time::Duration,
};

/// An object for managing background data fetches from the ledger database.
pub struct DbFetcher {
    /// Join handle used to wait for the thread to terminate.
    join_handle: Option<JoinHandle<()>>,

    /// Stop request trigger, used to signal the thread to stop.
    stop_requested: Arc<AtomicBool>,
}

impl DbFetcher {
    pub fn new<DB: Ledger + Clone + Send + Sync + 'static, E: LedgerEnclaveProxy>(
        db: DB,
        logger: Logger,
        enclave: E,
        watcher: WatcherDB,
        db_poll_shared_state: Arc<Mutex<DbPollSharedState>>,
    ) -> Self {
        let stop_requested = Arc::new(AtomicBool::new(false));
        let thread_stop_requested = stop_requested.clone();
        let thread_shared_state = db_poll_shared_state;
        let join_handle = Some(
            ThreadBuilder::new()
                .name("LedgerDbFetcher".to_owned())
                .spawn(move || {
                    DbFetcherThread::start(
                        db,
                        thread_stop_requested,
                        0,
                        logger,
                        enclave,
                        watcher,
                        thread_shared_state,
                    )
                })
                .expect("Could not spawn thread"),
        );

        Self {
            join_handle,
            stop_requested,
        }
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

impl Drop for DbFetcher {
    fn drop(&mut self) {
        let _ = self.stop();
    }
}

struct DbFetcherThread<DB: Ledger, E: LedgerEnclaveProxy + Clone + Send + Sync + 'static> {
    db: DB,
    stop_requested: Arc<AtomicBool>,
    next_block_index: u64,
    logger: Logger,
    enclave: E,
    watcher: WatcherDB,
    db_poll_shared_state: Arc<Mutex<DbPollSharedState>>,
}

/// Background worker thread implementation that takes care of periodically
/// polling data out of the database. Add join handle
impl<DB: Ledger, E: LedgerEnclaveProxy + Clone + Send + Sync + 'static> DbFetcherThread<DB, E> {
    const POLLING_FREQUENCY: Duration = Duration::from_millis(10);
    const ERROR_RETRY_FREQUENCY: Duration = Duration::from_millis(1000);

    pub fn start(
        db: DB,
        stop_requested: Arc<AtomicBool>,
        next_block_index: u64,
        logger: Logger,
        enclave: E,
        watcher: WatcherDB,
        db_poll_shared_state: Arc<Mutex<DbPollSharedState>>,
    ) {
        let thread = Self {
            db,
            stop_requested,
            next_block_index,
            logger,
            enclave,
            watcher,
            db_poll_shared_state,
        };
        thread.run();
    }

    fn run(mut self) {
        log::info!(self.logger, "Db fetcher thread started.");
        self.next_block_index = 0;
        loop {
            if self.stop_requested.load(Ordering::SeqCst) {
                log::info!(self.logger, "Db fetcher thread stop requested.");
                break;
            }
            // Each call to load_block_data attempts to load one block for each known
            // invocation. We want to keep loading blocks as long as we have data to load,
            // but that could take some time which is why the loop is also gated
            // on the stop trigger in case a stop is requested during loading.
            while self.load_block_data() && !self.stop_requested.load(Ordering::SeqCst) {}
        }
    }

    /// Attempt to load the next block that we
    /// are aware of and tracking.
    /// Returns true if we might have more block data to load.
    fn load_block_data(&mut self) -> bool {
        let mut has_more_work = false;
        let watcher_timeout: Duration = Duration::from_millis(5000);

        match self.db.get_block_contents(self.next_block_index) {
            Err(LedgerError::NotFound) => std::thread::sleep(Self::POLLING_FREQUENCY),
            Err(e) => {
                log::error!(
                    self.logger,
                    "Unexpected error when checking for block data {}: {:?}",
                    self.next_block_index,
                    e
                );
                std::thread::sleep(Self::ERROR_RETRY_FREQUENCY);
            }
            Ok(block_contents) => {
                // Get the timestamp for the block.
                let timestamp = self
                    .watcher
                    .poll_block_timestamp(self.next_block_index, watcher_timeout);

                let records = block_contents
                    .key_images
                    .iter()
                    .map(|key_image| KeyImageData {
                        key_image: *key_image,
                        block_index: self.next_block_index,
                        timestamp,
                    })
                    .collect();

                self.add_records_to_enclave(self.next_block_index, records);
                let mut shared_state = self.db_poll_shared_state.lock().expect("mutex poisoned");
                // this is next_block_index + 1 because next_block_index is actually the block
                // we just processed, so we have fully processed next_block_index + 1 blocks
                shared_state.highest_processed_block_count = self.next_block_index + 1;
                match self.db.num_txos() {
                    Err(e) => {
                        log::error!(
                            self.logger,
                            "Unexpected error when checking for ledger num txos {}: {:?}",
                            self.next_block_index,
                            e
                        );
                    }
                    Ok(global_txo_count) => {
                        // keep track of count for ledger enclave untrusted
                        shared_state.last_known_block_cumulative_txo_count = global_txo_count;
                    }
                }
                self.next_block_index += 1;
                has_more_work = true;
            }
        }
        has_more_work
    }

    fn add_records_to_enclave(&mut self, block_index: u64, records: Vec<KeyImageData>) {
        let num_records = records.len();

        let _info = retry(delay::Fixed::from_millis(5000), || {
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
                    counters::KEY_IMAGES_FETCHED_COUNT.inc_by(num_records as i64);
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
            "Added {} keyimage outs for {} into the enclave",
            num_records,
            block_index
        );
    }
}
