// Copyright (c) 2018-2021 The MobileCoin Foundation

use crate::{controller::IngestController, error::IngestServiceError};
use mc_attest_net::RaClient;
use mc_common::logger::{log, Logger};
use mc_fog_recovery_db_iface::{RecoveryDb, ReportDb};
use mc_ledger_db::{Error as LedgerError, Ledger, LedgerDB};
use mc_sgx_report_cache_untrusted::REPORT_REFRESH_INTERVAL;
use mc_transaction_core::BlockIndex;
use mc_watcher::watcher_db::WatcherDB;
use std::{
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    thread::JoinHandle,
    time::{Duration, Instant},
};

/// The ingest worker is a thread responsible for driving the polling loop which
/// checks if there are new blocks in the ledger to be processed
pub struct IngestWorker {
    stop_requested: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl IngestWorker {
    /// Poll for new data every 10 ms
    const POLLING_FREQUENCY: Duration = Duration::from_millis(10);
    /// If a database invariant is violated, e.g. we get block but not block
    /// contents, it typically will not be fixed and so we won't be able to
    /// proceed. But bringing the server down is costly from ops POV because
    /// we will lose all the user rng's.
    ///
    /// So instead, if this happens, we log an error, and retry in 1s.
    /// This avoids logging at > 1hz when there is this error, which would be
    /// very spammy. But the retries are unlikely to eventually lead to
    /// progress. Another strategy might be for the server to enter a
    /// "paused" state and signal for intervention.
    const ERROR_RETRY_FREQUENCY: Duration = Duration::from_millis(1000);

    /// Create a new IngestWorker thread
    ///
    /// Arguments:
    /// * Controller for this ingest server
    /// * LedgerDB to read blocks from
    /// * WatcherDB to read block timestamps from
    /// * Logger to send log messages to
    ///
    /// Returns a freshly started IngestWorker thread handle
    pub fn new<
        R: RaClient + Send + Sync + 'static,
        DB: RecoveryDb + ReportDb + Clone + Send + Sync + 'static,
    >(
        controller: Arc<IngestController<R, DB>>,
        db: LedgerDB,
        watcher: WatcherDB,
        watcher_timeout: Duration,
        logger: Logger,
    ) -> Self
    where
        IngestServiceError: From<<DB as RecoveryDb>::Error>,
    {
        let stop_requested = Arc::new(AtomicBool::new(false));
        Self {
            stop_requested: stop_requested.clone(),
            thread: Some(std::thread::spawn(move || {
                let mut last_not_found_log: Option<LastNotFound> = None;
                loop {
                    let (next_block_index, is_idle) = controller.get_next_block_index();

                    if stop_requested.load(Ordering::SeqCst) {
                        log::info!(
                            logger,
                            "Stop Requested: Polling loop stopped at block number {}, is_idle {}",
                            next_block_index,
                            is_idle
                        );
                        break;
                    }

                    if is_idle {
                        std::thread::sleep(Self::POLLING_FREQUENCY);
                        continue;
                    }

                    match db.get_block_data(next_block_index) {
                        Err(LedgerError::NotFound) => {
                            if let Some(rec) = &mut last_not_found_log {
                                if rec.block_index == next_block_index {
                                    // Log at debug level every 1 min
                                    // This is mainly useful for debugging conformance tests, not
                                    // prod, which uses
                                    // prometheus metrics
                                    if rec.time.elapsed() > Duration::from_secs(60) {
                                        log::debug!(
                                            logger,
                                            "Waited 1 min for block {}",
                                            next_block_index
                                        );
                                        rec.time = Instant::now();
                                    }
                                } else {
                                    last_not_found_log = Some(LastNotFound::new(next_block_index));
                                }
                            } else {
                                last_not_found_log = Some(LastNotFound::new(next_block_index));
                            }
                            std::thread::sleep(Self::POLLING_FREQUENCY)
                        }
                        Err(e) => {
                            log::error!(
                                logger,
                                "Unexpected error when checking for block data {}: {:?}",
                                next_block_index,
                                e
                            );
                            std::thread::sleep(Self::ERROR_RETRY_FREQUENCY);
                        }
                        Ok(block_data) => {
                            last_not_found_log = None;
                            // If we were able to load a new block, update the ledger metrics. They
                            // won't get updated automatically since the block got appended by an
                            // external process (mobilecoind).
                            if let Err(err) = db.update_metrics() {
                                log::warn!(logger, "Failed updating ledger db metrics: {}", err);
                            }

                            // Get the timestamp for the block.
                            let timestamp =
                                watcher.poll_block_timestamp(next_block_index, watcher_timeout);

                            controller.process_next_block(
                                block_data.block(),
                                block_data.contents(),
                                timestamp,
                            );
                        }
                    }
                }
            })),
        }
    }
}

impl Drop for IngestWorker {
    fn drop(&mut self) {
        if let Some(thread) = self.thread.take() {
            self.stop_requested.store(true, Ordering::SeqCst);
            thread.join().expect("Could not join ingest worker thread")
        }
    }
}

// Helper struct: Keeps track of when we last logged about a block that was not
// found
struct LastNotFound {
    block_index: BlockIndex,
    time: Instant,
}

impl LastNotFound {
    pub fn new(block_index: BlockIndex) -> Self {
        Self {
            block_index,
            time: Instant::now(),
        }
    }
}

/// The peer checkup worker is a thread responsible for periodically checking up
/// on our peers, if we are active, and making sure they are functioning as
/// backups. This is a separate thread so that it can be on a time-based
/// schedule, so it will happen even if there are few blocks.
pub struct PeerCheckupWorker {
    stop_requested: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl PeerCheckupWorker {
    /// Create a new PeerCheckupWorker thread
    ///
    /// Arguments:
    /// * Controller for this ingest server
    /// * Period determining how often to checkup on a peer
    /// * Logger to send log messages to
    ///
    /// Returns a freshly started PeerCheckupWorker thread handle
    pub fn new<
        R: RaClient + Send + Sync + 'static,
        DB: RecoveryDb + ReportDb + Clone + Send + Sync + 'static,
    >(
        controller: Arc<IngestController<R, DB>>,
        peer_checkup_period: Duration,
        logger: Logger,
    ) -> Self
    where
        IngestServiceError: From<<DB as RecoveryDb>::Error>,
    {
        let stop_requested = Arc::new(AtomicBool::new(false));
        Self {
            stop_requested: stop_requested.clone(),
            thread: Some(std::thread::spawn(move || {
                log::debug!(logger, "Peer checkup thread started");

                let mut last_refreshed_at = Instant::now();

                loop {
                    if stop_requested.load(Ordering::SeqCst) {
                        log::debug!(logger, "Peer checkup thread stop requested.");
                        break;
                    }

                    let now = Instant::now();
                    if now - last_refreshed_at > peer_checkup_period {
                        log::info!(logger, "Peer checkup period exceeded, refreshing...");
                        controller.peer_checkup();
                        last_refreshed_at = now;
                    }

                    std::thread::sleep(Duration::from_secs(1));
                }
            })),
        }
    }
}

impl Drop for PeerCheckupWorker {
    fn drop(&mut self) {
        if let Some(thread) = self.thread.take() {
            self.stop_requested.store(true, Ordering::SeqCst);
            thread.join().expect("Could not join peer checkup thread");
        }
    }
}

/// The report cache worker is a thread responsible for periodically calling
/// update report cache. This is a separate thread so that it can be on a
/// time-based schedule, so it will happen even if there are few blocks.
pub struct ReportCacheWorker {
    stop_requested: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl ReportCacheWorker {
    /// Create a new ReportCacheWorker thread
    ///
    /// Arguments:
    /// * Controller for this ingest server
    /// * Logger to send log messages to
    ///
    /// Returns a freshly started ReportCacheWorker thread handle
    pub fn new<
        R: RaClient + Send + Sync + 'static,
        DB: RecoveryDb + ReportDb + Clone + Send + Sync + 'static,
    >(
        controller: Arc<IngestController<R, DB>>,
        logger: Logger,
    ) -> Self
    where
        IngestServiceError: From<<DB as RecoveryDb>::Error>,
    {
        let stop_requested = Arc::new(AtomicBool::new(false));
        Self {
            stop_requested: stop_requested.clone(),
            thread: Some(std::thread::spawn(move || {
                log::debug!(logger, "Report cache thread started");

                let mut last_refreshed_at = Instant::now();

                loop {
                    if stop_requested.load(Ordering::SeqCst) {
                        log::debug!(logger, "Report cache thread stop requested.");
                        break;
                    }

                    let now = Instant::now();
                    if now - last_refreshed_at > REPORT_REFRESH_INTERVAL {
                        log::info!(logger, "Report refresh interval exceeded, refreshing...");
                        match controller.update_enclave_report_cache() {
                            Ok(()) => {
                                last_refreshed_at = now;
                            }
                            Err(err) => {
                                log::error!(logger, "update_enclave_report_cache failed: {}", err);
                            }
                        }
                    }

                    std::thread::sleep(Duration::from_secs(1));
                }
            })),
        }
    }
}

impl Drop for ReportCacheWorker {
    fn drop(&mut self) {
        if let Some(thread) = self.thread.take() {
            self.stop_requested.store(true, Ordering::SeqCst);
            thread.join().expect("Could not join report cache thread");
        }
    }
}
