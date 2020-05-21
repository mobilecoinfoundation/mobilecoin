// Copyright (c) 2018-2020 MobileCoin Inc.

//! Basic Watcher Node

use crate::{error::WatcherError, watcher_db::WatcherDB};

use mc_api::conversions::block_num_to_s3block_path;
use mc_common::{
    logger::{log, Logger},
    HashMap,
};
use mc_ledger_db::Ledger;
use mc_ledger_sync::ReqwestTransactionsFetcher;

use std::{
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    thread,
    time::Duration,
};
use url::Url;

/// Watches multiple consensus validators and collects block signatures.
pub struct Watcher {
    transactions_fetcher: Arc<ReqwestTransactionsFetcher>,
    watcher_db: WatcherDB,
    logger: Logger,
}

impl Watcher {
    /// Create a new Watcher.
    pub fn new(
        watcher_db: WatcherDB,
        transactions_fetcher: ReqwestTransactionsFetcher,
        logger: Logger,
    ) -> Self {
        Self {
            transactions_fetcher: Arc::new(transactions_fetcher),
            watcher_db,
            logger,
        }
    }

    /// The number of blocks in the watcher db.
    pub fn min_synced(&self) -> Result<u64, WatcherError> {
        let last_synced = self.watcher_db.last_synced_blocks()?;
        Ok(last_synced.values().min().map_or(0, |x| *x))
    }

    /// Sync a signature from a url at a given block_index.
    pub fn sync_signature(&self, src_url: &Url, block_index: u64) -> Result<(), WatcherError> {
        let filename = block_num_to_s3block_path(block_index)
            .into_os_string()
            .into_string()
            .unwrap();
        let url = src_url.join(&filename)?;

        // Try and get the block.
        log::debug!(
            self.logger,
            "Attempting to fetch block {} from {}",
            block_index,
            url
        );
        match self.transactions_fetcher.block_from_url(&url) {
            Ok(archive_block) => {
                log::debug!(
                    self.logger,
                    "Archive block retrieved for {:?} {:?}",
                    src_url,
                    block_index
                );
                if let Some(signature) = archive_block.signature {
                    self.watcher_db.add_block_signature(
                        src_url,
                        block_index,
                        signature,
                        filename,
                    )?;
                } else {
                    self.watcher_db.update_last_synced(src_url, block_index)?;
                }
                Ok(())
            }
            Err(err) => {
                log::debug!(
                    self.logger,
                    "Could not sync block {} for url ({:?})",
                    block_index,
                    err
                );
                Err(WatcherError::SyncFailed)
            }
        }
    }

    /// Sync blocks and collect signatures.
    ///
    /// * `start` - starting block to sync.
    /// * `max_block_height` - the max block height to sync per archive url. If None, continue polling.
    pub fn sync_signatures(
        &self,
        start: u64,
        max_block_height: Option<u64>,
    ) -> Result<(), WatcherError> {
        log::debug!(
            self.logger,
            "Now syncing signatures from {} to {:?}",
            start,
            max_block_height,
        );

        loop {
            // Get the last synced block for each URL we are tracking.
            let mut last_synced: HashMap<String, u64> = self.watcher_db.last_synced_blocks()?;

            // Track whether sync failed - this catches cases where S3 is behind local ledger,
            // which could happen if your local ledger was synced previously from different nodes
            // than you are now watching. We track the sync failures so we can return control to the
            // polling thread rather than continuously loop in this method.
            let mut sync_failed: HashMap<String, bool> = self
                .transactions_fetcher
                .source_urls
                .iter()
                .map(|url| (url.as_str().to_string(), false))
                .collect();

            if let Some(max_block_height) = max_block_height {
                last_synced.retain(|_url, block_index| *block_index < max_block_height);
            }
            if last_synced.is_empty() {
                return Ok(());
            }
            // Construct URL for the block we are trying to fetch.
            for src_url in self.transactions_fetcher.source_urls.iter() {
                let url_key = src_url.as_str().to_string();
                let next_block_index = last_synced[&url_key] + 1;
                match self.sync_signature(&src_url, next_block_index) {
                    Ok(()) => {}
                    Err(WatcherError::SyncFailed) => {
                        sync_failed.insert(url_key, true);
                    }
                    Err(e) => {
                        return Err(e);
                    }
                }
            }
            if sync_failed.values().all(|x| *x) {
                return Ok(());
            }
        }
    }
}

/// Maximal number of blocks to attempt to sync at each loop iteration.
const MAX_BLOCKS_PER_SYNC_ITERATION: u32 = 10;

/// Syncs new ledger materials for the watcher when the local ledger
/// appends new blocks.
pub struct WatcherSyncThread {
    join_handle: Option<thread::JoinHandle<()>>,
    currently_behind: Arc<AtomicBool>,
    stop_requested: Arc<AtomicBool>,
}

impl WatcherSyncThread {
    /// Create a new watcher sync thread.
    pub fn new(
        watcher_db: WatcherDB,
        transactions_fetcher: ReqwestTransactionsFetcher,
        ledger: impl Ledger + 'static,
        poll_interval: Duration,
        logger: Logger,
    ) -> Self {
        log::debug!(logger, "Creating watcher sync thread.");
        let watcher = Watcher::new(watcher_db, transactions_fetcher, logger.clone());

        let currently_behind = Arc::new(AtomicBool::new(false));
        let stop_requested = Arc::new(AtomicBool::new(false));

        let thread_currently_behind = currently_behind.clone();
        let thread_stop_requested = stop_requested.clone();
        let join_handle = Some(
            thread::Builder::new()
                .name("WatcherSync".into())
                .spawn(move || {
                    Self::thread_entrypoint(
                        ledger,
                        watcher,
                        poll_interval,
                        thread_currently_behind,
                        thread_stop_requested,
                        logger,
                    );
                })
                .expect("Failed spawning LedgerSync thread"),
        );

        Self {
            join_handle,
            currently_behind,
            stop_requested,
        }
    }

    /// Stop the watcher sync thread.
    pub fn stop(&mut self) {
        self.stop_requested.store(true, Ordering::SeqCst);
        if let Some(thread) = self.join_handle.take() {
            thread.join().expect("WatcherSync thread join failed");
        }
    }

    /// Check whether the watcher DB is behind the ledger DB.
    pub fn is_behind(&self) -> bool {
        self.currently_behind.load(Ordering::SeqCst)
    }

    /// The entrypoint for the watcher sync thread.
    fn thread_entrypoint(
        ledger: impl Ledger,
        watcher: Watcher,
        poll_interval: Duration,
        currently_behind: Arc<AtomicBool>,
        stop_requested: Arc<AtomicBool>,
        logger: Logger,
    ) {
        log::debug!(logger, "WatcherSyncThread has started.");

        loop {
            if stop_requested.load(Ordering::SeqCst) {
                log::debug!(logger, "WatcherSyncThread stop requested.");
                break;
            }

            let min_synced = watcher.min_synced().unwrap();
            let ledger_num_blocks = ledger.num_blocks().unwrap();
            // See if we're currently behind.
            let is_behind = { min_synced < ledger_num_blocks };
            log::debug!(
                logger,
                "Minimum synced block {:?} Ledger block height {:?}, is_behind {:?}",
                min_synced,
                ledger_num_blocks,
                is_behind
            );

            // Store current state and log.
            currently_behind.store(is_behind, Ordering::SeqCst);
            if is_behind {
                log::debug!(
                    logger,
                    "watcher sync is_behind: {:?} num blocks watcher: {:?} vs ledger: {:?}",
                    is_behind,
                    min_synced,
                    ledger_num_blocks,
                );
            }

            // Maybe sync, maybe wait and check again.
            if is_behind {
                let max_blocks = std::cmp::min(
                    ledger_num_blocks - 1,
                    min_synced + MAX_BLOCKS_PER_SYNC_ITERATION as u64,
                );
                watcher
                    .sync_signatures(min_synced, Some(max_blocks))
                    .expect("Could not sync signatures");
            } else if !stop_requested.load(Ordering::SeqCst) {
                log::trace!(
                    logger,
                    "Sleeping, watcher blocks synced = {}...",
                    min_synced
                );
                std::thread::sleep(poll_interval);
            }
        }
    }
}

impl Drop for WatcherSyncThread {
    fn drop(&mut self) {
        self.stop();
    }
}
