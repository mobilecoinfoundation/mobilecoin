// Copyright (c) 2018-2021 The MobileCoin Foundation

//! Basic Watcher Node

use crate::{
    error::{WatcherDBError, WatcherError},
    watcher_db::WatcherDB,
};

use mc_api::block_num_to_s3block_path;
use mc_common::{
    logger::{log, Logger},
    HashMap, HashSet,
};
use mc_ledger_db::Ledger;
use mc_ledger_sync::ReqwestTransactionsFetcher;

use std::{
    iter::FromIterator,
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
    store_block_data: bool,
    logger: Logger,
}

impl Watcher {
    /// Create a new Watcher.
    ///
    /// # Arguments
    /// * `watcher_db` - The backing database to use for storing and retreiving data
    /// * `transactions_fetcher` - The transaction fetcher used to fetch blocks from watched source
    ///   URLs
    /// * `store_block_data` - The fetched BlockData objects into the database
    /// * `logger` - Logger
    pub fn new(
        watcher_db: WatcherDB,
        transactions_fetcher: ReqwestTransactionsFetcher,
        store_block_data: bool,
        logger: Logger,
    ) -> Self {
        // Sanity check that the watcher db and transaction fetcher were initialized with the same
        // set of URLs.
        assert_eq!(
            HashSet::from_iter(transactions_fetcher.source_urls.iter()),
            HashSet::from_iter(
                watcher_db
                    .get_config_urls()
                    .expect("get_config_urls failed")
                    .iter()
            )
        );

        Self {
            transactions_fetcher: Arc::new(transactions_fetcher),
            watcher_db,
            store_block_data,
            logger,
        }
    }

    /// The lowest next block we need to try and sync.
    pub fn lowest_next_block_to_sync(&self) -> Result<u64, WatcherError> {
        let last_synced = self.watcher_db.last_synced_blocks()?;
        Ok(last_synced
            .values()
            .map(|last_synced_block| match last_synced_block {
                // If we haven't synced any blocks yet, the next one is block 0.
                None => 0,
                // If we synced a block, the next one is the next one.
                Some(index) => index + 1,
            })
            .min()
            .unwrap_or(0))
    }

    /// Sync a specific block from a url.
    pub fn sync_block(&self, src_url: &Url, block_index: u64) -> Result<(), WatcherError> {
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
            Ok(block_data) => {
                log::info!(
                    self.logger,
                    "Archive block retrieved for {:?} {:?}",
                    src_url,
                    block_index
                );

                if self.store_block_data {
                    match self.watcher_db.add_block_data(src_url, &block_data) {
                        Ok(()) => {}
                        Err(WatcherDBError::AlreadyExists) => {}
                        Err(err) => {
                            return Err(err.into());
                        }
                    };
                }

                if let Some(signature) = block_data.signature() {
                    self.watcher_db.add_block_signature(
                        src_url,
                        block_index,
                        signature.clone(),
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

    /// Sync blocks and collect signatures (and block data, when enabled).
    ///
    /// * `start` - starting block to sync.
    /// * `max_block_height` - the max block height to sync per archive url. If None, continue polling.
    ///
    /// Returns true if syncing has reached max_block_height, false if more blocks still need to be
    /// synced.
    pub fn sync_blocks(
        &self,
        start: u64,
        max_block_height: Option<u64>,
    ) -> Result<bool, WatcherError> {
        log::debug!(
            self.logger,
            "Now syncing signatures from {} to {:?}",
            start,
            max_block_height,
        );

        loop {
            // Get the last synced block for each URL we are tracking.
            let mut last_synced = self.watcher_db.last_synced_blocks()?;

            // Filter the list to only contain URLs we still need to sync from.
            if let Some(max_block_height) = max_block_height {
                last_synced.retain(|_url, opt_block_index| {
                    opt_block_index
                        .map(|block_index| block_index < max_block_height)
                        .unwrap_or(true)
                });
            }
            if last_synced.is_empty() {
                return Ok(true);
            }

            // Track whether sync failed - this catches cases where S3 is behind local ledger,
            // which could happen if your local ledger was synced previously from different nodes
            // than you are now watching. We track the sync failures so we can return control to the
            // polling thread rather than continuously loop in this method.
            let mut sync_failed: HashMap<Url, bool> = last_synced
                .iter()
                .map(|(url, _opt_block_index)| (url.clone(), false))
                .collect();

            for (src_url, opt_last_synced) in last_synced {
                let next_block_index = opt_last_synced
                    .map(|block_index| block_index + 1)
                    .unwrap_or(start);
                match self.sync_block(&src_url, next_block_index) {
                    Ok(()) => {}
                    Err(WatcherError::SyncFailed) => {
                        sync_failed.insert(src_url.clone(), true);
                    }
                    Err(e) => {
                        return Err(e);
                    }
                }
            }
            if sync_failed.values().all(|x| *x) {
                return Ok(false);
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
        store_block_data: bool,
        logger: Logger,
    ) -> Self {
        log::debug!(logger, "Creating watcher sync thread.");
        let watcher = Watcher::new(
            watcher_db,
            transactions_fetcher,
            store_block_data,
            logger.clone(),
        );

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
                .expect("Failed spawning WatcherSync thread"),
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

            let lowest_next_block_to_sync = watcher
                .lowest_next_block_to_sync()
                .expect("failed getting lowest next block to sync");
            let ledger_num_blocks = ledger.num_blocks().unwrap();
            // See if we're currently behind.
            let is_behind = { lowest_next_block_to_sync < ledger_num_blocks };
            log::debug!(
                logger,
                "Lowest next block to sync: {}, Ledger block height {}, is_behind {}",
                lowest_next_block_to_sync,
                ledger_num_blocks,
                is_behind
            );

            // Store current state and log.
            currently_behind.store(is_behind, Ordering::SeqCst);
            if is_behind {
                log::debug!(
                    logger,
                    "watcher sync is_behind: {:?} lowest next block to sync: {:?} vs ledger: {:?}",
                    is_behind,
                    lowest_next_block_to_sync,
                    ledger_num_blocks,
                );
            }

            // Maybe sync, maybe wait and check again.
            if is_behind {
                let max_blocks = std::cmp::min(
                    ledger_num_blocks - 1,
                    lowest_next_block_to_sync + MAX_BLOCKS_PER_SYNC_ITERATION as u64,
                );
                watcher
                    .sync_blocks(lowest_next_block_to_sync, Some(max_blocks))
                    .expect("Could not sync blocks");
            } else if !stop_requested.load(Ordering::SeqCst) {
                log::trace!(
                    logger,
                    "Sleeping, watcher blocks synced = {}...",
                    lowest_next_block_to_sync
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
