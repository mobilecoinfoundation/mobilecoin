// Copyright (c) 2018-2020 MobileCoin Inc.

//! Basic Watcher Node

use crate::watcher_db::WatcherDB;

use mc_api::conversions::block_num_to_s3block_path;
use mc_common::{
    logger::{log, Logger},
    HashMap,
};
use mc_ledger_db::Ledger;
use mc_ledger_sync::{ArchiveBlockData, ReqwestTransactionsFetcher};
use mc_transaction_core::BlockSignature;

use std::{
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    thread,
    time::Duration,
};

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
    pub fn num_blocks(&self) -> u64 {
        self.watcher_db.num_blocks().unwrap()
    }

    /// Sync blocks and collect signatures.
    pub fn sync_signatures(&self, start: u64, end: Option<u64>) {
        let mut block_index = start;
        loop {
            if let Some(max_blocks) = end {
                if block_index > max_blocks {
                    return;
                }
            }
            // Construct URL for the block we are trying to fetch.
            let filename = block_num_to_s3block_path(block_index)
                .into_os_string()
                .into_string()
                .unwrap();
            let mut archive_blocks: HashMap<String, ArchiveBlockData> = HashMap::default();
            let mut signatures: Vec<BlockSignature> = Vec::new();
            for src_url in self.transactions_fetcher.source_urls.iter() {
                let url = src_url.join(&filename).unwrap();

                // Try and get the block.
                log::debug!(
                    self.logger,
                    "Attempting to fetch block {} from {}",
                    block_index,
                    url
                );
                match self.transactions_fetcher.block_from_url(&url) {
                    Ok(archive_block) => {
                        archive_blocks.insert(src_url.to_string(), archive_block.clone());
                        log::debug!(
                            self.logger,
                            "Got archve block {:?} for block index ({:?})",
                            archive_block,
                            block_index,
                        );
                        if let Some(signature) = archive_block.signature {
                            signatures.push(signature)
                        }
                    }
                    Err(err) => {
                        log::debug!(
                            self.logger,
                            "Done fetching transactions for {} blocks ({:?})",
                            block_index,
                            err
                        );
                        return;
                    }
                }
            }
            println!(
                "\x1b[1;33m How many archive blocks for block ID? {}: {:?}\x1b[0m",
                block_index,
                archive_blocks.len()
            );
            println!(
                "\x1b[1;36m How many signatures for block ID? {}: {:?}\x1b[0m",
                block_index,
                signatures.len()
            );
            self.watcher_db
                .add_signatures(block_index, &signatures)
                .expect("Could not add signatures");

            block_index += 1;
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

            // See if we're currently behind. If we're not, poll to be sure.
            let is_behind = { watcher.num_blocks() < ledger.num_blocks().unwrap() };

            // Store current state and log.
            currently_behind.store(is_behind, Ordering::SeqCst);
            if is_behind {
                log::debug!(
                    logger,
                    "watcher sync is_behind: {:?} num blocks watcher: {:?} vs ledger: {:?}",
                    is_behind,
                    watcher.num_blocks(),
                    ledger.num_blocks().unwrap(),
                );
            }

            // Maybe sync, maybe wait and check again.
            if is_behind {
                let _ = watcher.sync_signatures(
                    watcher.num_blocks(),
                    Some(watcher.num_blocks() + MAX_BLOCKS_PER_SYNC_ITERATION as u64),
                );
            } else if !stop_requested.load(Ordering::SeqCst) {
                log::trace!(logger, "Sleeping, num_blocks = {}...", watcher.num_blocks());
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
