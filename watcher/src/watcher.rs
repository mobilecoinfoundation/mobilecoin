// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Basic Watcher Node

use crate::{
    error::{WatcherDBError, WatcherError},
    metrics::WatcherMetrics,
    watcher_db::WatcherDB,
};
use mc_api::block_num_to_s3block_path;
use mc_blockchain_types::{BlockData, BlockIndex};
use mc_common::logger::{log, Logger};
use mc_ledger_db::Ledger;
use mc_ledger_sync::ReqwestTransactionsFetcher;
use rayon::iter::{IntoParallelIterator, ParallelIterator};
use std::{
    collections::HashMap,
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
    /// A transaction fetcher per watched URL.
    // The reason we keep a transaction fetcher per url has to do with the pre-fetching and caching
    // mechanism implemented in ReqwestTransactionsFetcher: ReqwestTransactionsFetcher will try and
    // fetch the large merged-blocks and then try to hand out results from its cache. However, it
    // is oblivious as to which URL got used to cache the blocks. This behavior is suitable for
    // LedgerSyncService but in the watcher we want to ensure the blocks are fetched from a
    // specific URL. If we want to use the cache mechanism (which we do, since it cuts down sync
    // time significantlly) then the workaround is to have a ReqwestTransactionsFetcher that only
    // has a single source URL.
    transactions_fetcher_by_url: Arc<HashMap<Url, ReqwestTransactionsFetcher>>,
    watcher_db: WatcherDB,
    store_block_data: bool,
    logger: Logger,
    metrics: WatcherMetrics,
}

/// Result of sync loop
pub enum SyncResult {
    /// Reached max allowed blocks per iteration
    ReachedMaxBlocksPerIteration,

    /// All blocks have been synced
    AllBlocksSynced,

    /// Block syncing error
    BlockSyncError,
}

impl Watcher {
    /// Create a new Watcher.
    ///
    /// # Arguments
    /// * `watcher_db` - The backing database to use for storing and retreiving
    ///   data
    /// * `transactions_fetcher` - The transaction fetcher used to fetch blocks
    ///   from watched source URLs
    /// * `store_block_data` - The fetched BlockData objects into the database
    /// * `logger` - Logger
    pub fn new(
        watcher_db: WatcherDB,
        store_block_data: bool,
        logger: Logger,
    ) -> Result<Self, WatcherError> {
        let tx_source_urls = watcher_db.get_config_urls()?;

        let transactions_fetcher_by_url = Arc::new(
            tx_source_urls
                .into_iter()
                .map(|source_url| {
                    Ok((
                        source_url.clone(),
                        ReqwestTransactionsFetcher::new(
                            vec![source_url.to_string()],
                            logger.clone(),
                        )?,
                    ))
                })
                .collect::<Result<HashMap<_, _>, WatcherError>>()?,
        );

        let metrics = WatcherMetrics::new();

        Ok(Self {
            transactions_fetcher_by_url,
            watcher_db,
            store_block_data,
            logger,
            metrics,
        })
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

    /// Collect number of blocks synced per peer and ledger height (if
    /// available)
    pub fn collect_metrics(&self, ledger_height: Option<u64>) {
        let last_synced = self.watcher_db.last_synced_blocks().unwrap_or_default();
        self.metrics.collect_peer_blocks_synced(last_synced);
        if let Some(ledger_height) = ledger_height {
            self.metrics.set_ledger_height(ledger_height as i64);
        }
    }
    /// Sync blocks and collect signatures (and block data, when enabled).
    ///
    /// * `start` - starting block to sync.
    /// * `max_block_height` - max block height to sync to
    /// * `max_blocks_per_iteration` - max blocks to check for in a sync loop
    /// * `log_sync_failures` - log node syncing failures at error! level
    ///
    /// Returns true if syncing has reached max_block_height, false if more
    /// blocks still need to be synced.
    pub fn sync_blocks(
        &self,
        start: u64,
        max_block_height: Option<u64>,
        max_blocks_per_iteration: Option<usize>,
        log_sync_failures: bool,
    ) -> Result<SyncResult, WatcherError> {
        match max_block_height {
            None => {
                log::debug!(
                    self.logger,
                    "Now syncing signatures from {} to {:?}",
                    start,
                    max_block_height,
                );
            }
            Some(_) => {
                log::info!(
                    self.logger,
                    "Now syncing signatures from {} to {:?}",
                    start,
                    max_block_height,
                );
            }
        }

        let mut counter = 0usize;

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
                return Ok(SyncResult::AllBlocksSynced);
            }

            // Construct a map of src_url -> next block index we want to attempt to sync.
            let url_to_block_index: HashMap<Url, u64> = last_synced
                .iter()
                .map(|(src_url, opt_block_index)| {
                    (
                        src_url.clone(),
                        opt_block_index.map(|i| i + 1).unwrap_or(start),
                    )
                })
                .collect();

            // Attempt to fetch block data for all urls in parallel.
            let url_to_block_data_result =
                parallel_fetch_blocks(url_to_block_index, self.transactions_fetcher_by_url.clone());

            // Store data for each successfully synced blocked. Track on whether any of the
            // sources was able to produce block data. If so, more data might be
            // available.
            let mut had_success = false;

            for (src_url, (block_index, block_data_result)) in url_to_block_data_result {
                match block_data_result {
                    Ok(block_data) => {
                        log::info!(
                            self.logger,
                            "Archive block retrieved for {} {}",
                            src_url,
                            block_index
                        );
                        if self.store_block_data {
                            match self.watcher_db.add_block_data(&src_url, &block_data) {
                                Ok(()) => {}
                                Err(WatcherDBError::AlreadyExists) => {}
                                Err(err) => Err(err)?,
                            };
                        }

                        if let Some(signature) = block_data.signature() {
                            let filename = block_num_to_s3block_path(block_index)
                                .into_os_string()
                                .into_string()
                                .unwrap();
                            self.watcher_db.add_block_signature(
                                &src_url,
                                block_index,
                                signature.clone(),
                                filename,
                            )?;
                        } else {
                            self.watcher_db.update_last_synced(&src_url, block_index)?;
                        }

                        had_success = true;
                    }

                    Err(err) => {
                        if log_sync_failures {
                            log::error!(
                                self.logger,
                                "Could not sync block {} for url ({:?})",
                                block_index,
                                err
                            );
                        } else {
                            log::debug!(
                                self.logger,
                                "Could not sync block {} for url ({:?})",
                                block_index,
                                err
                            );
                        }
                    }
                }
            }

            // If nothing succeeded, maybe we are synced all the way through or something
            // else is wrong.
            if !had_success {
                return Ok(SyncResult::BlockSyncError);
            }

            // If iteration limit was specified, check to see if it's been reached
            if let Some(max_blocks_per_iteration) = max_blocks_per_iteration {
                counter += 1;
                if counter > max_blocks_per_iteration {
                    log::debug!(
                        self.logger,
                        "reached max iteration limit of {} blocks before fully syncing nodes",
                        max_blocks_per_iteration,
                    );
                    return Ok(SyncResult::ReachedMaxBlocksPerIteration);
                }
            }
        }
    }
}

/// Given a map of block indexes per source URL and a map of transaction
/// fetchers per source URL, perform a parallel fetch of each of the blocks and
/// return the result.
fn parallel_fetch_blocks(
    url_to_block_index: HashMap<Url, BlockIndex>,
    transactions_fetcher_by_url: Arc<HashMap<Url, ReqwestTransactionsFetcher>>,
) -> HashMap<Url, (u64, Result<BlockData, WatcherError>)> {
    url_to_block_index
        .into_par_iter()
        .map(|(src_url, block_index)| {
            let block_fetch_result = transactions_fetcher_by_url
                .get(&src_url)
                .ok_or_else(|| WatcherError::UnknownTxSourceUrl(src_url.to_string()))
                .and_then(|transactions_fetcher| {
                    assert_eq!(transactions_fetcher.source_urls, vec![src_url.clone()]);

                    transactions_fetcher
                        .get_block_data_by_index(block_index, None)
                        .map_err(WatcherError::from)
                });

            (src_url, (block_index, block_fetch_result))
        })
        .collect()
}

/// Maximal number of blocks to attempt to sync at each loop iteration.
const MAX_BLOCKS_PER_SYNC_ITERATION: usize = 1000;

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
        ledger: impl Ledger + 'static,
        poll_interval: Duration,
        store_block_data: bool,
        logger: Logger,
    ) -> Result<Self, WatcherError> {
        log::debug!(logger, "Creating watcher sync thread.");
        let watcher = Watcher::new(watcher_db, store_block_data, logger.clone())?;

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

        Ok(Self {
            join_handle,
            currently_behind,
            stop_requested,
        })
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
                let sync_result = watcher
                    .sync_blocks(
                        lowest_next_block_to_sync,
                        Some(ledger_num_blocks - 1),
                        Some(MAX_BLOCKS_PER_SYNC_ITERATION),
                        true,
                    )
                    .expect("Could not sync blocks");

                // Collect blocks synced so far vs. ledger height
                watcher.collect_metrics(Some(ledger_num_blocks));

                // Pause for a second if a node is having trouble
                if let SyncResult::BlockSyncError = sync_result {
                    log::trace!(
                        logger,
                        "Sleeping due to sync error, lowest watcher block synced = {}... ",
                        lowest_next_block_to_sync
                    );
                    std::thread::sleep(poll_interval);
                }
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
