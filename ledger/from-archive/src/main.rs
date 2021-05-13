// Copyright (c) 2018-2021 The MobileCoin Foundation

#![feature(external_doc)]
#![doc(include = "../README.md")]
#![forbid(unsafe_code)]

mod config;

use config::LedgerFromArchiveConfig;
use mc_common::logger::{create_app_logger, log, Logger, o};
use mc_ledger_db::{Ledger, LedgerDB};
use mc_ledger_sync::ReqwestTransactionsFetcher;
use mc_transaction_core::{BlockData, BlockIndex};
use structopt::StructOpt;
use std::{
    collections::{BTreeMap},
    sync::{
        Arc, Condvar, Mutex,
    },
    time::{Duration, Instant},
};

/// Maximal amount of concurrent get_block_contents calls to allow.
const MAX_CONCURRENT_GET_BLOCK_CONTENTS_CALLS: usize = 50;

fn main() {
    mc_common::setup_panic_handler();
    let (logger, _global_logger_guard) = create_app_logger(o!());

    let config = LedgerFromArchiveConfig::from_args();

    let transactions_fetcher =
        Arc::new(ReqwestTransactionsFetcher::new(config.tx_source_urls.clone(), logger.clone())
            .expect("Failed creating ReqwestTransactionsFetcher"));

    log::info!(logger, "Creating local ledger at {:?}", config.ledger_db);
    // Open LedgerDB
    LedgerDB::create(&config.ledger_db).expect("Could not create ledger_db");
    let mut local_ledger = LedgerDB::open(&config.ledger_db).expect("Failed creating LedgerDB");

    // Sync Origin Block
    log::info!(logger, "Getting origin block");
    let block_data = transactions_fetcher
        .get_origin_block_and_transactions()
        .expect("Could not retrieve origin block");
    log::info!(logger, "Appending origin block to local ledger");
    local_ledger
        .append_block(
            block_data.block(),
            block_data.contents(),
            block_data.signature().clone(),
        )
        .expect("Could not append origin block to ledger");

    let mut start = 1;
    loop {
        let end = start + config.block_chunk_size;
        if let Some(block_limit) = config.num_blocks {
            if start >= block_limit {
                log::info!(
                    logger,
                    "Done fetching transactions for {} blocks",
                    start,
                );
                return;
            }
        }
        log::info!(logger, "Getting block contents for {}-{}", start, end);
        let block_map = get_block_contents(transactions_fetcher.clone(), start.clone(), end, std::time::Duration::from_secs(1), &logger);
        log::info!(logger, "Got block contents. Now appending to ledger");
        for (block_index, block_data_opt) in block_map.iter() {
            if let Some(block_data) = block_data_opt {
                local_ledger.append_block(&block_data.block(), &block_data.contents(), block_data.signature().clone()).unwrap();
            } else {
                log::warn!(logger, "No block data for index {}", block_index);
            }
        }
        start = end;
    }
}

/// Gets all transactions for a range of block indices.
///
/// # Arguments
/// * `transactions_fetcher` - The mechanism used for fetching transaction
///   contents for a given
/// block.
/// * `block_start` - Start index
/// * `block_end` - End index
/// * `timeout` - Overall request timeout.
///
/// Peers are queried concurrently. Currently, this method will run indefinitely
/// until all transactions have been retrieved.
fn get_block_contents(
    transactions_fetcher: Arc<ReqwestTransactionsFetcher>,
    block_start: u64,
    block_end: u64,
    timeout: Duration,
    logger: &Logger,
) -> BTreeMap<BlockIndex, Option<BlockData>> {
    type ResultsMap = BTreeMap<BlockIndex, Option<BlockData>>;

    enum Msg {
        FetchBlock {
            // Block we are trying to fetch transactions for.
            block_index: u64,

            // How many attempts have we made so far (this is used for calculating retry delays).
            num_attempts: u64,
        },
        Stop,
    }

    // The channel is going to hold the list of pending blocks we still need to get
    // transactions for.
    let range = (block_end - block_start) as usize;
    let (sender, receiver) = crossbeam_channel::bounded(range.clone());
    for block_index in block_start..block_end {
        sender
            .send(Msg::FetchBlock {
                block_index,
                num_attempts: 0,
            })
            .expect("failed sending to channel");
    }

    let results_and_condvar = Arc::new((Mutex::new(ResultsMap::new()), Condvar::new()));
    let deadline = Instant::now() + timeout;

    // Spawn worker threads.
    let mut thread_handles = Vec::new();

    let num_workers = std::cmp::min(MAX_CONCURRENT_GET_BLOCK_CONTENTS_CALLS, range as usize);
    for worker_num in 0..num_workers {
        let thread_results_and_condvar = results_and_condvar.clone();
        let thread_sender = sender.clone();
        let thread_receiver = receiver.clone();
        let thread_logger = logger.clone();
        let thread_transactions_fetcher = transactions_fetcher.clone();

        let thread_handle = std::thread::Builder::new()
            .name(format!("GetTxs:{}", worker_num))
            .spawn(move || {
                let &(ref lock, ref condvar) = &*thread_results_and_condvar;

                for msg in thread_receiver.iter() {
                    match msg {
                        Msg::FetchBlock {
                            block_index,
                            num_attempts,
                        } => {
                            // Check for timeout.
                            if std::time::Instant::now() > deadline {
                                log::error!(
                                    thread_logger,
                                    "Worker {} giving up on block {}: deadline exceeded",
                                    worker_num,
                                    block_index,
                                );

                                let mut results = lock.lock().expect("mutex poisoned");
                                results.insert(block_index.clone(), None);
                                condvar.notify_one();
                                continue;
                            }

                            // Try and get contents of this block.
                            log::trace!(
                                thread_logger,
                                "Worker {} attempting block {}",
                                worker_num,
                                block_index
                            );

                            match thread_transactions_fetcher
                                .get_block_data_by_index(block_index, None)
                                {
                                Ok(block_data) => {
                                    // Log
                                    log::trace!(
                                        thread_logger,
                                        "Worker {} got contents for block {}",
                                        worker_num,
                                        block_index
                                    );

                                    // passing the actual block and not just a block index.
                                    let mut results = lock.lock().expect("mutex poisoned");
                                    let old_result = results
                                        .insert(block_index.clone(), Some(block_data.clone()));

                                    // We should encounter each blocks index only once.
                                    assert!(old_result.is_none());

                                    // Signal condition variable to check if maybe we're done.
                                    condvar.notify_one();
                                }

                                Err(err) => {
                                    // Log
                                    log::info!(
                                        thread_logger,
                                        "Worker {} failed getting transactions for block {}: {}",
                                        worker_num,
                                        block_index,
                                        err
                                    );

                                    // Sleep, with a linearly increasing delay. This prevents
                                    // endless retries
                                    // as long as the deadline is not exceeded.
                                    std::thread::sleep(std::time::Duration::from_secs(num_attempts + 1));

                                    // Put back to queue for a retry
                                    thread_sender
                                        .send(Msg::FetchBlock {
                                            block_index,
                                            num_attempts: num_attempts + 1,
                                        })
                                        .expect("failed sending to channel");
                                }
                            }
                        }
                        Msg::Stop => {
                            return;
                        }
                    }
                }
            })
            .expect("Failed spawning GetBlocks thread!");

        thread_handles.push(thread_handle);
    }

    // Wait until we get all results, or we timeout. Note that timeout checking is
    // handled inside the worker threads.
    log::trace!(logger, "Waiting on {} results", range);
    let &(ref lock, ref condvar) = &*results_and_condvar;
    let results = condvar
        .wait_while(lock.lock().unwrap(), |ref mut results| {
            results.len() != range.clone()
        })
        .expect("waiting on condvar failed");

    // Sanity - we will only get here when results.len() == blocks.len(), which only
    // happens when everything in the queue was proceesed.
    assert!(receiver.is_empty());

    // Tell all threads to stop.

    for _ in 0..range {
        sender.send(Msg::Stop).expect("failed sending to channel");
    }

    // Wait for all threads to stop
    log::trace!(logger, "Joining worker threads...");
    for thread_handle in thread_handles.into_iter() {
        if let Err(err) = thread_handle.join() {
            log::error!(
                logger,
                "Failed joining get_transactions worker thread: {:?}",
                err
            );
        }
    }

    // Return results.
    results.clone()
}