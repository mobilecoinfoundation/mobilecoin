// Copyright (c) 2018-2023 The MobileCoin Foundation

//! Manages ledger block scanning for mobilecoind monitors.
//!
//! The sync code creates a pool of worker threads, and a main thread to hand
//! off tasks to the worker threads over a crossbeam channel. Each task is a
//! request to sync block data for a given monitor id. Each task is limited to a
//! pre-defined amount of blocks - this is useful when the amount of monitors
//! exceeds the amount of working threads as it ensures monitors are processed
//! concurrently.
//! The main thread periodically queries the database for all currently known
//! monitor ids, and submits new jobs into the queue for each monitor not
//! currently queued. In order to prevent duplicate queueing, the code also
//! keeps track of the list of already-queued monitor ids inside a hashset that
//! is shared with the worker threads. When a worker thread is finished with a
//! given monitor id, it removes it from the hashset, which in turns allows the
//! main thread to queue it again once the polling interval is exceeded. Since
//! the worker thread processes blocks in chunks, it is possible that not all
//! available blocks gets processed at once. When that happens, instead of
//! removing the monitor id from the hashset, it would be placed back into the
//! queue to be picked up by the next available worker thread.

use crate::{
    database::Database,
    error::Error,
    monitor_store::{MonitorData, MonitorId},
    subaddress_store::SubaddressSPKId,
    utxo_store::UnspentTxOut,
};
use mc_common::{
    logger::{log, Logger},
    HashSet,
};
use mc_crypto_keys::RistrettoPublic;
use mc_ledger_db::{Ledger, LedgerDB};
use mc_transaction_core::{
    get_tx_out_shared_secret,
    onetime_keys::{recover_onetime_private_key, recover_public_subaddress_spend_key},
    ring_signature::KeyImage,
    tx::TxOut,
};
use rayon::iter::{IntoParallelIterator, ParallelIterator};
use std::{
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    thread,
};

///  The maximal number of blocks a worker thread would process at once.
const MAX_BLOCKS_PROCESSING_CHUNK_SIZE: usize = 5;

/// Message type the our crossbeam channel used to communicate with the worker
/// thread pull.
enum SyncMsg {
    SyncMonitor(MonitorId),
    Stop,
}

/// Possible return values for the `sync_monitor` function.
#[derive(Debug, Eq, PartialEq)]
enum SyncMonitorOk {
    // No more blocks are currently available for processing.
    NoMoreBlocks,

    // More blocks might be available.
    MoreBlocksPotentiallyAvailable,
}

/// Sync thread - holds objects needed to cleanly terminate the sync thread.
pub struct SyncThread {
    /// The main sync thread handle.
    join_handle: Option<thread::JoinHandle<()>>,

    /// Stop trigger, used to signal the thread to reminate.
    stop_requested: Arc<AtomicBool>,
}

impl SyncThread {
    pub fn start(
        ledger_db: LedgerDB,
        mobilecoind_db: Database,
        num_workers: Option<usize>,
        logger: Logger,
    ) -> Self {
        // Queue for sending jobs to our worker threads.
        let (sender, receiver) = crossbeam_channel::unbounded::<SyncMsg>();

        // A hashset to keep track of which MonitorIds were already sent to the queue,
        // preventing them from being sent again until they are processed.
        let queued_monitor_ids = Arc::new(Mutex::new(HashSet::<MonitorId>::default()));

        // Create worker threads.
        let mut worker_join_handles = Vec::new();

        let num_workers = num_workers.unwrap_or_else(num_cpus::get);

        for idx in 0..num_workers {
            let thread_ledger_db = ledger_db.clone();
            let thread_mobilecoind_db = mobilecoind_db.clone();
            let thread_sender = sender.clone();
            let thread_receiver = receiver.clone();
            let thread_queued_monitor_ids = queued_monitor_ids.clone();
            let thread_logger = logger.clone();
            let join_handle = thread::Builder::new()
                .name(format!("sync_worker_{idx}"))
                .spawn(move || {
                    sync_thread_entry_point(
                        thread_ledger_db,
                        thread_mobilecoind_db,
                        thread_sender,
                        thread_receiver,
                        thread_queued_monitor_ids,
                        num_workers,
                        thread_logger,
                    );
                })
                .expect("failed starting sync worker thread");

            worker_join_handles.push(join_handle);
        }

        // Start the main sync thread.
        // This thread constantly monitors the list of monitor ids we are aware of,
        // and adds new one into our cyclic queue.
        let stop_requested = Arc::new(AtomicBool::new(false));
        let thread_stop_requested = stop_requested.clone();

        let join_handle = Some(
            thread::Builder::new()
                .name("sync".to_string())
                .spawn(move || {
                    log::debug!(logger, "Syncthread started.");

                    loop {
                        if thread_stop_requested.load(Ordering::SeqCst) {
                            log::debug!(logger, "SyncThread stop requested.");
                            break;
                        }

                        // Get the current number of blocks in ledger.
                        let num_blocks = ledger_db
                            .num_blocks()
                            .expect("failed getting number of blocks");

                        // A flag to track whether we sent a message to our work queue.
                        // If we sent a message, that means new blocks have arrived and we can skip
                        // sleeping. If no new blocks arrived, and we
                        // haven't had to sync any monitors, we can sleep for
                        // a bit so that we do not use 100% cpu.
                        let mut message_sent = false;

                        // Go over our list of monitors and see which one needs to process these
                        // blocks.
                        for (monitor_id, monitor_data) in mobilecoind_db
                            .get_monitor_map()
                            .expect("failed getting monitor map")
                        {
                            // If there are no new blocks for this monitor, don't do anything.
                            if monitor_data.next_block >= num_blocks {
                                continue;
                            }

                            let mut queued_monitor_ids =
                                queued_monitor_ids.lock().expect("mutex poisoned");
                            if !queued_monitor_ids.insert(monitor_id) {
                                // Already queued, no need to add again to queue at this point.
                                log::trace!(logger, "{}: skipping, already queued", monitor_id);
                                continue;
                            }

                            // This monitor has blocks to process, put it in the queue.
                            log::debug!(
                                logger,
                                "sync thread noticed monitor {} needs syncing",
                                monitor_id,
                            );
                            sender
                                .send(SyncMsg::SyncMonitor(monitor_id))
                                .expect("failed sending to queue");
                            message_sent = true;
                        }

                        // If we saw no activity, sleep for a bit.
                        if !message_sent {
                            thread::sleep(std::time::Duration::from_secs(1));
                        }
                    }

                    log::trace!(
                        logger,
                        "SyncThread attempting to stop all worker threads..."
                    );
                    for _ in 0..worker_join_handles.len() {
                        sender
                            .send(SyncMsg::Stop)
                            .expect("failed sending stop message");
                    }

                    let num_workers = worker_join_handles.len();
                    for (i, join_handle) in worker_join_handles.into_iter().enumerate() {
                        log::trace!(logger, "Joining worker {}/{}", i + 1, num_workers);
                        join_handle.join().expect("Failed joining worker thread");
                        log::debug!(
                            logger,
                            "SyncThread worker {}/{} stopped",
                            i + 1,
                            num_workers
                        );
                    }

                    log::debug!(logger, "SyncThread stopped.");
                })
                .expect("failed starting main sync thread"),
        );

        Self {
            join_handle,
            stop_requested,
        }
    }

    pub fn stop(&mut self) {
        self.stop_requested.store(true, Ordering::SeqCst);
        if let Some(join_handle) = self.join_handle.take() {
            join_handle.join().expect("SyncThread join failed");
        }
    }
}

impl Drop for SyncThread {
    fn drop(&mut self) {
        self.stop();
    }
}
/// The entry point of a sync worker thread that processes queue messages.
fn sync_thread_entry_point(
    ledger_db: LedgerDB,
    mobilecoind_db: Database,
    sender: crossbeam_channel::Sender<SyncMsg>,
    receiver: crossbeam_channel::Receiver<SyncMsg>,
    queued_monitor_ids: Arc<Mutex<HashSet<MonitorId>>>,
    num_workers: usize,
    logger: Logger,
) {
    for msg in receiver.iter() {
        match msg {
            SyncMsg::SyncMonitor(monitor_id) => {
                match sync_monitor_parallel(
                    &ledger_db,
                    &mobilecoind_db,
                    &monitor_id,
                    num_workers,
                    &logger,
                ) {
                    // Success - No more blocks are currently available.
                    Ok(SyncMonitorOk::NoMoreBlocks) => {
                        // Remove the monitor id from the list of queued ones so that the main
                        // thread could queue it again if necessary.
                        log::trace!(logger, "{}: sync_monitor returned NoMoreBlocks", monitor_id);

                        let mut queued_monitor_ids =
                            queued_monitor_ids.lock().expect("mutex poisoned");
                        queued_monitor_ids.remove(&monitor_id);
                    }

                    // Success - more blocks might be available.
                    Ok(SyncMonitorOk::MoreBlocksPotentiallyAvailable) => {
                        // Put the monitor id back in the queue for further processing.
                        log::trace!(
                            logger,
                            "{}: sync_monitor returned MoreBlocksPotentiallyAvailable",
                            monitor_id,
                        );

                        sender
                            .send(SyncMsg::SyncMonitor(monitor_id))
                            .expect("failed sending to channel");
                    }

                    // Errors that are acceptable - nothing to do.
                    Err(Error::MonitorIdNotFound) => {}

                    // Other errors - log.
                    Err(err) => {
                        log::error!(logger, "error syncing monitor {}: {:?}", monitor_id, err);
                    }
                };
            }

            SyncMsg::Stop => {
                break;
            }
        }
    }
}

/// Sync a single monitor, spawning parallel jobs to perform block scanning if
/// it is many blocks behind. This allows us to use all the CPU cores scanning
/// even when we only have a single monitor to work on, and all the blocks are
/// pretty small (only 2 or 3 UTXOs), which is a very common configuration and
/// situation. First, we test how far behind the monitor is. When the monitor is
/// close to caught up, we fallback to sync_monitor_sequential.
fn sync_monitor_parallel(
    ledger_db: &LedgerDB,
    mobilecoind_db: &Database,
    monitor_id: &MonitorId,
    num_workers: usize,
    logger: &Logger,
) -> Result<SyncMonitorOk, Error> {
    let monitor_data = mobilecoind_db.get_monitor_data(monitor_id)?;
    let num_blocks = ledger_db.num_blocks()?;

    // If we cannot hope to work on num_workers blocks in parallel for this montior,
    // then we are pretty close to the end, let's fall back to
    // sync_monitor_sequential. Otherwise, we should be able to get num_workers
    // blocks and work on them in parallel.
    if monitor_data.next_block + num_workers as u64 >= num_blocks {
        return sync_monitor_sequential(ledger_db, mobilecoind_db, monitor_id, logger);
    }

    // Each worker will try to call
    // ledger_db.get_block_contents(monitor_data.next_block + worker_idx)
    // and then
    // match_tx_outs_into_utxos
    // in parallel.
    //
    // At the end we collect the results and add them to the database in order,
    // because the database needs that to be done sequentially. But the scanning
    // is the slow part here, so this is fine.
    let parallel_results = (0..num_workers)
        .into_par_iter()
        .map(
            |worker_idx| -> Result<(Vec<UnspentTxOut>, Vec<KeyImage>), Error> {
                // We don't expect to get Error::NotFound here, since we earlier tested
                // ledger_db.num_blocks(). The other error cases are not common
                // either.
                let block_idx = monitor_data.next_block + worker_idx as u64;
                let block_contents = match ledger_db.get_block_contents(block_idx) {
                    Ok(block_contents) => block_contents,
                    // Note: mc_ledger_db::Error::NotFound is being handled like any other error
                    // here, since it really isn't expected.
                    Err(err) => {
                        return Err(err.into());
                    }
                };

                log::trace!(
                    logger,
                    "processing {} outputs and {} key images from block {} for monitor_id {}",
                    block_contents.outputs.len(),
                    block_contents.key_images.len(),
                    block_idx,
                    monitor_id,
                );

                // Match tx outs into UTXOs.
                let utxos = match_tx_outs_into_utxos(
                    mobilecoind_db,
                    &block_contents.outputs,
                    monitor_id,
                    &monitor_data,
                    logger,
                )?;

                Ok((utxos, block_contents.key_images))
            },
        )
        .collect::<Vec<Result<(Vec<UnspentTxOut>, Vec<KeyImage>), Error>>>();

    // For diagnostics, we want to keep track of which workers were successful.
    // Usually it should be all of them, but if sometimes a worker in the middle
    // fails and later ones don't, that will harm performance.
    let worker_successes = parallel_results
        .iter()
        .map(|result| if result.is_ok() { 1 } else { 0 })
        .collect::<Vec<usize>>();

    // Now add everything to the database
    for (worker_idx, result) in parallel_results.into_iter().enumerate() {
        match result {
            Ok((utxos, key_images)) => {
                // Update database.
                mobilecoind_db.block_processed(
                    monitor_id,
                    monitor_data.next_block + worker_idx as u64,
                    &utxos,
                    &key_images,
                )?;
            }
            Err(err) => {
                // Unfortunately, we have to abandon any work that could have been accomplished
                // successfully by the threads after this one. To track this,
                // we'll log a warning about work being abandoned.
                let abandoned_successes: usize = worker_successes.iter().skip(worker_idx + 1).sum();
                if abandoned_successes > 0 {
                    log::warn!(logger, "Due to an error while parallel scanning, had to abandon {} successful block scanning results", abandoned_successes);
                }
                return Err(err);
            }
        }
    }

    Ok(SyncMonitorOk::MoreBlocksPotentiallyAvailable)
}

/// Sync a single monitor, working on at most MAX_BLOCKS_PROCESSING_CHUNK_SIZE
/// before moving on. Works on blocks sequentially.
fn sync_monitor_sequential(
    ledger_db: &LedgerDB,
    mobilecoind_db: &Database,
    monitor_id: &MonitorId,
    logger: &Logger,
) -> Result<SyncMonitorOk, Error> {
    for _ in 0..MAX_BLOCKS_PROCESSING_CHUNK_SIZE {
        // Get the monitor data. If it is no longer available, the monitor has been
        // removed and we can simply return.
        let monitor_data = mobilecoind_db.get_monitor_data(monitor_id)?;
        let block_contents = match ledger_db.get_block_contents(monitor_data.next_block) {
            Ok(block_contents) => block_contents,
            Err(mc_ledger_db::Error::NotFound) => {
                return Ok(SyncMonitorOk::NoMoreBlocks);
            }
            Err(err) => {
                return Err(err.into());
            }
        };

        log::trace!(
            logger,
            "processing {} outputs and {} key images from block {} for monitor_id {}",
            block_contents.outputs.len(),
            block_contents.key_images.len(),
            monitor_data.next_block,
            monitor_id,
        );

        // Match tx outs into UTXOs.
        let utxos = match_tx_outs_into_utxos(
            mobilecoind_db,
            &block_contents.outputs,
            monitor_id,
            &monitor_data,
            logger,
        )?;

        // Update database.
        mobilecoind_db.block_processed(
            monitor_id,
            monitor_data.next_block,
            &utxos,
            &block_contents.key_images,
        )?;
    }

    Ok(SyncMonitorOk::MoreBlocksPotentiallyAvailable)
}

/// Helper function for matching a list of TxOuts to a given monitor.
fn match_tx_outs_into_utxos(
    mobilecoind_db: &Database,
    outputs: &[TxOut],
    monitor_id: &MonitorId,
    monitor_data: &MonitorData,
    logger: &Logger,
) -> Result<Vec<UnspentTxOut>, Error> {
    let account_key = &monitor_data.account_key;
    // Iterate over each output and filter the results using a parallel iterator.
    let results: Result<Vec<UnspentTxOut>, Error> = outputs
        .into_par_iter()
        .filter_map(|tx_out| {
            // Convert target and public keys to RistrettoPublic type.
            let tx_out_target_key = RistrettoPublic::try_from(&tx_out.target_key).ok()?;
            let tx_public_key = RistrettoPublic::try_from(&tx_out.public_key).ok()?;

            // Generate subaddress spend public key for tx_out.
            let subaddress_spk = SubaddressSPKId::from(&recover_public_subaddress_spend_key(
                account_key.view_private_key(),
                &tx_out_target_key,
                &tx_public_key,
            ));

            // Search the database for the subaddress ID that matches the generated key.
            let subaddress_id = match mobilecoind_db.get_subaddress_id_by_spk(&subaddress_spk) {
                Ok(data) => {
                    // Log the index and monitor ID of the matched subaddress.
                    log::trace!(
                        logger,
                        "matched subaddress index {} for monitor_id {}",
                        data.index,
                        data.monitor_id,
                    );

                    data
                }
                Err(Error::SubaddressSPKNotFound) => return None,
                Err(e) => return Some(Err(e)),
            };

            // Check that the matched subaddress belongs to the current monitor.
            assert_eq!(monitor_id, &subaddress_id.monitor_id);

            // Generate the shared secret between the subaddress and output public key.
            let shared_secret =
                get_tx_out_shared_secret(account_key.view_private_key(), &tx_public_key);

            // Get the amount and blinding factor for the output.
            let (amount, _blinding) = tx_out
                .get_masked_amount()
                .expect("missing masked amount")
                .get_value(&shared_secret)
                .expect("Malformed amount"); // TODO

            // Recover the onetime private key using the account and subaddress spend
            // private keys.
            let onetime_private_key = recover_onetime_private_key(
                &tx_public_key,
                account_key.view_private_key(),
                &account_key.subaddress_spend_private(subaddress_id.index),
            );

            // Generate the key image from the onetime private key.
            let key_image = KeyImage::from(&onetime_private_key);

            // Construct a new unspent transaction output.
            Some(Ok(UnspentTxOut {
                tx_out: tx_out.clone(),
                subaddress_index: subaddress_id.index,
                key_image,
                value: amount.value,
                attempted_spend_height: 0,
                attempted_spend_tombstone: 0,
                token_id: *amount.token_id,
            }))
        })
        .collect();

    results
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{
        monitor_store::MonitorData,
        test_utils::{
            self, add_block_to_ledger, add_txos_to_ledger, get_test_databases, BlockVersion,
            DEFAULT_PER_RECIPIENT_AMOUNT,
        },
    };
    use mc_account_keys::{AccountKey, PublicAddress, DEFAULT_SUBADDRESS_INDEX};
    use mc_common::logger::{test_with_logger, Logger};
    use mc_fog_report_validation_test_utils::MockFogResolver;
    use mc_transaction_builder::{EmptyMemoBuilder, TransactionBuilder, TxOutContext};
    use mc_transaction_core::{tokens::Mob, tx::TxOut, Amount, Token};
    use rand::{rngs::StdRng, SeedableRng};
    use std::time::Instant;

    #[test_with_logger]
    fn test_sync_monitor(logger: Logger) {
        let mut rng: StdRng = SeedableRng::from_seed([98u8; 32]);

        let account_keys: Vec<_> = (0..5).map(|_i| AccountKey::random(&mut rng)).collect();

        let data = MonitorData::new(
            account_keys[0].clone(),
            DEFAULT_SUBADDRESS_INDEX, // first subaddress
            5,                        // number of subaddresses
            0,                        // first block
            "",                       // name
        )
        .unwrap();

        let monitor_id = MonitorId::from(&data);

        let recipients: Vec<PublicAddress> = account_keys
            .iter()
            .map(AccountKey::default_subaddress)
            .collect();

        // Generate a test database with a number blocks that does not divide evenly by
        // MAX_BLOCKS_PROCESSING_CHUNK_SIZE.
        let num_blocks = (MAX_BLOCKS_PROCESSING_CHUNK_SIZE * 2) + 1;
        let (mut ledger_db, mobilecoind_db) = get_test_databases(
            BlockVersion::MAX,
            0,
            &recipients,
            num_blocks,
            logger.clone(),
            &mut rng,
        );

        // Our recipient (controlled by the monitor id) is the first account
        // (account_keys[0]). Each block generated by test_utils has a TxOut per
        // recipient, so building on that knowledge the following code gets us
        // the TxOuts relevant to our particular recipient.
        let account0_tx_outs: Vec<TxOut> = (0..num_blocks)
            .map(|idx| {
                let block_contents = ledger_db.get_block_contents(idx as u64).unwrap();
                block_contents.outputs[0].clone()
            })
            .collect();

        // Before doing anything, we should not have any utxos for our test monitor.
        let utxos = mobilecoind_db
            .get_utxos_for_subaddress(&monitor_id, DEFAULT_SUBADDRESS_INDEX)
            .unwrap();
        assert_eq!(utxos.len(), 0);

        // Add monitor, should still have 0 outputs.
        assert_eq!(mobilecoind_db.add_monitor(&data).unwrap(), monitor_id);

        // Haven't synced yet, so still no outputs expected.
        let utxos = mobilecoind_db
            .get_utxos_for_subaddress(&monitor_id, DEFAULT_SUBADDRESS_INDEX)
            .unwrap();
        assert_eq!(utxos.len(), 0);

        let monitor_data = mobilecoind_db.get_monitor_data(&monitor_id).unwrap();
        assert_eq!(monitor_data.next_block, 0);

        // Process the first MAX_BLOCKS_PROCESSING_CHUNK_SIZE blocks.
        let result = sync_monitor(&ledger_db, &mobilecoind_db, &monitor_id, &logger).unwrap();
        assert_eq!(result, SyncMonitorOk::MoreBlocksPotentiallyAvailable);

        // We should now discover some outputs. Each block has 1 output per recipient,
        // and we synced the max chunk size.
        let monitor_data = mobilecoind_db.get_monitor_data(&monitor_id).unwrap();
        assert_eq!(
            monitor_data.next_block,
            MAX_BLOCKS_PROCESSING_CHUNK_SIZE as u64
        );

        let utxos = mobilecoind_db
            .get_utxos_for_subaddress(&monitor_id, DEFAULT_SUBADDRESS_INDEX)
            .unwrap();
        assert_eq!(utxos.len(), MAX_BLOCKS_PROCESSING_CHUNK_SIZE);

        // Sanity test the utxos.
        for utxo in utxos {
            assert!(account0_tx_outs.contains(&utxo.tx_out));
            assert_eq!(utxo.subaddress_index, 0);
            assert_eq!(utxo.value, test_utils::DEFAULT_PER_RECIPIENT_AMOUNT);
            assert_eq!(utxo.attempted_spend_height, 0);
        }

        // Process the second MAX_BLOCKS_PROCESSING_CHUNK_SIZE blocks.
        let result = sync_monitor(&ledger_db, &mobilecoind_db, &monitor_id, &logger).unwrap();
        assert_eq!(result, SyncMonitorOk::MoreBlocksPotentiallyAvailable);

        let monitor_data = mobilecoind_db.get_monitor_data(&monitor_id).unwrap();
        assert_eq!(
            monitor_data.next_block,
            (MAX_BLOCKS_PROCESSING_CHUNK_SIZE * 2) as u64
        );

        let utxos = mobilecoind_db
            .get_utxos_for_subaddress(&monitor_id, DEFAULT_SUBADDRESS_INDEX)
            .unwrap();
        assert_eq!(utxos.len(), MAX_BLOCKS_PROCESSING_CHUNK_SIZE * 2);

        // Sanity test the utxos.
        for utxo in utxos {
            assert!(account0_tx_outs.contains(&utxo.tx_out));
            assert_eq!(utxo.subaddress_index, 0);
            assert_eq!(utxo.value, test_utils::DEFAULT_PER_RECIPIENT_AMOUNT);
            assert_eq!(utxo.attempted_spend_height, 0);
        }

        // Process the last remaining block.
        let result = sync_monitor(&ledger_db, &mobilecoind_db, &monitor_id, &logger).unwrap();
        assert_eq!(result, SyncMonitorOk::NoMoreBlocks);

        let monitor_data = mobilecoind_db.get_monitor_data(&monitor_id).unwrap();
        assert_eq!(monitor_data.next_block, num_blocks as u64);

        let utxos = mobilecoind_db
            .get_utxos_for_subaddress(&monitor_id, DEFAULT_SUBADDRESS_INDEX)
            .unwrap();
        assert_eq!(utxos.len(), num_blocks);

        // Sanity test the utxos.
        for utxo in utxos {
            assert!(account0_tx_outs.contains(&utxo.tx_out));
            assert_eq!(utxo.subaddress_index, 0);
            assert_eq!(utxo.value, test_utils::DEFAULT_PER_RECIPIENT_AMOUNT);
            assert_eq!(utxo.attempted_spend_height, 0);
        }

        // Calling sync_monitor again should not change the results.
        let result = sync_monitor(&ledger_db, &mobilecoind_db, &monitor_id, &logger).unwrap();
        assert_eq!(result, SyncMonitorOk::NoMoreBlocks);

        let monitor_data = mobilecoind_db.get_monitor_data(&monitor_id).unwrap();
        assert_eq!(monitor_data.next_block, num_blocks as u64);

        let utxos = mobilecoind_db
            .get_utxos_for_subaddress(&monitor_id, DEFAULT_SUBADDRESS_INDEX)
            .unwrap();
        assert_eq!(utxos.len(), num_blocks);

        // Sanity test the utxos.
        for utxo in utxos.iter() {
            assert!(account0_tx_outs.contains(&utxo.tx_out));
            assert_eq!(utxo.subaddress_index, 0);
            assert_eq!(utxo.value, test_utils::DEFAULT_PER_RECIPIENT_AMOUNT);
            assert_eq!(utxo.attempted_spend_height, 0);
        }

        // All our utxos should be unique.
        assert_eq!(HashSet::from_iter(utxos.clone()).len(), num_blocks);

        // Add a block that spends our first utxo and sync it.
        let first_utxo = utxos[0].clone();

        add_block_to_ledger(
            &mut ledger_db,
            BlockVersion::MAX,
            &[recipients[1].clone()],
            Amount::new(DEFAULT_PER_RECIPIENT_AMOUNT, Mob::ID),
            &[utxos[0].key_image],
            &mut rng,
        )
        .unwrap();

        let result = sync_monitor(&ledger_db, &mobilecoind_db, &monitor_id, &logger).unwrap();
        assert_eq!(result, SyncMonitorOk::NoMoreBlocks);

        let utxos = mobilecoind_db
            .get_utxos_for_subaddress(&monitor_id, DEFAULT_SUBADDRESS_INDEX)
            .unwrap();
        assert_eq!(utxos.len(), num_blocks - 1);

        assert!(!utxos.contains(&first_utxo));
    }

    // TODO: make this a bench instead of a unit test.
    #[test_with_logger]
    fn test_sync_monitor_with_random_recipients(logger: Logger) {
        let mut rng: StdRng = SeedableRng::from_seed([98u8; 32]);

        let account_keys: Vec<_> = (0..5).map(|_i| AccountKey::random(&mut rng)).collect();

        let first_subaddress = DEFAULT_SUBADDRESS_INDEX;
        let subaddress_count = 5;
        let first_block_index = 0;
        let name = "";
        let data = MonitorData::new(
            account_keys[0].clone(),
            first_subaddress,
            subaddress_count,
            first_block_index,
            name,
        )
        .unwrap();

        let monitor_id = MonitorId::from(&data);

        let recipients: Vec<PublicAddress> = account_keys
            .iter()
            .map(AccountKey::default_subaddress)
            .collect();

        // Generate a test database with a number blocks that does not divide evenly by
        // MAX_BLOCKS_PROCESSING_CHUNK_SIZE.
        let num_blocks = (MAX_BLOCKS_PROCESSING_CHUNK_SIZE * 2) + 1;
        let (mut ledger_db, mobilecoind_db) = get_test_databases(
            BlockVersion::MAX,
            0,
            &recipients,
            num_blocks,
            logger.clone(),
            &mut rng,
        );

        // Our recipient (controlled by the monitor id) is the first account
        // (account_keys[0]). Each block generated by test_utils has a TxOut per
        // recipient, so building on that knowledge the following code gets us
        // the TxOuts relevant to our particular recipient.
        let account0_tx_outs: Vec<TxOut> = (0..num_blocks)
            .map(|idx| {
                let block_contents = ledger_db.get_block_contents(idx as u64).unwrap();
                block_contents.outputs[0].clone()
            })
            .collect();

        // Before doing anything, we should not have any utxos for our test monitor.
        let utxos = mobilecoind_db
            .get_utxos_for_subaddress(&monitor_id, DEFAULT_SUBADDRESS_INDEX)
            .unwrap();
        assert_eq!(utxos.len(), 0);

        // Add monitor, should still have 0 outputs.
        assert_eq!(mobilecoind_db.add_monitor(&data).unwrap(), monitor_id);

        // Haven't synced yet, so still no outputs expected.
        let utxos = mobilecoind_db
            .get_utxos_for_subaddress(&monitor_id, DEFAULT_SUBADDRESS_INDEX)
            .unwrap();
        assert_eq!(utxos.len(), 0);

        let monitor_data = mobilecoind_db.get_monitor_data(&monitor_id).unwrap();
        assert_eq!(monitor_data.next_block, 0);

        // Process the first MAX_BLOCKS_PROCESSING_CHUNK_SIZE blocks.
        let result = sync_monitor(&ledger_db, &mobilecoind_db, &monitor_id, &logger).unwrap();
        assert_eq!(result, SyncMonitorOk::MoreBlocksPotentiallyAvailable);

        // We should now discover some outputs. Each block has 1 output per recipient,
        // and we synced the max chunk size.
        let monitor_data = mobilecoind_db.get_monitor_data(&monitor_id).unwrap();
        assert_eq!(
            monitor_data.next_block,
            MAX_BLOCKS_PROCESSING_CHUNK_SIZE as u64
        );

        let utxos = mobilecoind_db
            .get_utxos_for_subaddress(&monitor_id, DEFAULT_SUBADDRESS_INDEX)
            .unwrap();
        assert_eq!(utxos.len(), MAX_BLOCKS_PROCESSING_CHUNK_SIZE);

        // Sanity test the utxos.
        for utxo in utxos {
            assert!(account0_tx_outs.contains(&utxo.tx_out));
            assert_eq!(utxo.subaddress_index, 0);
            assert_eq!(utxo.value, test_utils::DEFAULT_PER_RECIPIENT_AMOUNT);
            assert_eq!(utxo.attempted_spend_height, 0);
        }

        // Process the second MAX_BLOCKS_PROCESSING_CHUNK_SIZE blocks.
        let result = sync_monitor(&ledger_db, &mobilecoind_db, &monitor_id, &logger).unwrap();
        assert_eq!(result, SyncMonitorOk::MoreBlocksPotentiallyAvailable);

        let monitor_data = mobilecoind_db.get_monitor_data(&monitor_id).unwrap();
        assert_eq!(
            monitor_data.next_block,
            (MAX_BLOCKS_PROCESSING_CHUNK_SIZE * 2) as u64
        );

        let utxos = mobilecoind_db
            .get_utxos_for_subaddress(&monitor_id, DEFAULT_SUBADDRESS_INDEX)
            .unwrap();
        assert_eq!(utxos.len(), MAX_BLOCKS_PROCESSING_CHUNK_SIZE * 2);

        // Sanity test the utxos.
        for utxo in utxos {
            assert!(account0_tx_outs.contains(&utxo.tx_out));
            assert_eq!(utxo.subaddress_index, 0);
            assert_eq!(utxo.value, test_utils::DEFAULT_PER_RECIPIENT_AMOUNT);
            assert_eq!(utxo.attempted_spend_height, 0);
        }

        // Process the last remaining block.
        let result = sync_monitor(&ledger_db, &mobilecoind_db, &monitor_id, &logger).unwrap();
        assert_eq!(result, SyncMonitorOk::NoMoreBlocks);

        let monitor_data = mobilecoind_db.get_monitor_data(&monitor_id).unwrap();
        assert_eq!(monitor_data.next_block, num_blocks as u64);

        let utxos = mobilecoind_db
            .get_utxos_for_subaddress(&monitor_id, DEFAULT_SUBADDRESS_INDEX)
            .unwrap();
        assert_eq!(utxos.len(), num_blocks);

        // Sanity test the utxos.
        for utxo in utxos {
            assert!(account0_tx_outs.contains(&utxo.tx_out));
            assert_eq!(utxo.subaddress_index, 0);
            assert_eq!(utxo.value, test_utils::DEFAULT_PER_RECIPIENT_AMOUNT);
            assert_eq!(utxo.attempted_spend_height, 0);
        }

        // Calling sync_monitor again should not change the results.
        let result = sync_monitor(&ledger_db, &mobilecoind_db, &monitor_id, &logger).unwrap();
        assert_eq!(result, SyncMonitorOk::NoMoreBlocks);

        let monitor_data = mobilecoind_db.get_monitor_data(&monitor_id).unwrap();
        assert_eq!(monitor_data.next_block, num_blocks as u64);

        let utxos = mobilecoind_db
            .get_utxos_for_subaddress(&monitor_id, DEFAULT_SUBADDRESS_INDEX)
            .unwrap();
        assert_eq!(utxos.len(), num_blocks);

        // Sanity test the utxos.
        for utxo in utxos.iter() {
            assert!(account0_tx_outs.contains(&utxo.tx_out));
            assert_eq!(utxo.subaddress_index, 0);
            assert_eq!(utxo.value, test_utils::DEFAULT_PER_RECIPIENT_AMOUNT);
            assert_eq!(utxo.attempted_spend_height, 0);
        }

        // All our utxos should be unique.
        assert_eq!(HashSet::from_iter(utxos).len(), num_blocks);
        let receiver = AccountKey::random(&mut rng);

        // Add a block that has a bunch of irrelevant txos.
        let mut transaction_builder = TransactionBuilder::new(
            BlockVersion::MAX,
            Amount::new(Mob::MINIMUM_FEE, Mob::ID),
            MockFogResolver::default(),
            EmptyMemoBuilder::default(),
        )
        .unwrap();
        let mut tx_outs = Vec::new();
        for i in 0..1000 {
            let TxOutContext { tx_out, .. } = transaction_builder
                .add_output(Amount::new(10, Mob::ID), &receiver.subaddress(i), &mut rng)
                .unwrap();
            tx_outs.push(tx_out);
        }
        let start = Instant::now();

        add_txos_to_ledger(&mut ledger_db, BlockVersion::MAX, &tx_outs, &mut rng).unwrap();

        let add_txos_time = start.elapsed();
        log::info!(logger, "add_txos_to_ledger took {add_txos_time:?}");

        let start = Instant::now();

        let result = sync_monitor(&ledger_db, &mobilecoind_db, &monitor_id, &logger).unwrap();

        let sync_monitor_time = start.elapsed();
        log::info!(logger, "sync_monitor took {sync_monitor_time:?}");
        assert_eq!(result, SyncMonitorOk::NoMoreBlocks);
    }

    #[test_with_logger]
    fn test_utxo_value_zero(logger: Logger) {
        let mut rng: StdRng = SeedableRng::from_seed([98u8; 32]);

        let account_keys: Vec<_> = (0..5).map(|_i| AccountKey::random(&mut rng)).collect();

        let data = MonitorData::new(
            account_keys[0].clone(),
            DEFAULT_SUBADDRESS_INDEX, // first subaddress
            5,                        // number of subaddresses
            0,                        // first block
            "",                       // name
        )
        .unwrap();

        let monitor_id = MonitorId::from(&data);

        let recipients: Vec<PublicAddress> = account_keys
            .iter()
            .map(AccountKey::default_subaddress)
            .collect();

        // Generate a test database with one block.
        let (mut ledger_db, mobilecoind_db) = get_test_databases(
            BlockVersion::MAX,
            0,
            &recipients,
            1,
            logger.clone(),
            &mut rng,
        );

        // Add monitor.
        assert_eq!(mobilecoind_db.add_monitor(&data).unwrap(), monitor_id);

        // Sync.
        let result = sync_monitor(&ledger_db, &mobilecoind_db, &monitor_id, &logger).unwrap();
        assert_eq!(result, SyncMonitorOk::NoMoreBlocks);

        // Should have a single non-zero utxo for our monitor.
        let utxos = mobilecoind_db
            .get_utxos_for_subaddress(&monitor_id, DEFAULT_SUBADDRESS_INDEX)
            .unwrap();

        assert_eq!(utxos.len(), 1);
        assert_ne!(utxos[0].value, 0);

        // Add a block with 0-value txout that spends our first utxo and sync it.
        add_block_to_ledger(
            &mut ledger_db,
            BlockVersion::MAX,
            &[recipients[0].clone()],
            Amount::new(0, Mob::ID),
            &[utxos[0].key_image],
            &mut rng,
        )
        .unwrap();

        let result = sync_monitor(&ledger_db, &mobilecoind_db, &monitor_id, &logger).unwrap();
        assert_eq!(result, SyncMonitorOk::NoMoreBlocks);

        // We should now have only a zero utxo.
        let utxos = mobilecoind_db
            .get_utxos_for_subaddress(&monitor_id, DEFAULT_SUBADDRESS_INDEX)
            .unwrap();

        assert_eq!(utxos.len(), 1);
        assert_eq!(utxos[0].value, 0);
    }
}
