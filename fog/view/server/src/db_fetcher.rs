// Copyright (c) 2018-2021 The MobileCoin Foundation

//! An object for managing background data fetches from the recovery database.

use crate::{block_tracker::BlockTracker, counters};
use mc_common::logger::{log, Logger};
use mc_crypto_keys::CompressedRistrettoPublic;
use mc_fog_recovery_db_iface::{IngressPublicKeyRecord, RecoveryDb};
use mc_fog_types::ETxOutRecord;
use std::{
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Condvar, Mutex, MutexGuard,
    },
    thread::{sleep, Builder as ThreadBuilder, JoinHandle},
    time::Duration,
};

/// Time to wait between database fetch attempts.
pub const DB_POLL_INTERNAL: Duration = Duration::from_millis(100);

/// Approximate maximum number of ETxOutRecords we will collect inside
/// fetched_records before blocking and waiting for the enclave thread to pick
/// them up. Since DB fetching is significantlly faster than enclave insertion
/// we need a mechanism that prevents fetched_records from growing indefinitely.
/// This essentially caps the memory usage of the fetched_records array.
/// Assuming each ETxOutRecord is <256 bytes, this gives a worst case scenario
/// of 128MB.
pub const MAX_QUEUED_RECORDS: usize = (128 * 1024 * 1024) / 256;

/// A single block of fetched ETxOutRecords, together with information
/// identifying where it came from.
pub struct FetchedRecords {
    /// The ingress key associated to these ETxOutRecords
    pub ingress_key: CompressedRistrettoPublic,

    /// The block index the ETxOutRecords belong to.
    pub block_index: u64,

    /// The records produced by the ingest server.
    pub records: Vec<ETxOutRecord>,
}

/// Container for data that is shared between the worker thread and the holder
/// of the DbFetcher object.
#[derive(Default)]
struct DbFetcherSharedState {
    /// Information about ingress public keys we are aware of.
    ingress_keys: Vec<IngressPublicKeyRecord>,

    /// A queue of ETxOutRecords we have fetched from the database.
    /// This is periodically polled by an external thread which grabs this data
    /// and feeds it into the enclave.
    /// The queue is limited to approximately MAX_QUEUED_RECORDS ETxOutRecords
    /// total.
    fetched_records: Vec<FetchedRecords>,
}

/// An object for managing background data fetches from the recovery database.
pub struct DbFetcher {
    /// Join handle used to wait for the thread to terminate.
    join_handle: Option<JoinHandle<()>>,

    /// Stop request trigger, used to signal the thread to stop.
    stop_requested: Arc<AtomicBool>,

    /// State shared with the worker thread.
    shared_state: Arc<Mutex<DbFetcherSharedState>>,

    /// A tuple containing a mutex that holds the number of ETxOutRecords we
    /// have queued inside fetched_records so far, and a condition variable
    /// to signal when the count resets to zero.
    num_queued_records_limiter: Arc<(Mutex<usize>, Condvar)>,
}

impl DbFetcher {
    pub fn new<DB: RecoveryDb + Clone + Send + Sync + 'static>(db: DB, logger: Logger) -> Self {
        let stop_requested = Arc::new(AtomicBool::new(false));

        let shared_state = Arc::new(Mutex::new(DbFetcherSharedState::default()));

        // Clippy suggests to use AtomicUSize but we need a mutex for the conditional
        // variable.
        #[allow(clippy::mutex_atomic)]
        let num_queued_records_limiter = Arc::new((Mutex::new(0), Condvar::new()));

        let thread_stop_requested = stop_requested.clone();
        let thread_shared_state = shared_state.clone();
        let thread_num_queued_records_limiter = num_queued_records_limiter.clone();
        let join_handle = Some(
            ThreadBuilder::new()
                .name("ViewDbFetcher".to_owned())
                .spawn(move || {
                    DbFetcherThread::start(
                        db,
                        thread_stop_requested,
                        thread_shared_state,
                        thread_num_queued_records_limiter,
                        logger,
                    )
                })
                .expect("Could not spawn thread"),
        );

        Self {
            join_handle,
            stop_requested,
            shared_state,
            num_queued_records_limiter,
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

    /// Get context for the enclave block tracker to compute the highest
    /// processed block count
    pub fn get_highest_processed_block_context(&self) -> Vec<IngressPublicKeyRecord> {
        self.shared_state().ingress_keys.clone()
    }

    /// Get the list of FetchedRecords that were obtained by the worker thread.
    /// This also clears the queue so that more records could be fetched by
    /// the worker thread. This updates over time by the background worker
    /// thread.
    pub fn get_pending_fetched_records(&self) -> Vec<FetchedRecords> {
        // First grab all the records queued so far.
        let records = self.shared_state().fetched_records.split_off(0);

        // Now, signal the condition variable that the queue has been drained.
        let (lock, condvar) = &*self.num_queued_records_limiter;
        let mut num_queued_records = lock.lock().expect("mutex poisoned");
        *num_queued_records = 0;

        counters::DB_FETCHER_NUM_QUEUED_RECORDS.set(0);

        condvar.notify_one();

        // Return the records
        records
    }

    /// Get a locked reference to the shared state.
    fn shared_state(&self) -> MutexGuard<DbFetcherSharedState> {
        self.shared_state.lock().expect("mutex poisoned")
    }
}

impl Drop for DbFetcher {
    fn drop(&mut self) {
        let _ = self.stop();
    }
}

struct DbFetcherThread<DB: RecoveryDb + Clone + Send + Sync + 'static> {
    db: DB,
    stop_requested: Arc<AtomicBool>,
    shared_state: Arc<Mutex<DbFetcherSharedState>>,
    block_tracker: BlockTracker,
    num_queued_records_limiter: Arc<(Mutex<usize>, Condvar)>,
    logger: Logger,
}

/// Background worker thread implementation that takes care of periodically
/// polling data out of the database.
impl<DB: RecoveryDb + Clone + Send + Sync + 'static> DbFetcherThread<DB> {
    pub fn start(
        db: DB,
        stop_requested: Arc<AtomicBool>,
        shared_state: Arc<Mutex<DbFetcherSharedState>>,
        num_queued_records_limiter: Arc<(Mutex<usize>, Condvar)>,
        logger: Logger,
    ) {
        let thread = Self {
            db,
            stop_requested,
            shared_state,
            block_tracker: BlockTracker::new(logger.clone()),
            num_queued_records_limiter,
            logger,
        };
        thread.run();
    }

    fn run(mut self) {
        log::info!(self.logger, "Db fetcher thread started.");
        loop {
            if self.stop_requested.load(Ordering::SeqCst) {
                log::info!(self.logger, "Db fetcher thread stop requested.");
                break;
            }

            self.load_ingress_keys();

            // Each call to load_block_data attempts to load one block for each known ingest
            // invocation. We want to keep loading blocks as long as we have data to load,
            // but that could take some time which is why the loop is also gated
            // on the stop trigger in case a stop is requested during loading.
            while self.load_block_data() && !self.stop_requested.load(Ordering::SeqCst) {}

            sleep(DB_POLL_INTERNAL);
        }
    }

    /// Sync ingress key records from the database. This allows us to learn
    /// which ingress keys are currently alive, which block ranges they are
    /// able to cover, and which blocks have they ingested so far.
    fn load_ingress_keys(&self) {
        let _metrics_timer = counters::LOAD_INGRESS_KEYS_TIME.start_timer();

        match self.db.get_ingress_key_records(0) {
            Ok(records) => {
                log::trace!(self.logger, "get_ingress_key_records: {:?}", records);

                self.shared_state().ingress_keys = records;
            }

            Err(err) => {
                log::warn!(self.logger, "Failed getting ingress keys: {}", err);
            }
        }
    }

    /// Attempt to load the next block for each of the ingest invocations we are
    /// aware of and tracking.
    /// Returns true if we might have more block data to load.
    fn load_block_data(&mut self) -> bool {
        let mut has_more_work = false;

        // See whats the next block number we need to load for each invocation we are
        // aware of.
        let ingress_keys = self.shared_state().ingress_keys.clone();

        log::trace!(
            self.logger,
            "Have {} ingress keys: {:?}",
            ingress_keys.len(),
            ingress_keys
        );

        let next_block_index_per_ingress_key = self.block_tracker.next_blocks(&ingress_keys);

        log::trace!(
            self.logger,
            "load_block_data next_blocks: {:?}",
            next_block_index_per_ingress_key
        );

        for (ingress_key, block_index) in next_block_index_per_ingress_key.into_iter() {
            // Attempt to load data for the next block.
            let get_tx_outs_by_block_result = {
                let _metrics_timer = counters::GET_TX_OUTS_BY_BLOCK_TIME.start_timer();
                self.db
                    .get_tx_outs_by_block_and_key(ingress_key, block_index)
            };

            match get_tx_outs_by_block_result {
                Ok(Some(tx_outs)) => {
                    let num_tx_outs = tx_outs.len();

                    // Log
                    log::info!(
                        self.logger,
                        "ingress_key {:?} fetched {} tx outs for block {}",
                        ingress_key,
                        num_tx_outs,
                        block_index,
                    );

                    // Ingest has produced data for this block, we'd like to keep trying the
                    // next block on the next loop iteration.
                    has_more_work = true;

                    // Mark that we are done fetching data for this block.
                    self.block_tracker.block_processed(ingress_key, block_index);

                    // Store the fetched records so that they could be consumed by the enclave
                    // when its ready.
                    {
                        let mut state = self.shared_state();
                        state.fetched_records.push(FetchedRecords {
                            ingress_key,
                            block_index,
                            records: tx_outs,
                        });
                    }

                    // Update metrics.
                    counters::BLOCKS_FETCHED_COUNT.inc();
                    counters::TXOS_FETCHED_COUNT.inc_by(num_tx_outs as i64);

                    // Block if we have queued up enough records for now.
                    // (Until the enclave thread drains the queue).
                    let (lock, condvar) = &*self.num_queued_records_limiter;
                    let mut num_queued_records = condvar
                        .wait_while(lock.lock().unwrap(), |num_queued_records| {
                            *num_queued_records > MAX_QUEUED_RECORDS
                        })
                        .expect("condvar wait failed");
                    *num_queued_records += num_tx_outs;

                    counters::DB_FETCHER_NUM_QUEUED_RECORDS.set(*num_queued_records as i64);
                }
                Ok(None) => {
                    log::trace!(
                        self.logger,
                        "ingress_key {:?} block {} query missed, no new data yet",
                        ingress_key,
                        block_index
                    );
                }
                Err(err) => {
                    log::warn!(
                        self.logger,
                        "Failed querying tx outs for {:?}/{}: {}",
                        ingress_key,
                        block_index,
                        err
                    );
                }
            }
        }

        has_more_work
    }

    fn shared_state(&self) -> MutexGuard<DbFetcherSharedState> {
        self.shared_state.lock().expect("mutex poisoned")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mc_attest_core::VerificationReport;
    use mc_common::logger::test_with_logger;
    use mc_fog_recovery_db_iface::{IngressPublicKeyStatus, ReportData, ReportDb};
    use mc_fog_sql_recovery_db::test_utils::SqlRecoveryDbTestContext;
    use mc_fog_test_infra::db_tests::{random_block, random_kex_rng_pubkey};
    use mc_util_from_random::FromRandom;
    use rand::{rngs::StdRng, SeedableRng};
    use std::{thread::sleep, time::Duration};

    #[test_with_logger]
    fn basic_single_ingress_key(logger: Logger) {
        let mut rng: StdRng = SeedableRng::from_seed([123u8; 32]);
        let db_test_context = SqlRecoveryDbTestContext::new(logger.clone());
        let db = db_test_context.get_db_instance();
        let db_fetcher = DbFetcher::new(db.clone(), logger);

        // Initially, our database starts empty.
        let ingress_keys = db_fetcher.get_highest_processed_block_context();
        assert!(ingress_keys.is_empty());
        assert!(db_fetcher.get_pending_fetched_records().is_empty());

        // Register a new ingress key with start block 10 and check that wer can see it.
        let ingress_key = CompressedRistrettoPublic::from_random(&mut rng);
        db.new_ingress_key(&ingress_key, 10).unwrap();

        let mut success = false;
        for _i in 0..500 {
            let ingress_keys = db_fetcher.get_highest_processed_block_context();

            if ingress_keys.is_empty() {
                sleep(Duration::from_millis(10));
                continue;
            }

            assert_eq!(
                ingress_keys,
                vec![IngressPublicKeyRecord {
                    key: ingress_key.clone(),
                    status: IngressPublicKeyStatus {
                        start_block: 10,
                        pubkey_expiry: 0,
                        retired: false,
                        lost: false,
                    },
                    last_scanned_block: None,
                }]
            );

            assert!(db_fetcher.get_pending_fetched_records().is_empty());

            success = true;
            break;
        }

        assert!(success);

        // Add some blocks, they should get picked up and find their way into pending
        // fetched records and last_scanned_block.
        let invoc_id1 = db
            .new_ingest_invocation(None, &ingress_key, &random_kex_rng_pubkey(&mut rng), 10)
            .unwrap();

        let mut blocks_and_records = Vec::new();
        for block_index in 10..20 {
            let (block, records) = random_block(&mut rng, block_index, 5); // 5 outputs per block

            db.add_block_data(&invoc_id1, &block, 0, &records).unwrap();
            blocks_and_records.push((block, records));
        }

        for _i in 0..500 {
            let num_fetched_records = db_fetcher.shared_state().fetched_records.len();
            if num_fetched_records >= blocks_and_records.len() {
                break;
            }

            sleep(Duration::from_millis(10));
        }

        let fetched_records = db_fetcher.get_pending_fetched_records();
        assert_eq!(fetched_records.len(), blocks_and_records.len());

        for (i, fetched_record) in fetched_records.iter().enumerate() {
            assert_eq!(fetched_record.ingress_key, ingress_key);
            assert_eq!(fetched_record.block_index, i as u64 + 10); // We started at block index 10
            assert_eq!(blocks_and_records[i].1, fetched_record.records);
        }

        assert!(db_fetcher.get_pending_fetched_records().is_empty()); // The previous call should have drained this

        sleep(Duration::from_millis(100));

        let ingress_keys = db_fetcher.get_highest_processed_block_context();
        assert_eq!(
            ingress_keys,
            vec![IngressPublicKeyRecord {
                key: ingress_key.clone(),
                status: IngressPublicKeyStatus {
                    start_block: 10,
                    pubkey_expiry: 0,
                    retired: false,
                    lost: false,
                },
                last_scanned_block: Some(19),
            }]
        );

        // Add a few more blocks, they should get picked up.
        let mut blocks_and_records = Vec::new();
        for i in 20..30 {
            let (block, records) = random_block(&mut rng, i, 5); // 5 outputs per block

            db.add_block_data(&invoc_id1, &block, 0, &records).unwrap();
            blocks_and_records.push((block, records));
        }

        for _i in 0..500 {
            let num_fetched_records = db_fetcher.shared_state().fetched_records.len();
            if num_fetched_records >= blocks_and_records.len() {
                break;
            }

            sleep(Duration::from_millis(10));
        }

        let fetched_records = db_fetcher.get_pending_fetched_records();
        assert_eq!(fetched_records.len(), blocks_and_records.len());

        for (i, fetched_record) in fetched_records.iter().enumerate() {
            assert_eq!(fetched_record.ingress_key, ingress_key);
            assert_eq!(fetched_record.block_index, i as u64 + 20);
            assert_eq!(blocks_and_records[i].1, fetched_record.records);
        }

        assert!(db_fetcher.get_pending_fetched_records().is_empty()); // The previous call should have drained this

        sleep(Duration::from_millis(100));

        let ingress_keys = db_fetcher.get_highest_processed_block_context();
        assert_eq!(
            ingress_keys,
            vec![IngressPublicKeyRecord {
                key: ingress_key.clone(),
                status: IngressPublicKeyStatus {
                    start_block: 10,
                    pubkey_expiry: 0,
                    retired: false,
                    lost: false,
                },
                last_scanned_block: Some(29),
            }]
        );

        // Add more blocks but this time leave a hole between the previous blocks and
        // the new ones. They should not get picked up until a missed blocks
        // range is reported.
        let mut blocks_and_records_40_50 = Vec::new();
        for i in 40..50 {
            let (block, records) = random_block(&mut rng, i, 5); // 5 outputs per block

            db.add_block_data(&invoc_id1, &block, 0, &records).unwrap();
            blocks_and_records_40_50.push((block, records));
        }

        sleep(Duration::from_secs(1)); // Supposedly enough time for at least some blocks to get picked up.

        assert!(db_fetcher.get_pending_fetched_records().is_empty());

        sleep(Duration::from_millis(100));

        let ingress_keys = db_fetcher.get_highest_processed_block_context();
        assert_eq!(
            ingress_keys,
            vec![IngressPublicKeyRecord {
                key: ingress_key.clone(),
                status: IngressPublicKeyStatus {
                    start_block: 10,
                    pubkey_expiry: 0,
                    retired: false,
                    lost: false,
                },
                last_scanned_block: Some(49), // the last block added was 49 (loop is 40..50)
            }]
        );

        sleep(Duration::from_secs(1)); // Supposedly enough time for at least some blocks to get picked up.

        assert!(db_fetcher.shared_state().fetched_records.is_empty());

        // Retire our key at block 45, and provide blocks 30-39 (we previously provided
        // 40-49)
        // We should only get block data for blocks 30-44, and not bother loading 45 and
        // later, since the key expired after that.
        db.set_report(
            &ingress_key,
            "",
            &ReportData {
                ingest_invocation_id: None,
                report: create_report(""),
                pubkey_expiry: 45,
            },
        )
        .unwrap();
        db.retire_ingress_key(&ingress_key, true).unwrap();

        let mut blocks_and_records = Vec::new();
        for i in 30..40 {
            let (block, records) = random_block(&mut rng, i, 5); // 5 outputs per block

            db.add_block_data(&invoc_id1, &block, 0, &records).unwrap();
            blocks_and_records.push((block, records));
        }

        sleep(Duration::from_secs(1)); // Supposedly enough time for at least some blocks to get picked up.

        for _i in 0..500 {
            let num_fetched_records = db_fetcher.shared_state().fetched_records.len();
            // We expect 15 blocks (30-44)
            if num_fetched_records >= blocks_and_records.len() + 15 {
                break;
            }

            sleep(Duration::from_millis(10));
        }

        let fetched_records = db_fetcher.get_pending_fetched_records();
        assert_eq!(fetched_records.len(), blocks_and_records.len() + 5);

        blocks_and_records.extend(blocks_and_records_40_50);

        for (i, fetched_record) in fetched_records.iter().enumerate() {
            assert_eq!(fetched_record.ingress_key, ingress_key);
            assert_eq!(fetched_record.block_index, i as u64 + 30);
            assert_eq!(fetched_record.records, blocks_and_records[i].1);
        }

        assert!(db_fetcher.get_pending_fetched_records().is_empty()); // The previous call should have drained this
    }

    #[test_with_logger]
    fn test_overlapping_keys(logger: Logger) {
        let mut rng: StdRng = SeedableRng::from_seed([123u8; 32]);
        let db_test_context = SqlRecoveryDbTestContext::new(logger.clone());
        let db = db_test_context.get_db_instance();
        let db_fetcher = DbFetcher::new(db.clone(), logger);

        // Register two ingress keys that have some overlap:
        // key_id1 starts at block 0, key2 starts at block 5.
        let key1 = CompressedRistrettoPublic::from_random(&mut rng);
        db.new_ingress_key(&key1, 0).unwrap();
        let invoc_id1 = db
            .new_ingest_invocation(None, &key1, &random_kex_rng_pubkey(&mut rng), 0)
            .unwrap();

        let key2 = CompressedRistrettoPublic::from_random(&mut rng);
        db.new_ingress_key(&key2, 5).unwrap();
        let invoc_id2 = db
            .new_ingest_invocation(None, &key2, &random_kex_rng_pubkey(&mut rng), 5)
            .unwrap();

        // Add 10 blocks to both keys and see that we are able to get both.
        let mut blocks_and_records = Vec::new();
        for i in 0..10 {
            let (block, records) = random_block(&mut rng, i, 5); // 5 outputs per block
            db.add_block_data(&invoc_id1, &block, 0, &records).unwrap();
            blocks_and_records.push((key1, block, records));

            let (block, records) = random_block(&mut rng, i + 5, 5); // start block is 5
            db.add_block_data(&invoc_id2, &block, 0, &records).unwrap();
            blocks_and_records.push((key2, block, records));
        }

        for _i in 0..500 {
            let num_fetched_records = db_fetcher.shared_state().fetched_records.len();
            if num_fetched_records >= blocks_and_records.len() {
                break;
            }

            sleep(Duration::from_millis(10));
        }

        let mut fetched_records = db_fetcher.get_pending_fetched_records();
        assert_eq!(fetched_records.len(), blocks_and_records.len());

        // Sort to make comparing easier
        fetched_records.sort_by_key(|fr| (fr.ingress_key, fr.block_index));
        blocks_and_records
            .sort_by_key(|(ingress_key, block, _records)| (ingress_key.clone(), block.index));

        for (i, fetched_record) in fetched_records.iter().enumerate() {
            assert_eq!(fetched_record.ingress_key, blocks_and_records[i].0);
            assert_eq!(fetched_record.block_index, blocks_and_records[i].1.index);
            assert_eq!(blocks_and_records[i].2, fetched_record.records);
        }
    }

    #[test_with_logger]
    fn test_non_overlapping_keys(logger: Logger) {
        let mut rng: StdRng = SeedableRng::from_seed([123u8; 32]);
        let db_test_context = SqlRecoveryDbTestContext::new(logger.clone());
        let db = db_test_context.get_db_instance();
        let db_fetcher = DbFetcher::new(db.clone(), logger);

        // Register two ingress keys that have some overlap:
        // invoc_id1 starts at block 0, invoc_id2 starts at block 50.
        let key1 = CompressedRistrettoPublic::from_random(&mut rng);
        db.new_ingress_key(&key1, 0).unwrap();
        let invoc_id1 = db
            .new_ingest_invocation(None, &key1, &random_kex_rng_pubkey(&mut rng), 0)
            .unwrap();

        let key2 = CompressedRistrettoPublic::from_random(&mut rng);
        db.new_ingress_key(&key2, 50).unwrap();
        let invoc_id2 = db
            .new_ingest_invocation(None, &key2, &random_kex_rng_pubkey(&mut rng), 50)
            .unwrap();

        // Add 10 blocks to both keys and see that we are able to get both.
        let mut blocks_and_records = Vec::new();
        for i in 0..10 {
            let (block, records) = random_block(&mut rng, i, 5); // 5 outputs per block
            db.add_block_data(&invoc_id1, &block, 0, &records).unwrap();
            blocks_and_records.push((key1, block, records));

            let (block, records) = random_block(&mut rng, i + 50, 5); // start block is 50
            db.add_block_data(&invoc_id2, &block, 0, &records).unwrap();
            blocks_and_records.push((key2, block, records));
        }

        // Add a few more blocks to invoc_id2
        for i in 10..20 {
            let (block, records) = random_block(&mut rng, i + 50, 5); // start block is 50
            db.add_block_data(&invoc_id2, &block, 0, &records).unwrap();
            blocks_and_records.push((key2, block, records));
        }

        for _i in 0..500 {
            let num_fetched_records = db_fetcher.shared_state().fetched_records.len();
            if num_fetched_records >= blocks_and_records.len() {
                break;
            }

            sleep(Duration::from_millis(10));
        }

        let mut fetched_records = db_fetcher.get_pending_fetched_records();
        assert_eq!(fetched_records.len(), blocks_and_records.len());

        // Sort to make comparing easier
        fetched_records.sort_by_key(|fr| (fr.ingress_key, fr.block_index));
        blocks_and_records
            .sort_by_key(|(ingress_key, block, _records)| (ingress_key.clone(), block.index));

        for (i, fetched_record) in fetched_records.iter().enumerate() {
            assert_eq!(fetched_record.ingress_key, blocks_and_records[i].0);
            assert_eq!(fetched_record.block_index, blocks_and_records[i].1.index);
            assert_eq!(blocks_and_records[i].2, fetched_record.records);
        }
    }

    fn create_report(name: &str) -> VerificationReport {
        let chain = pem::parse_many(mc_crypto_x509_test_vectors::ok_rsa_chain_25519_leaf().0)
            .into_iter()
            .map(|p| p.contents)
            .collect();

        VerificationReport {
            sig: format!("{} sig", name).into_bytes().into(),
            chain,
            http_body: format!("{} body", name),
        }
    }
}
