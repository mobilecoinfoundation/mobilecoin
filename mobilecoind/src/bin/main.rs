// Copyright (c) 2018-2023 The MobileCoin Foundation
#![deny(missing_docs)]
#![allow(unused)]

//! mobilecoind daemon entry point

use clap::Parser;
use displaydoc::Display;
use hex;
use mc_account_keys::burn_address_view_private;
use mc_attest_verifier::{MrSignerVerifier, Verifier, DEBUG_ENCLAVE};
use mc_blockchain_types::{BlockData, BlockIndex};
use mc_common::{
    logger::{create_app_logger, log, o, Logger},
    HashMap, ResponderId,
};
use mc_crypto_keys::RistrettoPublic;
use mc_ledger_db::{Error as LedgerDbError, Ledger, LedgerDB};
use mc_ledger_sync::{LedgerSyncServiceThread, PollingNetworkState, ReqwestTransactionsFetcher};
use mc_mobilecoind::{
    config::Config, database::Database, payments::TransactionsManager, service::Service,
};
use mc_mobilecoind_api::blockchain::ArchiveBlock;
use mc_transaction_core::tx::TxOut;
use mc_util_telemetry::setup_default_tracer;
use mc_watcher::{
    error::{WatcherDBError, WatcherError},
    watcher::WatcherSyncThread,
    watcher_db::{create_or_open_rw_watcher_db, WatcherDB},
};
use rayon::iter::{IntoParallelIterator, ParallelIterator};
use reqwest::Url;
use std::{
    fmt::Write,
    path::Path,
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc, RwLock,
    },
    thread,
    time::Duration,
};
fn main() {
    let _sentry_guard = mc_common::sentry::init();
    let (logger, _global_logger_guard) = create_app_logger(o!());
    mc_common::setup_panic_handler();

    let config = Config::parse();
    if !cfg!(debug_assertions) && !config.offline {
        config.validate_host().expect("Could not validate host");
    }

    let _tracer =
        setup_default_tracer(env!("CARGO_PKG_NAME")).expect("Failed setting telemetry tracer");

    let mut mr_signer_verifier =
        MrSignerVerifier::from(mc_consensus_enclave_measurement::sigstruct());
    mr_signer_verifier
        .allow_hardening_advisories(mc_consensus_enclave_measurement::HARDENING_ADVISORIES);

    let mut verifier = Verifier::default();
    verifier.mr_signer(mr_signer_verifier).debug(DEBUG_ENCLAVE);

    log::debug!(logger, "Verifier: {:?}", verifier);

    // Create peer manager.
    let peer_manager = config.peers_config.create_peer_manager(verifier, &logger);

    // Create network state, transactions fetcher and ledger sync.
    let network_state = Arc::new(RwLock::new(PollingNetworkState::new(
        config.quorum_set(),
        peer_manager.clone(),
        logger.clone(),
    )));

    let transactions_fetcher = ReqwestTransactionsFetcher::new(
        config.tx_source_urls.clone().unwrap_or_default(),
        logger.clone(),
    )
    .expect("Failed creating ReqwestTransactionsFetcher");

    // Create the ledger_db.
    let ledger_db = create_or_open_ledger_db(&config, &logger, &transactions_fetcher);

    // Start ledger sync thread unless running in offline mode.
    let ledger_sync_service_thread = if config.offline {
        None
    } else {
        Some(LedgerSyncServiceThread::new(
            ledger_db.clone(),
            peer_manager.clone(),
            network_state.clone(),
            transactions_fetcher.clone(),
            config.poll_interval,
            logger.clone(),
        ))
    };

    // Optionally instantiate the watcher sync thread and get the watcher_db handle.
    let (watcher_db, watcher_sync_thread) = match &config.watcher_db {
        Some(watcher_db_path) => {
            log::info!(logger, "Launching watcher.");

            log::info!(logger, "Opening watcher db at {:?}.", watcher_db_path);
            let watcher_db = create_or_open_rw_watcher_db(
                watcher_db_path,
                &transactions_fetcher.source_urls,
                logger.clone(),
            )
            .expect("Could not create or open WatcherDB");

            // Start watcher db sync thread, unless running in offline mode.
            let watcher_sync_thread = if config.offline {
                panic!("Attempted to start watcher but we are configured in offline mode");
            } else {
                log::info!(logger, "Starting watcher sync thread from mobilecoind.");
                Some(
                    WatcherSyncThread::new(
                        watcher_db.clone(),
                        ledger_db.clone(),
                        config.poll_interval,
                        true,
                        logger.clone(),
                    )
                    .expect("Failed starting watcher thread"),
                )
            };
            (Some(watcher_db), watcher_sync_thread)
        }
        None => (None, None),
    };

    // Start the relayer thread if both the watcher_sync_thread and
    // ledger_sync_thread are not None
    let _relayer_service_thread =
        if ledger_sync_service_thread.is_some() && watcher_sync_thread.is_some() {
            Some(RelayerThread::new(
                watcher_db.clone().unwrap(),
                ledger_db.clone(),
                config.poll_interval,
                logger.clone(),
            ))
        } else {
            None
        };

    // Potentially launch API server
    match (&config.mobilecoind_db, &config.listen_uri) {
        (Some(mobilecoind_db), Some(listen_uri)) => {
            log::info!(logger, "Launching mobilecoind API services");

            let _ = std::fs::create_dir_all(mobilecoind_db);

            let mobilecoind_db = Database::new(mobilecoind_db, logger.clone())
                .expect("Could not open mobilecoind_db");

            let transactions_manager = TransactionsManager::new(
                ledger_db.clone(),
                mobilecoind_db.clone(),
                peer_manager,
                config.get_fog_resolver_factory(logger.clone()),
                logger.clone(),
            );

            let _api_server = Service::new(
                ledger_db,
                mobilecoind_db,
                watcher_db,
                transactions_manager,
                network_state,
                listen_uri,
                config.num_workers,
                config.peers_config.chain_id.clone(),
                logger,
            );

            loop {
                std::thread::sleep(config.poll_interval);
            }
        }

        (None, None) => {
            // No mobilecoind service, only ledger syncing.
            loop {
                std::thread::sleep(config.poll_interval);
            }
        }

        _ => {
            panic!(
                "Please provide both --mobilecoind-db and --listen-uri if you want to enable the API server"
            );
        }
    }
}

fn create_or_open_ledger_db(
    config: &Config,
    logger: &Logger,
    transactions_fetcher: &ReqwestTransactionsFetcher,
) -> LedgerDB {
    let ledger_db_file = Path::new(&config.ledger_db).join("data.mdb");

    // Attempt to run migrations, if requested and ledger is available.
    if config.ledger_db_migrate && ledger_db_file.exists() {
        mc_ledger_migration::migrate(&config.ledger_db, logger);
    }

    // Attempt to open the ledger and see if it has anything in it.
    match LedgerDB::open(&config.ledger_db) {
        Ok(ledger_db) => {
            if let Ok(num_blocks) = ledger_db.num_blocks() {
                if num_blocks > 0 {
                    // Successfully opened a ledger that has blocks in it.
                    log::info!(
                        logger,
                        "Ledger DB {:?} opened: num_blocks={} num_txos={}",
                        config.ledger_db,
                        num_blocks,
                        ledger_db.num_txos().expect("Failed getting number of txos")
                    );
                    return ledger_db;
                }
            }
        }
        Err(mc_ledger_db::Error::MetadataStore(
            mc_ledger_db::MetadataStoreError::VersionIncompatible(old, new),
        )) => {
            panic!("Ledger DB {:?} requires migration from version {} to {}. Please run mobilecoind with --ledger-db-migrate or use the mc-ledger-migration utility.", config.ledger_db, old, new);
        }
        Err(err) => {
            // If the ledger database exists and we failed to open it, something is wrong
            // with it and this requires manual intervention.
            if ledger_db_file.exists() {
                panic!("Failed to open ledger db {:?}: {:?}", config.ledger_db, err);
            }
        }
    };

    // Ledger doesn't exist, or is empty. Copy a bootstrapped ledger or try and get
    // it from the network.
    match &config.ledger_db_bootstrap {
        Some(ledger_db_bootstrap) => {
            log::debug!(
                logger,
                "Ledger DB {:?} does not exist, copying from {}",
                config.ledger_db,
                ledger_db_bootstrap
            );

            // Try and create directory in case it doesn't exist. We need it to exist before
            // we can copy the data.mdb file.
            if !Path::new(&config.ledger_db).exists() {
                std::fs::create_dir_all(&config.ledger_db)
                    .unwrap_or_else(|_| panic!("Failed creating directory {:?}", config.ledger_db));
            }

            let src = format!("{ledger_db_bootstrap}/data.mdb");
            std::fs::copy(src.clone(), &ledger_db_file).unwrap_or_else(|_| {
                panic!(
                    "Failed copying ledger from {} into directory {}",
                    src,
                    ledger_db_file.display()
                )
            });
        }
        None => {
            log::info!(
                    logger,
                    "Ledger DB {:?} does not exist, bootstrapping from peer, this may take a few minutes",
                    config.ledger_db
                );
            std::fs::create_dir_all(&config.ledger_db).expect("Could not create ledger dir");
            LedgerDB::create(&config.ledger_db).expect("Could not create ledger_db");
            let block_data = transactions_fetcher
                .get_origin_block_and_transactions()
                .expect("Failed to download initial transactions");
            let mut db = LedgerDB::open(&config.ledger_db).expect("Could not open ledger_db");
            db.append_block_data(&block_data)
                .expect("Failed to appened initial transactions");
            log::info!(logger, "Bootstrapping completed!");
        }
    }

    // Open ledger and verify it has (at least) the origin block.
    log::debug!(logger, "Opening Ledger DB {:?}", config.ledger_db);
    let ledger_db = LedgerDB::open(&config.ledger_db)
        .unwrap_or_else(|_| panic!("Could not open ledger db inside {:?}", config.ledger_db));

    let num_blocks = ledger_db
        .num_blocks()
        .expect("Failed getting number of blocks");
    if num_blocks == 0 {
        panic!("Ledger DB is empty :(");
    }

    log::info!(
        logger,
        "Ledger DB {:?} opened: num_blocks={} num_txos={}",
        config.ledger_db,
        num_blocks,
        ledger_db.num_txos().expect("Failed getting number of txos")
    );

    ledger_db
}

/// Maximal number of blocks to attempt to sync at each loop iteration.
const MAX_BLOCKS_PER_SYNC_ITERATION: usize = 1000;

/// Syncs new ledger materials from the watcher when the local ledger
/// appends new interesting burns, and relays the BlockData and relevant burns.
pub struct RelayerThread {
    join_handle: Option<thread::JoinHandle<()>>,
    currently_behind: Arc<AtomicBool>,
    stop_requested: Arc<AtomicBool>,
    next_block_to_sync: Arc<AtomicU64>,
}

impl RelayerThread {
    /// Create a new Relayer thread.
    pub fn new(
        watcher_db: WatcherDB,
        ledger: impl Ledger + 'static + Clone,
        poll_interval: Duration,
        logger: Logger,
    ) -> Result<Self, WatcherError> {
        log::debug!(logger, "Creating relayer thread.");

        let currently_behind = Arc::new(AtomicBool::new(false));
        let stop_requested = Arc::new(AtomicBool::new(false));
        //TODO: Figure out what to do with this.
        let ledger_num_blocks = ledger.num_blocks().unwrap();
        let next_block_to_sync = Arc::new(AtomicU64::new(ledger_num_blocks));
        let thread_next_block_to_sync = next_block_to_sync.clone();
        let thread_currently_behind = currently_behind.clone();
        let thread_stop_requested = stop_requested.clone();
        let join_handle = Some(
            thread::Builder::new()
                .name("Relayer".into())
                .spawn(move || {
                    Self::thread_entrypoint(
                        ledger,
                        watcher_db,
                        poll_interval,
                        thread_currently_behind,
                        thread_stop_requested,
                        thread_next_block_to_sync,
                        logger,
                    );
                })
                .expect("Failed spawning Relayer thread"),
        );

        Ok(Self {
            join_handle,
            currently_behind,
            stop_requested,
            next_block_to_sync,
        })
    }

    /// Stop the relayer thread.
    pub fn stop(&mut self) {
        self.stop_requested.store(true, Ordering::SeqCst);
        if let Some(thread) = self.join_handle.take() {
            thread.join().expect("Relayer thread join failed");
        }
    }

    /// Check whether the relayer is behind the ledger DB.
    pub fn is_behind(&self) -> bool {
        self.currently_behind.load(Ordering::SeqCst)
    }

    /// The entrypoint for the relayer thread.
    fn thread_entrypoint(
        ledger: impl Ledger + Clone,
        watcher_db: WatcherDB,
        poll_interval: Duration,
        currently_behind: Arc<AtomicBool>,
        stop_requested: Arc<AtomicBool>,
        next_block_to_sync: Arc<AtomicU64>,
        logger: Logger,
    ) {
        log::debug!(logger, "RelayerThread has started.");

        loop {
            if stop_requested.load(Ordering::SeqCst) {
                log::debug!(logger, "RelayerThread stop requested.");
                break;
            }

            let next_block = next_block_to_sync.load(Ordering::SeqCst);
            let ledger_num_blocks = ledger.num_blocks().unwrap();
            // See if we're currently behind.
            let is_behind = { next_block < ledger_num_blocks };
            log::debug!(
                logger,
                "next block to sync: {}, Ledger block height {}, is_behind {}",
                next_block,
                ledger_num_blocks,
                is_behind
            );

            // Store current state and log.
            currently_behind.store(is_behind, Ordering::SeqCst);
            if is_behind {
                log::debug!(
                    logger,
                    "Relayer is_behind: {:?} next block to sync: {:?} vs ledger: {:?}",
                    is_behind,
                    next_block,
                    ledger_num_blocks,
                );
            }

            // Maybe sync, maybe wait and check again.
            if is_behind {
                // Get the block contents and check to see if there's a burn in it.
                let sync_result = Self::process_block(
                    ledger.clone(),
                    watcher_db.clone(),
                    next_block,
                    poll_interval,
                    &logger,
                );
                match sync_result {
                    Ok(()) => {
                        // Advance to the next block to sync if this block was successfully
                        // processed
                        next_block_to_sync
                            .compare_exchange(
                                next_block,
                                next_block + 1,
                                Ordering::SeqCst,
                                Ordering::SeqCst,
                            )
                            .expect("Threading error, attempted to process blocks out of order");
                    }
                    Err(e) => {
                        //TODO: Figure out what kind of errors are acceptable
                        // here. Which ones should cause the thread to fail?
                    }
                }
            } else if !stop_requested.load(Ordering::SeqCst) {
                log::trace!(
                    logger,
                    "Sleeping, relayer last block synced = {}...",
                    next_block
                );
                std::thread::sleep(poll_interval);
            }
        }
    }

    /// Function to match TXOs from a block into interesting vector of
    /// unspent UTXOs.
    fn check_block_for_burns(
        ledger: impl Ledger,
        block_number: BlockIndex,
        logger: &Logger,
    ) -> Result<Vec<TxOut>, RelayerError> {
        let block_contents = ledger.get_block_contents(block_number)?;
        let outputs = block_contents.outputs;
        // Iterate over each output and filter the results using a parallel iterator.
        let results: Result<Vec<TxOut>, RelayerError> = outputs
            .into_par_iter()
            .filter_map(|tx_out| {
                // View key match against the burn address. If it returns ok, then it's a burn.
                match tx_out
                    .view_key_match(&burn_address_view_private())
                    .map(|(amount, _commitment)| (tx_out.clone(), amount))
                    .ok()
                {
                    Some((tx_out, amount)) => Some(Ok(tx_out)),
                    None => None,
                }
            })
            .collect();

        results
    }
    /// A function that processes a block by:
    ///     1. checks the blocks for burns.
    ///     2. Checks those burns for burns with the correct memo types to
    /// relay.     3. Extracts a map of responder_id to block_data for the
    /// block if there are relevant burns.     4. Calls the relevant api to
    /// send it the list of txos and the map of responder_ids to block_data.
    fn process_block(
        ledger: impl Ledger,
        watcher_db: WatcherDB,
        next_block: BlockIndex,
        poll_interval: Duration,
        logger: &Logger,
    ) -> Result<(), RelayerError> {
        let txos = Self::check_block_for_burns(ledger, next_block, logger)?;
        // There are no burns in this block so this block is finished processing.
        if (txos.is_empty()) {
            return Ok(());
        }
        let burns_with_relevant_memos = Self::check_burns_for_relevant_memo(txos, logger)?;
        // There are no burns with relevant memos in this block so this block is
        // finished processing.
        if (burns_with_relevant_memos.is_empty()) {
            return Ok(());
        }
        let mut block_data_map = watcher_db.get_block_data_map(next_block)?;
        while block_data_map.is_empty() {
            std::thread::sleep(poll_interval);
            block_data_map = watcher_db.get_block_data_map(next_block)?;
        }
        Self::forward_data_to_verifier(burns_with_relevant_memos, block_data_map, logger)
    }
    /// Function to check whether a burn_txo has a relevant memo for the
    /// relayer.
    fn check_burns_for_relevant_memo(
        txos: Vec<TxOut>,
        logger: &Logger,
    ) -> Result<Vec<TxOut>, RelayerError> {
        log::info!(
            logger,
            "Relayer: Checking these txos for a burn memo: {:?}",
            txos
        );
        for txo in &txos {
            // Reconstruct compressed commitment based on our view key.
            // The first step is reconstructing the TxOut shared secret
            //TODO: Fix this uwrap
            let public_key = RistrettoPublic::try_from(&txo.public_key).unwrap();
            let tx_out_shared_secret = mc_transaction_core::get_tx_out_shared_secret(
                &burn_address_view_private(),
                &public_key,
            );
            let memo = txo.decrypt_memo(&tx_out_shared_secret);
            let memo_data = memo.get_memo_data();
            let hex_string = hex::encode(&memo_data);
            // TODO: Actually filter this based on the memo somehow.
            log::info!(logger, "Relayer: the burn memo was: {:?}", hex_string);
        }
        Ok(txos)
    }

    ///  Function to send block data and txos to the verifier.
    fn forward_data_to_verifier(
        txos: Vec<TxOut>,
        block_data_map: HashMap<Url, BlockData>,
        logger: &Logger,
    ) -> Result<(), RelayerError> {
        log::info!(logger, "Relayer: The relevant burns were: {:?}", txos);
        for (url, blockdata) in block_data_map {
            let meta = blockdata.metadata().ok_or(RelayerError::BlockMetaData(
                "Found a burn on a block with no metadata".to_owned(),
            ))?;
            let responder_id = meta.contents().responder_id();
            log::info!(
                logger,
                "Relayer: The responder_id for {:?} was: {:?}",
                url,
                responder_id
            );
        }
        Ok(())
    }
}

impl Drop for RelayerThread {
    fn drop(&mut self) {
        self.stop();
    }
}

/// Watcher Errors
#[derive(Debug, Display)]
pub enum RelayerError {
    /// Failure with LedgerDB: {0}
    LedgerDB(LedgerDbError),
    /// Failure with WatcherDB: {0}
    WatcherDB(WatcherDBError),
    /// Invalid Block Metadata: {0}
    BlockMetaData(String),
    /// Not sure what this is for yet.
    UnknownError(),
}

impl From<LedgerDbError> for RelayerError {
    fn from(e: LedgerDbError) -> Self {
        Self::LedgerDB(e)
    }
}

impl From<WatcherDBError> for RelayerError {
    fn from(e: WatcherDBError) -> Self {
        Self::WatcherDB(e)
    }
}
