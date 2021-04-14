// Copyright (c) 2018-2021 The MobileCoin Foundation

//! mobilecoind daemon entry point

use mc_attest_core::{MrSignerVerifier, Verifier, DEBUG_ENCLAVE};
use mc_common::logger::{create_app_logger, log, o, Logger};
use mc_ledger_db::{Ledger, LedgerDB};
use mc_ledger_sync::{LedgerSyncServiceThread, PollingNetworkState, ReqwestTransactionsFetcher};
use mc_mobilecoind::{
    config::Config, database::Database, payments::TransactionsManager, service::Service,
};
use mc_watcher::{watcher::WatcherSyncThread, watcher_db::create_or_open_rw_watcher_db};
use std::{
    path::Path,
    sync::{Arc, RwLock},
};
use structopt::StructOpt;

fn main() {
    let config = Config::from_args();
    if !cfg!(debug_assertions) && !config.offline {
        config.validate_host().expect("Could not validate host");
    }

    mc_common::setup_panic_handler();
    let _sentry_guard = mc_common::sentry::init();
    let (logger, _global_logger_guard) = create_app_logger(o!());

    let mut mr_signer_verifier =
        MrSignerVerifier::from(mc_consensus_enclave_measurement::sigstruct());
    mr_signer_verifier.allow_hardening_advisory("INTEL-SA-00334");

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
    let _ledger_sync_service_thread = if config.offline {
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
    let (watcher_db, _watcher_sync_thread) = match &config.watcher_db {
        Some(watcher_db_path) => {
            log::info!(logger, "Launching watcher.");

            log::info!(logger, "Opening watcher db at {:?}.", watcher_db_path);
            let watcher_db = create_or_open_rw_watcher_db(
                &watcher_db_path,
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
                        false,
                        logger.clone(),
                    )
                    .expect("Failed starting watcher thread"),
                )
            };
            (Some(watcher_db), watcher_sync_thread)
        }
        None => (None, None),
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
    // Attempt to open the ledger and see if it has anything in it.
    if let Ok(ledger_db) = LedgerDB::open(&config.ledger_db) {
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

    // Ledger doesn't exist, or is empty. Copy a bootstrapped ledger or try and get
    // it from the network.
    let ledger_db_file = Path::new(&config.ledger_db).join("data.mdb");
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

            let src = format!("{}/data.mdb", ledger_db_bootstrap);
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
            db.append_block(
                block_data.block(),
                block_data.contents(),
                block_data.signature().clone(),
            )
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
