// Copyright (c) 2018-2020 MobileCoin Inc.

#![feature(external_doc)]
#![doc(include = "../../README.md")]

use mc_watcher::{config::WatcherConfig, watcher_db::WatcherDB};

use mc_common::logger::{create_app_logger, log, o};
use mc_ledger_db::{Ledger, LedgerDB};
use mc_ledger_sync::ReqwestTransactionsFetcher;
use structopt::StructOpt;

fn main() {
    mc_common::setup_panic_handler();
    let (logger, _global_logger_guard) = create_app_logger(o!());

    let config = WatcherConfig::from_args();

    let transactions_fetcher =
        ReqwestTransactionsFetcher::new(config.tx_source_urls.clone(), logger.clone())
            .expect("Failed creating ReqwestTransactionsFetcher");

    log::debug!(
        logger,
        "Creating local ledger at {:?}",
        config.ledger_db.clone()
    );
    // Open LedgerDB
    LedgerDB::create(config.ledger_db.clone()).expect("Could not create LedgerDB");
    let mut local_ledger = LedgerDB::open(config.ledger_db).expect("Failed opening LedgerDB");

    // Open WatcherDB
    WatcherDB::create(config.watcher_db.clone(), logger.clone())
        .expect("Could not create WatcherDB");
    let mut _watcher_db =
        WatcherDB::open(config.watcher_db, logger.clone()).expect("Failed opening WatcherDB");

    // Sync Origin Block - FIXME: MC-1420 include origin signature
    log::debug!(logger, "Getting origin block");
    let (origin_block, origin_txs) = transactions_fetcher
        .get_origin_block_and_transactions()
        .expect("Could not retrieve origin block");
    local_ledger
        .append_block(&origin_block, &origin_txs, None)
        .expect("Could not append origin block to ledger");

    // Sync all blocks and collect signatures
}
