// Copyright (c) 2018-2020 MobileCoin Inc.

#![feature(external_doc)]
#![doc(include = "../../README.md")]

use mc_watcher::{config::WatcherConfig, watcher::Watcher, watcher_db::create_or_open_watcher_db};

use mc_common::logger::{create_app_logger, o};
use mc_ledger_sync::ReqwestTransactionsFetcher;
use structopt::StructOpt;

fn main() {
    mc_common::setup_panic_handler();
    let (logger, _global_logger_guard) = create_app_logger(o!());

    let config = WatcherConfig::from_args();

    let transactions_fetcher =
        ReqwestTransactionsFetcher::new(config.tx_source_urls.clone(), logger.clone())
            .expect("Failed creating ReqwestTransactionsFetcher");

    let watcher_db = create_or_open_watcher_db(
        config.watcher_db,
        &transactions_fetcher.source_urls,
        logger.clone(),
    )
    .expect("Could not create or open watcher db");
    let watcher = Watcher::new(watcher_db, transactions_fetcher, logger);
    // For now, ignore origin block, as it does not have a signature.
    watcher
        .sync_signatures(1, config.max_blocks)
        .expect("Could not sync signatures");
}
