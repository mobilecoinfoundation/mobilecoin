// Copyright (c) 2018-2020 MobileCoin Inc.

#![feature(external_doc)]
#![doc(include = "../../README.md")]

use mc_watcher::{config::WatcherConfig, watcher::Watcher};

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

    let watcher = Watcher::new(config.watcher_db, transactions_fetcher, logger);
    // For now, ignore origin block, as it does not have a signature.
    watcher.sync_signatures(1, config.max_blocks);
}
