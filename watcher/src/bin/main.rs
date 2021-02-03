// Copyright (c) 2018-2021 The MobileCoin Foundation

#![feature(external_doc)]
#![doc(include = "../../README.md")]

//! A standalone watcher program that can sync data from multiple sources.

use mc_watcher::{
    config::WatcherConfig, verification_reports_collector::VerificationReportsCollector,
    watcher::Watcher, watcher_db::create_or_open_rw_watcher_db,
};

use mc_common::logger::{create_app_logger, log, o};
use mc_ledger_sync::ReqwestTransactionsFetcher;
use std::thread::sleep;
use structopt::StructOpt;

fn main() {
    mc_common::setup_panic_handler();
    let (logger, _global_logger_guard) = create_app_logger(o!());

    let config = WatcherConfig::from_args();
    let sources_config = config.sources_config();

    let transactions_fetcher =
        ReqwestTransactionsFetcher::new(sources_config.tx_source_urls(), logger.clone())
            .expect("Failed creating ReqwestTransactionsFetcher");

    let watcher_db = create_or_open_rw_watcher_db(
        config.watcher_db,
        &transactions_fetcher.source_urls,
        logger.clone(),
    )
    .expect("Could not create or open watcher db");
    let watcher = Watcher::new(
        watcher_db.clone(),
        transactions_fetcher,
        config.store_block_data,
        logger.clone(),
    );

    let _verification_reports_collector = <VerificationReportsCollector>::new(
        watcher_db,
        sources_config.tx_source_urls_to_consensus_client_urls(),
        config.poll_interval,
        logger.clone(),
    );

    loop {
        // For now, ignore origin block, as it does not have a signature.
        let syncing_done = watcher
            .sync_blocks(1, config.max_block_height)
            .expect("Could not sync signatures");
        if syncing_done {
            log::info!(logger, "sync_signatures indicates we're done");
            break;
        }

        sleep(config.poll_interval);
    }
}
