// Copyright (c) 2018-2022 The MobileCoin Foundation
#![deny(missing_docs)]
#![doc = include_str!("../README.md")]
#![forbid(unsafe_code)]

mod config;

use std::path::Path;
use clap::Parser;
use config::LedgerFromArchiveConfig;
use mc_common::logger::{create_app_logger, log, Logger, o};
use mc_ledger_db::{create_ledger_in, Ledger, LedgerDB};
use mc_ledger_sync::ReqwestTransactionsFetcher;

fn main() {
    let (logger, _global_logger_guard) = create_app_logger(o!());
    mc_common::setup_panic_handler();

    let config = LedgerFromArchiveConfig::parse();

    let transactions_fetcher =
        ReqwestTransactionsFetcher::new(config.tx_source_urls.clone(), logger.clone())
            .expect("Failed creating ReqwestTransactionsFetcher");

    let mut local_ledger = ledger_db(&logger, config.ledger_db, &transactions_fetcher);

    // Sync all blocks
    let mut block_index = local_ledger.num_blocks().expect("Should have blocks in the ledger");
    loop {
        if let Some(block_limit) = config.num_blocks {
            if block_index >= block_limit {
                log::info!(
                    logger,
                    "Done fetching transactions for {} blocks",
                    block_index,
                );
                return;
            }
        }

        // Try and get the block.
        log::info!(logger, "Attempting to fetch block {}", block_index,);
        match transactions_fetcher.get_block_data_by_index(block_index, None) {
            Ok(block_data) => {
                // Append new data to the ledger
                local_ledger
                    .append_block_data(&block_data)
                    .unwrap_or_else(|_| panic!("Could not append block {block_index:?}"))
            }
            Err(err) => {
                log::info!(
                    logger,
                    "Done fetching transactions for {} blocks ({:?})",
                    block_index,
                    err
                );
                return;
            }
        }
        block_index += 1;
    }
}

fn ledger_db(logger: &Logger, ledger_path: impl AsRef<Path>, transactions_fetcher: &ReqwestTransactionsFetcher) -> LedgerDB {
    match ledger_path.as_ref().exists() {
        true => {
            log::info!(logger, "Opening existing ledger at {}", ledger_path.as_ref().display());
            LedgerDB::open(ledger_path.as_ref()).expect("Could not open existing ledger")
        }
        false => create_ledger_db(logger, ledger_path, transactions_fetcher)
    }
}

fn create_ledger_db(logger: &Logger, ledger_path: impl AsRef<Path>, transactions_fetcher: &ReqwestTransactionsFetcher) -> LedgerDB {
    let ledger_path = ledger_path.as_ref();
    log::info!(
        logger,
        "Creating local ledger at {}",
        ledger_path.display()
    );
    let mut local_ledger = create_ledger_in(ledger_path);

    // Sync Origin Block
    log::info!(logger, "Getting origin block");
    let block_data = transactions_fetcher
        .get_origin_block_and_transactions()
        .expect("Could not retrieve origin block");
    local_ledger
        .append_block_data(&block_data)
        .expect("Could not append origin block to ledger");
    local_ledger
}
