// Copyright (c) 2018-2022 The MobileCoin Foundation
#![deny(missing_docs)]
#![doc = include_str!("../README.md")]
#![forbid(unsafe_code)]

mod config;

use clap::Parser;
use config::LedgerFromArchiveConfig;
use mc_common::logger::{create_app_logger, log, o};
use mc_ledger_db::{create_ledger_in, Ledger};
use mc_ledger_sync::ReqwestTransactionsFetcher;

fn main() {
    mc_common::setup_panic_handler();
    let (logger, _global_logger_guard) = create_app_logger(o!());

    let config = LedgerFromArchiveConfig::parse();

    let transactions_fetcher =
        ReqwestTransactionsFetcher::new(config.tx_source_urls.clone(), logger.clone())
            .expect("Failed creating ReqwestTransactionsFetcher");

    log::info!(
        logger,
        "Creating local ledger at {}",
        config.ledger_db.display()
    );
    let mut local_ledger = create_ledger_in(&config.ledger_db);

    // Sync Origin Block
    log::info!(logger, "Getting origin block");
    let block_data = transactions_fetcher
        .get_origin_block_and_transactions()
        .expect("Could not retrieve origin block");
    local_ledger
        .append_block_data(&block_data)
        .expect("Could not append origin block to ledger");

    // Sync all blocks
    let mut block_index = 1;
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
                    .unwrap_or_else(|_| panic!("Could not append block {:?}", block_index))
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
