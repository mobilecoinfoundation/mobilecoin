// Copyright (c) 2018-2020 MobileCoin Inc.

#![feature(external_doc)]
#![doc(include = "../../README.md")]

use mc_watcher::{config::WatcherConfig, watcher_db::WatcherDB};

use mc_api::conversions::block_num_to_s3block_path;
use mc_common::{
    logger::{create_app_logger, log, o},
    HashMap,
};
//use mc_ledger_db::{Ledger, LedgerDB};
use mc_ledger_sync::{ArchiveBlockData, ReqwestTransactionsFetcher};
use mc_transaction_core::BlockSignature;
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
    //LedgerDB::create(config.ledger_db.clone()).expect("Could not create LedgerDB");
    //let mut local_ledger = LedgerDB::open(config.ledger_db).expect("Failed opening LedgerDB");

    // Open WatcherDB
    WatcherDB::create(config.watcher_db.clone(), logger.clone())
        .expect("Could not create WatcherDB");
    let watcher_db =
        WatcherDB::open(config.watcher_db, logger.clone()).expect("Failed opening WatcherDB");

    /*
    // Sync Origin Block - FIXME: MC-1420 include origin signature
    log::debug!(logger, "Getting origin block");
    let (origin_block, origin_txs) = transactions_fetcher
        .get_origin_block_and_transactions()
        .expect("Could not retrieve origin block");
    local_ledger
        .append_block(&origin_block, &origin_txs, None)
        .expect("Could not append origin block to ledger");
    */

    // Sync all blocks and collect signatures
    let mut block_index = 1;
    loop {
        // Construct URL for the block we are trying to fetch.
        let filename = block_num_to_s3block_path(block_index)
            .into_os_string()
            .into_string()
            .unwrap();
        let mut archive_blocks: HashMap<String, ArchiveBlockData> = HashMap::default();
        let mut signatures: Vec<BlockSignature> = Vec::new();
        for src_url in transactions_fetcher.source_urls.iter() {
            let url = src_url.join(&filename).unwrap();

            // Try and get the block.
            log::debug!(
                logger,
                "Attempting to fetch block {} from {}",
                block_index,
                url
            );
            match transactions_fetcher.block_from_url(&url) {
                Ok(archive_block) => {
                    archive_blocks.insert(src_url.to_string(), archive_block.clone());
                    log::debug!(
                        logger,
                        "Got archve block {:?} for block index ({:?})",
                        archive_block,
                        block_index,
                    );
                    if let Some(signature) = archive_block.signature {
                        signatures.push(signature)
                    }
                }
                Err(err) => {
                    log::debug!(
                        logger,
                        "Done fetching transactions for {} blocks ({:?})",
                        block_index,
                        err
                    );
                    return;
                }
            }
        }
        println!(
            "\x1b[1;33m How many archive blocks for block ID? {}: {:?}\x1b[0m",
            block_index,
            archive_blocks.len()
        );
        println!(
            "\x1b[1;36m How many signatures for block ID? {}: {:?}\x1b[0m",
            block_index,
            signatures.len()
        );
        watcher_db
            .add_signatures(block_index, &signatures)
            .expect("Could not add signatures");

        // FIXME: If block is reconciled, append to ledger:
        // Reconcile block append new data to the ledger
        /*
        local_ledger
            .append_block(
                &archive_block.block,
                &archive_block.block_contents,
                archive_block.signature.as_ref(),
            )
            .unwrap_or_else(|_| panic!("Could not append block {:?}", block_index));
        */
        block_index += 1;
    }
}
