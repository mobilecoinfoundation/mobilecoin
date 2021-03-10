// Copyright (c) 2018-2021 The MobileCoin Foundation

//! Ledger migration: Perform updates of LedgerDB to accommodate for
//! backward-incompatible changes.

use lmdb::{DatabaseFlags, Environment, Transaction, WriteFlags};
use mc_common::logger::{create_app_logger, log, o, Logger};
use mc_ledger_db::{
    key_bytes_to_u64, tx_out_store::TX_OUT_INDEX_BY_PUBLIC_KEY_DB_NAME, u64_to_key_bytes, Error,
    LedgerDbMetadataStoreSettings, MetadataStore, TxOutStore, TxOutsByBlockValue,
    BLOCK_NUMBER_BY_TX_OUT_INDEX, COUNTS_DB_NAME, NUM_BLOCKS_KEY, TX_OUTS_BY_BLOCK_DB_NAME,
};
use mc_util_lmdb::MetadataStoreError;
use mc_util_serial::decode;
use std::{path::PathBuf, thread::sleep, time::Duration};
use structopt::StructOpt;

const MAX_LMDB_FILE_SIZE: usize = 1_099_511_627_776; // 1 TB

/// Command line configuration
#[derive(Clone, Debug, StructOpt)]
pub struct Config {
    /// Ledger DB path.
    #[structopt(long, parse(from_os_str))]
    pub ledger_db: PathBuf,
}

fn main() {
    let config = Config::from_args();

    mc_common::setup_panic_handler();
    let _sentry_guard = mc_common::sentry::init();
    let (logger, _global_logger_guard) = create_app_logger(o!());

    // Open the LMDB database.
    let env = Environment::new()
        .set_max_dbs(22)
        .set_map_size(MAX_LMDB_FILE_SIZE)
        .open(&config.ledger_db)
        .expect("Failed opening ledger db");

    // Create metadata store.
    let metadata_store = MetadataStore::<LedgerDbMetadataStoreSettings>::new(&env)
        .expect("Failed creating MetadataStore");

    // Incrementally perform upgrades until we reach the current version.
    loop {
        // Check if the database we opened is compatible with the current
        // implementation.
        let db_txn = env.begin_ro_txn().expect("Failed starting ro transaction");
        let version = metadata_store
            .get_version(&db_txn)
            .expect("Failed getting metadata version");
        log::info!(logger, "Ledger db is currently at version: {:?}", version);
        db_txn.commit().expect("Failed committing transaction");

        match version.is_compatible_with_latest() {
            Ok(_) => {
                break;
            }
            // Version 20200610 introduced the TxOut public key -> index store.
            Err(MetadataStoreError::VersionIncompatible(20200427, 20200610))
            | Err(MetadataStoreError::VersionIncompatible(20200427, 20200707)) => {
                log::info!(logger, "Ledger db migrating from version 20200427 to 20200610, this might take awhile...");

                construct_tx_out_index_by_public_key_from_existing_data(&env, &logger)
                    .expect("Failed constructing tx out index by public key database");

                let mut db_txn = env.begin_rw_txn().expect("Failed starting rw transaction");
                metadata_store
                    .set_version(&mut db_txn, 20200610)
                    .expect("Failed setting metadata version");
                log::info!(
                    logger,
                    "Ledger db migration complete, now at version: {:?}",
                    metadata_store.get_version(&db_txn),
                );
                db_txn.commit().expect("Failed committing transaction");
            }
            // Version 20200707 introduced the TxOut global index -> block index store.
            Err(MetadataStoreError::VersionIncompatible(20200610, 20200707)) => {
                log::info!(logger, "Ledger db migrating from version 20200610 to 20200707, this might take awhile...");

                construct_block_number_by_tx_out_index_from_existing_data(&env, &logger)
                    .expect("Failed constructing block number by tx out index database");

                let mut db_txn = env.begin_rw_txn().expect("Failed starting rw transaction");
                metadata_store
                    .set_version_to_latest(&mut db_txn)
                    .expect("Failed setting metadata version");
                log::info!(
                    logger,
                    "Ledger db migration complete, now at version: {:?}",
                    metadata_store.get_version(&db_txn),
                );
                db_txn.commit().expect("Failed committing transaction");
            }
            // Don't know how to migrate.
            Err(err) => {
                panic!("Error while migrating: {:?}", err);
            }
        };
    }

    // Give logger a moment to flush.
    sleep(Duration::from_secs(1));
}

/// A utility function for constructing the tx_out_index_by_public_key store
/// using existing data.
fn construct_tx_out_index_by_public_key_from_existing_data(
    env: &Environment,
    logger: &Logger,
) -> Result<(), Error> {
    // When constructing the tx out index by public key database, we first need to
    // create it.
    env.create_db(
        Some(TX_OUT_INDEX_BY_PUBLIC_KEY_DB_NAME),
        DatabaseFlags::empty(),
    )?;

    // After the database has been created, we can use TxOutStore as normal.
    let instance = TxOutStore::new(env)?;

    let mut db_txn = env.begin_rw_txn()?;

    let num_tx_outs = instance.num_tx_outs(&db_txn)?;
    let mut percents: u64 = 0;
    let tx_out_index_by_public_key = instance.get_tx_out_index_by_public_key_database();

    for tx_out_index in 0..num_tx_outs {
        let tx_out = instance.get_tx_out_by_index(tx_out_index, &db_txn)?;
        db_txn.put(
            tx_out_index_by_public_key,
            &tx_out.public_key,
            &u64_to_key_bytes(tx_out_index),
            WriteFlags::NO_OVERWRITE,
        )?;

        // Throttled logging.
        let new_percents = tx_out_index * 100 / num_tx_outs;
        if new_percents != percents {
            percents = new_percents;
            log::info!(
                logger,
                "Constructing tx_out_index_by_public_key: {}% complete",
                percents
            );
        }
    }
    Ok(db_txn.commit()?)
}

/// A utility function for constructing the block_number_by_tx_out_index store
/// using existing data.
fn construct_block_number_by_tx_out_index_from_existing_data(
    env: &Environment,
    logger: &Logger,
) -> Result<(), Error> {
    // When constructing the block index by tx out index database, we first need to
    // create it.
    let block_number_by_tx_out_index_db =
        env.create_db(Some(BLOCK_NUMBER_BY_TX_OUT_INDEX), DatabaseFlags::empty())?;

    // Open pre-existing databases that has data we need.
    let tx_outs_by_block_db = env.open_db(Some(TX_OUTS_BY_BLOCK_DB_NAME))?;
    let counts_db = env.open_db(Some(COUNTS_DB_NAME))?;

    // After the database has been created, populate it with the existing data.
    let mut db_txn = env.begin_rw_txn()?;

    let num_blocks = key_bytes_to_u64(&db_txn.get(counts_db, &NUM_BLOCKS_KEY)?);

    let mut percents: u64 = 0;
    for block_num in 0..num_blocks {
        // Get information about the TxOuts in the block.
        let bytes = db_txn.get(tx_outs_by_block_db, &u64_to_key_bytes(block_num))?;
        let tx_outs_by_block: TxOutsByBlockValue = decode(&bytes)?;

        log::trace!(
            logger,
            "Assigning tx outs #{} - #{} to block #{}",
            tx_outs_by_block.first_tx_out_index,
            tx_outs_by_block.first_tx_out_index + tx_outs_by_block.num_tx_outs,
            block_num,
        );

        for i in 0..tx_outs_by_block.num_tx_outs {
            let tx_out_index = tx_outs_by_block.first_tx_out_index + i;

            db_txn.put(
                block_number_by_tx_out_index_db,
                &u64_to_key_bytes(tx_out_index),
                &u64_to_key_bytes(block_num),
                WriteFlags::NO_OVERWRITE,
            )?;
        }

        // Throttled logging.
        let new_percents = block_num * 100 / num_blocks;
        if new_percents != percents {
            percents = new_percents;
            log::info!(
                logger,
                "Constructing block_number_by_tx_out_index: {}% complete",
                percents
            );
        }
    }
    Ok(db_txn.commit()?)
}
