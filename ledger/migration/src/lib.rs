// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Ledger migration: Perform updates of LedgerDB to accommodate for
//! backward-incompatible changes.

#![allow(clippy::inconsistent_digit_grouping)]

use lmdb::{DatabaseFlags, Environment, Transaction, WriteFlags};
use mc_common::logger::{log, Logger};
use mc_ledger_db::{
    key_bytes_to_u64, tx_out_store::TX_OUT_INDEX_BY_PUBLIC_KEY_DB_NAME, u64_to_key_bytes, Error,
    LedgerDbMetadataStoreSettings, MetadataStore, MintConfigStore, TxOutStore, TxOutsByBlockValue,
    BLOCK_NUMBER_BY_TX_OUT_INDEX, COUNTS_DB_NAME, MAX_LMDB_DATABASES, MAX_LMDB_FILE_SIZE,
    NUM_BLOCKS_KEY, TX_OUTS_BY_BLOCK_DB_NAME,
};
use mc_util_lmdb::MetadataStoreError;
use mc_util_serial::decode;
use std::path::Path;

pub fn migrate(ledger_db_path: impl AsRef<Path>, logger: &Logger) {
    // Open the LMDB database.
    let env = Environment::new()
        .set_max_dbs(MAX_LMDB_DATABASES)
        .set_map_size(MAX_LMDB_FILE_SIZE)
        .open(ledger_db_path.as_ref())
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
            // Version 2020_06_10 came after 2020_04_27 and introduced the TxOut public key -> index
            // store.
            Err(MetadataStoreError::VersionIncompatible(2020_04_27, _)) => {
                log::info!(logger, "Ledger db migrating from version 2020_04_27 to 2020_06_10, this might take awhile...");

                construct_tx_out_index_by_public_key_from_existing_data(&env, logger)
                    .expect("Failed constructing tx out index by public key database");

                let mut db_txn = env.begin_rw_txn().expect("Failed starting rw transaction");
                metadata_store
                    .set_version(&mut db_txn, 2020_06_10)
                    .expect("Failed setting metadata version");
                log::info!(
                    logger,
                    "Ledger db migration complete, now at version: {:?}",
                    metadata_store.get_version(&db_txn),
                );
                db_txn.commit().expect("Failed committing transaction");
            }
            // Version 2020_07_07 came after 2020_06_10 introduced the TxOut global index -> block index
            // store.
            Err(MetadataStoreError::VersionIncompatible(2020_06_10, _)) => {
                log::info!(logger, "Ledger db migrating from version 2020_06_10 to 2020_07_07, this might take awhile...");

                construct_block_number_by_tx_out_index_from_existing_data(&env, logger)
                    .expect("Failed constructing block number by tx out index database");

                let mut db_txn = env.begin_rw_txn().expect("Failed starting rw transaction");
                metadata_store
                    .set_version(&mut db_txn, 2020_07_07)
                    .expect("Failed setting metadata version");
                log::info!(
                    logger,
                    "Ledger db migration complete, now at version: {:?}",
                    metadata_store.get_version(&db_txn),
                );
                db_txn.commit().expect("Failed committing transaction");
            }
            // Version 2022_02_22 came after 2020_07_07 introduced minting.
            Err(MetadataStoreError::VersionIncompatible(2020_07_07, _)) => {
                log::info!(
                    logger,
                    "Ledger db migrating from version 2020_07_07 to 2022_02_22..."
                );
                MintConfigStore::create(&env).expect("Failed creating MintConfigStore");

                let mut db_txn = env.begin_rw_txn().expect("Failed starting rw transaction");
                metadata_store
                    .set_version(&mut db_txn, 2022_02_22)
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

    let num_blocks = key_bytes_to_u64(db_txn.get(counts_db, &NUM_BLOCKS_KEY)?);

    let mut percents: u64 = 0;
    for block_num in 0..num_blocks {
        // Get information about the TxOuts in the block.
        let bytes = db_txn.get(tx_outs_by_block_db, &u64_to_key_bytes(block_num))?;
        let tx_outs_by_block: TxOutsByBlockValue = decode(bytes)?;

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
