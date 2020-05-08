// Copyright (c) 2018-2020 MobileCoin Inc.

//! The watcher database

use crate::{
    error::{SignatureStoreError, WatcherDBError},
    signature_store::SignatureStore,
};

use mc_common::logger::Logger;
use mc_transaction_core::BlockSignature;
use mc_util_serial::{decode, encode};

use lmdb::{Database, DatabaseFlags, Environment, Transaction, WriteFlags};
use std::{path::PathBuf, sync::Arc};

/// LMDB Constant.
const MAX_LMDB_FILE_SIZE: usize = 1_099_511_627_776; // 1 TB

/// Keys used by the `counts` database.
const NUM_BLOCKS_KEY: &str = "num_blocks";

/// Counts database name.
pub const COUNTS_DB_NAME: &str = "ledger_db:counts";

#[derive(Clone)]
/// DB for Watcher Node.
pub struct WatcherDB {
    /// LMDB Environment (database).
    env: Arc<Environment>,

    /// Signature store.
    signature_store: SignatureStore,

    /// Aggregate counts about the watcher db.
    /// * `NUM_BLOCKS_KEY` ---> number of blocks in the watcher db.
    counts: Database,

    /// Logger.
    logger: Logger,
}

impl WatcherDB {
    /// Open an existing WatcherDB.
    pub fn open(path: PathBuf, logger: Logger) -> Result<Self, WatcherDBError> {
        let env = Arc::new(
            Environment::new()
                .set_max_dbs(10)
                .set_map_size(MAX_LMDB_FILE_SIZE)
                .open(path.as_ref())?,
        );
        let signature_store = SignatureStore::new(env.clone(), logger.clone())?;
        let counts = env.open_db(Some(COUNTS_DB_NAME))?;
        Ok(WatcherDB {
            env,
            signature_store,
            counts,
            logger,
        })
    }

    /// Create a fresh WatcherDB.
    pub fn create(path: PathBuf, logger: Logger) -> Result<Self, WatcherDBError> {
        let env = Arc::new(
            Environment::new()
                .set_max_dbs(10)
                .set_map_size(MAX_LMDB_FILE_SIZE)
                .open(path.as_ref())?,
        );

        let signature_store = SignatureStore::new(env.clone(), logger.clone())?;
        let counts = env.create_db(Some(COUNTS_DB_NAME), DatabaseFlags::empty())?;

        // let mut db_transaction = env.begin_rw_txn()?;
        // db_transaction.put(counts, &NUM_BLOCKS_KEY, &encode(&0), WriteFlags::empty())?;
        // db_transaction.commit()?;

        println!("\x1b[1;33m Created watcher db!\x1b[0m");

        Ok(WatcherDB {
            env,
            signature_store,
            counts,
            logger,
        })
    }

    /// Add a signature for a block.
    pub fn add_signatures(
        &self,
        block_index: u64,
        signatures: &Vec<BlockSignature>,
    ) -> Result<(), WatcherDBError> {
        let mut db_txn = self.env.begin_rw_txn()?;
        // Assumes always adding signatures to monotonically increasing block indices.
        let num_blocks = self.num_blocks()?;
        if block_index == num_blocks + 1 {
            db_txn.put(
                self.counts,
                &NUM_BLOCKS_KEY,
                &encode(&block_index),
                WriteFlags::empty(),
            )?;
        } else {
            return Err(WatcherDBError::BlockOrder);
        }
        self.signature_store
            .add_signatures(&mut db_txn, block_index, signatures)?;
        db_txn.commit()?;
        Ok(())
    }

    /// Get the signatures for a block.
    pub fn get_block_signatures(
        &self,
        block_index: u64,
    ) -> Result<Vec<BlockSignature>, WatcherDBError> {
        let db_txn = self.env.begin_ro_txn()?;
        match self.signature_store.get_signatures(&db_txn, block_index) {
            Ok(signatures) => Ok(signatures),
            Err(SignatureStoreError::NotFound) => Ok(Vec::new()),
            Err(e) => Err(WatcherDBError::SignatureStore(e)),
        }
    }

    /// Get the total number of Blocks in the watcher db.
    pub fn num_blocks(&self) -> Result<u64, WatcherDBError> {
        let db_txn = self.env.begin_ro_txn()?;
        Ok(decode(db_txn.get(self.counts, &NUM_BLOCKS_KEY)?)?)
    }
}
