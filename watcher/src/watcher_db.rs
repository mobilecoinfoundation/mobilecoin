// Copyright (c) 2018-2020 MobileCoin Inc.

//! The watcher database

use crate::{
    error::{SignatureStoreError, WatcherDBError},
    signature_store::SignatureStore,
};

use mc_common::logger::Logger;
use mc_transaction_core::{BlockID, BlockSignature};

use lmdb::{Environment, Transaction};
use std::{path::PathBuf, sync::Arc};

/// LMDB Constant
const MAX_LMDB_FILE_SIZE: usize = 1_099_511_627_776; // 1 TB

#[derive(Clone)]
/// DB for Watcher Node.
pub struct WatcherDB {
    /// LMDB Environment (database).
    env: Arc<Environment>,

    /// Signature store.
    signature_store: SignatureStore,

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
        // FIXME: load
        let signature_store = SignatureStore::new(env.clone(), logger.clone())?;
        Ok(WatcherDB {
            env,
            signature_store,
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

        Ok(WatcherDB {
            env,
            signature_store,
            logger,
        })
    }

    /// Add a signature for a block.
    pub fn add_block_signature(
        &self,
        block_id: &BlockID,
        signature: &BlockSignature,
    ) -> Result<(), WatcherDBError> {
        let mut db_txn = self.env.begin_rw_txn()?;
        self.signature_store
            .insert(&mut db_txn, block_id, signature)?;
        db_txn.commit()?;
        Ok(())
    }

    /// Get the signatures for a block.
    pub fn get_block_signatures(
        &self,
        block_id: &BlockID,
    ) -> Result<Vec<BlockSignature>, WatcherDBError> {
        let db_txn = self.env.begin_ro_txn()?;
        match self.signature_store.get_signatures(&db_txn, block_id) {
            Ok(signatures) => Ok(signatures),
            Err(SignatureStoreError::NotFound) => Ok(Vec::new()),
            Err(e) => Err(WatcherDBError::SignatureStore(e)),
        }
    }
}
