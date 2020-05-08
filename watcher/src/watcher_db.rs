// Copyright (c) 2018-2020 MobileCoin Inc.

//! The watcher database

use crate::error::WatcherDBError;

use mc_common::logger::{log, Logger};
use mc_transaction_core::BlockSignature;
use mc_util_serial::{decode, encode};

use lmdb::{Cursor, Database, DatabaseFlags, Environment, Transaction, WriteFlags};
use std::{path::PathBuf, sync::Arc};

/// LMDB Constant.
const MAX_LMDB_FILE_SIZE: usize = 1_099_511_627_776; // 1 TB

/// Keys used by the `counts` database.
const NUM_BLOCKS_KEY: &str = "num_blocks";

/// Counts database name.
pub const COUNTS_DB_NAME: &str = "watcher_db:counts";

/// Block signatures database name.
pub const BLOCK_SIGNATURES_DB_NAME: &str = "watcher_db:block_signatures";

#[derive(Clone)]
/// DB for Watcher Node.
pub struct WatcherDB {
    /// LMDB Environment (database).
    env: Arc<Environment>,

    /// Signature store.
    block_signatures: Database,

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
        let counts = env.open_db(Some(COUNTS_DB_NAME))?;
        let block_signatures = env.open_db(Some(BLOCK_SIGNATURES_DB_NAME))?;

        Ok(WatcherDB {
            env,
            block_signatures,
            counts,
            logger,
        })
    }

    /// Create a fresh WatcherDB.
    pub fn create(path: PathBuf) -> Result<(), WatcherDBError> {
        let env = Arc::new(
            Environment::new()
                .set_max_dbs(10)
                .set_map_size(MAX_LMDB_FILE_SIZE)
                .open(path.as_ref())?,
        );

        let counts = env.create_db(Some(COUNTS_DB_NAME), DatabaseFlags::empty())?;
        env.create_db(
            Some(BLOCK_SIGNATURES_DB_NAME),
            DatabaseFlags::DUP_SORT | DatabaseFlags::DUP_FIXED,
        )?;

        let mut db_txn = env.begin_rw_txn()?;
        db_txn.put(counts, &NUM_BLOCKS_KEY, &encode(&0), WriteFlags::empty())?;
        db_txn.commit()?;
        Ok(())
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

        let key_bytes = encode(&block_index);
        for signature in signatures {
            let value_bytes = encode(signature);
            db_txn.put(
                self.block_signatures,
                &key_bytes,
                &value_bytes,
                WriteFlags::empty(),
            )?;
        }
        db_txn.commit()?;
        Ok(())
    }

    /// Get the signatures for a block.
    pub fn get_block_signatures(
        &self,
        block_index: u64,
    ) -> Result<Vec<BlockSignature>, WatcherDBError> {
        let db_txn = self.env.begin_ro_txn()?;

        let mut cursor = db_txn.open_ro_cursor(self.block_signatures)?;
        let key_bytes = encode(&block_index);

        log::trace!(
            self.logger,
            "Getting block signatures for {:?}",
            block_index
        );

        match cursor.iter_dup_of(&key_bytes) {
            Ok(iter) => {
                let mut results: Vec<BlockSignature> = Vec::new();
                for (_key_bytes, value_bytes) in iter {
                    let block_signature = decode(value_bytes)?;
                    log::trace!(
                        self.logger,
                        "Got block signatures for {:?} ({:?})",
                        block_index,
                        block_signature,
                    );
                    results.push(block_signature);
                }
                Ok(results)
            }
            Err(lmdb::Error::NotFound) => Ok(Vec::new()),
            Err(err) => Err(err.into()),
        }
    }

    /// Get the total number of Blocks in the watcher db.
    pub fn num_blocks(&self) -> Result<u64, WatcherDBError> {
        let db_txn = self.env.begin_ro_txn()?;
        Ok(decode(db_txn.get(self.counts, &NUM_BLOCKS_KEY)?)?)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use mc_common::logger::{test_with_logger, Logger};
    use mc_crypto_keys::Ed25519Pair;
    use mc_transaction_core::{account_keys::AccountKey, Block, BlockContents};
    use mc_transaction_core_test_utils::get_blocks;
    use mc_util_from_random::FromRandom;
    use rand_core::SeedableRng;
    use rand_hc::Hc128Rng;
    use tempdir::TempDir;

    fn setup_watcher_db(logger: Logger) -> WatcherDB {
        let db_tmp = TempDir::new("wallet_db").expect("Could not make tempdir for wallet db");
        let db_path = db_tmp.path().to_str().unwrap();
        WatcherDB::create(db_path, env, logger).unwrap()
    }

    fn setup_blocks() -> Vec<(Block, BlockContents)> {
        let mut rng: Hc128Rng = Hc128Rng::from_seed([8u8; 32]);
        let origin = Block::new_origin_block(&[]);

        let accounts: Vec<AccountKey> = (0..20).map(|_i| AccountKey::random(&mut rng)).collect();
        let recipient_pub_keys = accounts
            .iter()
            .map(|account| account.default_subaddress())
            .collect::<Vec<_>>();
        get_blocks(&recipient_pub_keys, 10, 1, 10, &origin, &mut rng)
    }

    // SignatureStore should insert and get multiple signatures.
    #[test_with_logger]
    fn test_insert_and_get(logger: Logger) {
        let mut rng: Hc128Rng = Hc128Rng::from_seed([8u8; 32]);
        let sig_store = setup_watcher_db(logger.clone());

        let blocks = setup_blocks();

        let signing_key_a = Ed25519Pair::from_random(&mut rng);
        let signing_key_b = Ed25519Pair::from_random(&mut rng);

        let signed_block_a1 =
            BlockSignature::from_block_and_keypair(&blocks[1].0, &signing_key_a).unwrap();
        let _signed_block_b1 =
            BlockSignature::from_block_and_keypair(&blocks[1].0, &signing_key_b).unwrap();

        let mut db_txn = sig_store.env.begin_rw_txn().unwrap();
        sig_store
            .add_signatures(&mut db_txn, 1, &vec![signed_block_a1])
            .unwrap();
        db_txn.commit().unwrap();

        let db_ro_txn = sig_store.env.begin_ro_txn().unwrap();
        assert_eq!(sig_store.get_signatures(&db_ro_txn, 1).unwrap().len(), 1);
    }
}
