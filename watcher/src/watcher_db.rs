// Copyright (c) 2018-2020 MobileCoin Inc.

//! The watcher database

use crate::error::WatcherDBError;

use mc_common::{
    logger::{log, Logger},
    HashMap,
};
use mc_transaction_core::BlockSignature;
use mc_util_serial::{decode, encode, Message};

use lmdb::{Cursor, Database, DatabaseFlags, Environment, Transaction, WriteFlags};
use std::{convert::TryInto, path::PathBuf, sync::Arc};
use url::Url;

/// LMDB Constant.
const MAX_LMDB_FILE_SIZE: usize = 1_099_511_627_776; // 1 TB

/// Block signatures database name.
pub const BLOCK_SIGNATURES_DB_NAME: &str = "watcher_db:block_signatures";

/// Last synced archive blocks database name.
pub const LAST_SYNCED_DB_NAME: &str = "watcher_db:last_synced";

/// Block Signature Data for Signature Store.
#[derive(Message, Eq, PartialEq)]
pub struct BlockSignatureData {
    /// The src_url for the archive block.
    #[prost(message, required, tag = "1")]
    pub src_url: String,

    /// The archive filename.
    #[prost(message, required, tag = "2")]
    pub archive_filename: String,

    /// The block index.
    #[prost(message, required, tag = "3")]
    pub block_signature: BlockSignature,
}

#[derive(Clone)]
/// DB for Watcher Node.
pub struct WatcherDB {
    /// LMDB Environment (database).
    env: Arc<Environment>,

    /// Signature store.
    block_signatures: Database,

    /// Last synced archive block.
    last_synced: Database,

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
        let block_signatures = env.open_db(Some(BLOCK_SIGNATURES_DB_NAME))?;
        let last_synced = env.open_db(Some(LAST_SYNCED_DB_NAME))?;

        Ok(WatcherDB {
            env,
            block_signatures,
            last_synced,
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

        env.create_db(
            Some(BLOCK_SIGNATURES_DB_NAME),
            DatabaseFlags::DUP_SORT | DatabaseFlags::DUP_FIXED,
        )?;
        env.create_db(Some(LAST_SYNCED_DB_NAME), DatabaseFlags::empty())?;

        Ok(())
    }

    /// Add a block signature for a URL at a given block index.
    pub fn add_block_signature(
        &self,
        src_url: &Url,
        block_index: u64,
        block_signature: BlockSignature,
        archive_filename: String,
    ) -> Result<(), WatcherDBError> {
        let mut db_txn = self.env.begin_rw_txn()?;
        let signature_data = BlockSignatureData {
            src_url: src_url.as_str().to_string(),
            archive_filename,
            block_signature,
        };
        let key_bytes = block_index.to_be_bytes();
        let value_bytes = encode(&signature_data);
        db_txn.put(
            self.block_signatures,
            &key_bytes,
            &value_bytes,
            WriteFlags::empty(),
        )?;

        db_txn.put(
            self.last_synced,
            &src_url.as_str().as_bytes(),
            &key_bytes,
            WriteFlags::empty(),
        )?;
        db_txn.commit()?;
        Ok(())
    }

    /// Get the signatures for a block.
    pub fn get_block_signatures(
        &self,
        block_index: u64,
    ) -> Result<Vec<BlockSignatureData>, WatcherDBError> {
        let db_txn = self.env.begin_ro_txn()?;

        let mut cursor = db_txn.open_ro_cursor(self.block_signatures)?;
        let key_bytes = block_index.to_be_bytes();

        log::trace!(
            self.logger,
            "Getting block signatures for {:?}",
            block_index
        );

        match cursor.iter_dup_of(&key_bytes) {
            Ok(iter) => {
                let mut results: Vec<BlockSignatureData> = Vec::new();
                for (_key_bytes, value_bytes) in iter {
                    let signature_data: BlockSignatureData = decode(value_bytes)?;
                    log::trace!(
                        self.logger,
                        "Got block signatures for {:?} ({:?})",
                        block_index,
                        signature_data,
                    );
                    results.push(signature_data);
                }
                Ok(results)
            }
            Err(lmdb::Error::NotFound) => Ok(Vec::new()),
            Err(err) => Err(err.into()),
        }
    }

    /// Get the total number of Blocks in the watcher db.
    pub fn last_synced_blocks(
        &self,
        src_urls: &[Url],
    ) -> Result<HashMap<Url, Option<u64>>, WatcherDBError> {
        let db_txn = self.env.begin_ro_txn()?;
        let mut results = HashMap::default();

        for src_url in src_urls.iter() {
            match db_txn.get(self.last_synced, &src_url.as_str().as_bytes()) {
                Ok(block_index_bytes) => {
                    if block_index_bytes.len() == 8 {
                        let block_index = u64::from_be_bytes(block_index_bytes.try_into().unwrap());
                        results.insert(src_url.clone(), Some(block_index));
                    } else {
                        log::error!(
                            self.logger,
                            "Got invalid block index bytes {:?} for {}",
                            block_index_bytes,
                            src_url,
                        );
                    }
                }
                Err(lmdb::Error::NotFound) => {
                    results.insert(src_url.clone(), None);
                }
                Err(err) => {
                    return Err(err.into());
                }
            };
        }

        Ok(results)
    }

    /// In the case where a synced block did not have a signature, update last synced.
    pub fn update_last_synced(
        &self,
        src_url: &Url,
        block_index: u64,
    ) -> Result<(), WatcherDBError> {
        let mut db_txn = self.env.begin_rw_txn()?;
        db_txn.put(
            self.last_synced,
            &src_url.as_str().as_bytes(),
            &block_index.to_be_bytes(),
            WriteFlags::empty(),
        )?;
        db_txn.commit()?;
        Ok(())
    }
}

/// Open an existing WatcherDB or create a new one.
pub fn create_or_open_watcher_db(
    watcher_db_path: PathBuf,
    src_urls: &[Url],
    logger: Logger,
) -> Result<WatcherDB, WatcherDBError> {
    // Create the path if it does not exist.
    if !watcher_db_path.exists() {
        std::fs::create_dir_all(watcher_db_path.clone())?;
    }

    // Attempt to open the WatcherDB and see if it has anything in it.
    if let Ok(watcher_db) = WatcherDB::open(watcher_db_path.clone(), logger.clone()) {
        if let Ok(last_synced) = watcher_db.last_synced_blocks(src_urls) {
            if last_synced.values().any(|val| val.is_some()) {
                // Successfully opened a ledger that has blocks in it.
                log::info!(
                    logger,
                    "Watcher DB {:?} opened, sync status = {:?}",
                    watcher_db_path,
                    last_synced,
                );
                return Ok(watcher_db);
            }
        }
    }

    // WatcherDB does't exist, or is empty. Create a new WatcherDB, and open it.
    WatcherDB::create(watcher_db_path.clone())?;
    WatcherDB::open(watcher_db_path, logger)
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
        WatcherDB::create(db_tmp.path().to_path_buf()).unwrap();
        WatcherDB::open(db_tmp.path().to_path_buf(), logger).unwrap()
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
        let url1 = Url::parse("http://www.my_url1.com").unwrap();
        let url2 = Url::parse("http://www.my_url2.com").unwrap();
        let urls = vec![url1, url2];
        let watcher_db = setup_watcher_db(logger.clone());

        let blocks = setup_blocks();

        let signing_key_a = Ed25519Pair::from_random(&mut rng);
        let signing_key_b = Ed25519Pair::from_random(&mut rng);

        let filename = String::from("00/00");

        let signed_block_a1 =
            BlockSignature::from_block_and_keypair(&blocks[1].0, &signing_key_a).unwrap();
        watcher_db
            .add_block_signature(&urls[0], 1, signed_block_a1, filename.clone())
            .unwrap();

        let signed_block_b1 =
            BlockSignature::from_block_and_keypair(&blocks[1].0, &signing_key_b).unwrap();
        watcher_db
            .add_block_signature(&urls[1], 1, signed_block_b1, filename)
            .unwrap();

        assert_eq!(watcher_db.get_block_signatures(1).unwrap().len(), 2);
    }
}
