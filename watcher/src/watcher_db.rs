// Copyright (c) 2018-2020 MobileCoin Inc.

//! The watcher database

use crate::error::WatcherDBError;

use mc_common::{
    logger::{log, Logger},
    HashMap,
};
use mc_transaction_core::BlockSignature;
use mc_util_lmdb::{MetadataStore, MetadataStoreSettings};
use mc_util_serial::{decode, encode, Message};
use mc_watcher_api::TimestampResultCode;

use lmdb::{Cursor, Database, DatabaseFlags, Environment, RoTransaction, Transaction, WriteFlags};
use std::{convert::TryInto, path::PathBuf, str::FromStr, sync::Arc};
use url::Url;

/// LMDB Constant.
const MAX_LMDB_FILE_SIZE: usize = 1_099_511_627_776; // 1 TB

/// Metadata store settings that are used for version control.
#[derive(Clone, Default, Debug)]
pub struct WatcherDbMetadataStoreSettings;
impl MetadataStoreSettings for WatcherDbMetadataStoreSettings {
    // Default database version. This should be bumped when breaking changes are introduced.
    // If this is properly maintained, we could check during ledger db opening for any
    // incompatibilities, and either refuse to open or perform a migration.
    #[allow(clippy::unreadable_literal)]
    const LATEST_VERSION: u64 = 20200805;

    /// The current crate version that manages the database.
    const CRATE_VERSION: &'static str = env!("CARGO_PKG_VERSION");

    /// LMDB Database name to use for storing the metadata information.
    const DB_NAME: &'static str = "watcher_db_metadata";
}

/// Block signatures database name.
pub const BLOCK_SIGNATURES_DB_NAME: &str = "watcher_db:block_signatures";

/// Last synced archive blocks database name.
pub const LAST_SYNCED_DB_NAME: &str = "watcher_db:last_synced";

/// Last known config database name.
pub const CONFIG_DB_NAME: &str = "watcher_db:config";

/// Keys used by the `config` database.
pub const CONFIG_DB_KEY_TX_SOURCE_URLS: &str = "tx_source_urls";

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

    /// Config database - stores the settings the watcher was started with.
    /// This allows the code that reads data from the database to only look at the set of URLs
    /// currently being polled.
    config: Database,

    /// Were we opened in write mode?
    write_allowed: bool,

    /// Metadata store.
    metadata_store: MetadataStore<WatcherDbMetadataStoreSettings>,

    /// Logger.
    logger: Logger,
}

impl WatcherDB {
    /// Open an existing WatcherDB for read-only operations.
    pub fn open_ro(path: PathBuf, logger: Logger) -> Result<Self, WatcherDBError> {
        let env = Arc::new(
            Environment::new()
                .set_max_dbs(10)
                .set_map_size(MAX_LMDB_FILE_SIZE)
                .open(path.as_ref())?,
        );

        let metadata_store = MetadataStore::<WatcherDbMetadataStoreSettings>::new(&env)?;

        let db_txn = env.begin_ro_txn()?;
        let version = metadata_store.get_version(&db_txn)?;
        log::info!(logger, "Watcher db is currently at version: {:?}", version);
        db_txn.commit()?;

        version.is_compatible_with_latest()?;

        let block_signatures = env.open_db(Some(BLOCK_SIGNATURES_DB_NAME))?;
        let last_synced = env.open_db(Some(LAST_SYNCED_DB_NAME))?;
        let config = env.open_db(Some(CONFIG_DB_NAME))?;

        Ok(WatcherDB {
            env,
            block_signatures,
            last_synced,
            config,
            write_allowed: false,
            metadata_store,
            logger,
        })
    }

    /// Open an existing WatcherDB for read-write operations.
    pub fn open_rw(
        path: PathBuf,
        tx_source_urls: &[Url],
        logger: Logger,
    ) -> Result<Self, WatcherDBError> {
        let mut db = Self::open_ro(path, logger)?;
        db.write_allowed = true;
        db.store_config(tx_source_urls)?;
        Ok(db)
    }

    /// Create a fresh WatcherDB.
    pub fn create(path: PathBuf) -> Result<(), WatcherDBError> {
        let env = Arc::new(
            Environment::new()
                .set_max_dbs(10)
                .set_map_size(MAX_LMDB_FILE_SIZE)
                .open(path.as_ref())?,
        );

        MetadataStore::<WatcherDbMetadataStoreSettings>::create(&env)?;

        env.create_db(Some(BLOCK_SIGNATURES_DB_NAME), DatabaseFlags::DUP_SORT)?;
        env.create_db(Some(LAST_SYNCED_DB_NAME), DatabaseFlags::empty())?;
        env.create_db(Some(CONFIG_DB_NAME), DatabaseFlags::DUP_SORT)?;

        Ok(())
    }

    /// Get the current set of configured URLs.
    pub fn get_config_urls(&self) -> Result<Vec<Url>, WatcherDBError> {
        let db_txn = self.env.begin_ro_txn()?;
        self.get_config_urls_with_txn(&db_txn)
    }

    /// Add a block signature for a URL at a given block index.
    pub fn add_block_signature(
        &self,
        src_url: &Url,
        block_index: u64,
        block_signature: BlockSignature,
        archive_filename: String,
    ) -> Result<(), WatcherDBError> {
        if !self.write_allowed {
            return Err(WatcherDBError::ReadOnly);
        }

        let mut db_txn = self.env.begin_rw_txn()?;

        // Sanity test - the URL needs to be configured.
        let urls = self.get_config_urls_with_txn(&db_txn)?;
        if !urls.contains(&src_url) {
            return Err(WatcherDBError::NotFound);
        }

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

        Ok(cursor
            .iter_dup_of(&key_bytes)
            .map(|result| {
                result
                    .map_err(WatcherDBError::from)
                    .and_then(|(key_bytes2, value_bytes)| {
                        // Sanity check.
                        assert_eq!(key_bytes, key_bytes2);

                        let signature_data: BlockSignatureData = decode(value_bytes)?;
                        log::trace!(
                            self.logger,
                            "Got block signatures for {:?} ({:?})",
                            block_index,
                            signature_data,
                        );
                        Ok(signature_data)
                    })
            })
            .collect::<Result<Vec<_>, WatcherDBError>>()?)
    }

    /// Get the earliest timestamp for a given block.
    /// The earliest timestamp reflects the time closest to when the block passed consensus.
    /// If no timestamp is present, return u64::MAX, and a status code.
    ///
    /// Note: If there are no Signatures (and therefore no timestamps) for the given
    ///       block, the result from get_signatures will be Ok(vec![]).
    ///       A consensus validator only writes a signature for a block in which it
    ///       participated in consensus. Therefore, if the watcher is only watching
    ///       a subset of nodes, and those nodes happened to not participate in this
    ///       block, the timestamp result will be unavailable for this block. It is
    ///       also possible to be in a temporary state where there are no signatures
    ///       for the given block if the watcher sync is behind the ledger sync.
    pub fn get_block_timestamp(
        &self,
        block_index: u64,
    ) -> Result<(u64, TimestampResultCode), WatcherDBError> {
        if block_index == 0 || block_index == u64::MAX {
            return Ok((u64::MAX, TimestampResultCode::BlockIndexOutOfBounds));
        }
        let sigs = self.get_block_signatures(block_index)?;
        match sigs.iter().map(|s| s.block_signature.signed_at()).min() {
            Some(earliest) => Ok((earliest, TimestampResultCode::TimestampFound)),
            None => {
                // Check whether we are synced for all watched URLs
                let highest_common = self.highest_common_block()?;
                if highest_common < block_index {
                    Ok((u64::MAX, TimestampResultCode::WatcherBehind))
                } else {
                    Ok((u64::MAX, TimestampResultCode::Unavailable))
                }
            }
        }
    }

    /// Get the last synced block per configured url.
    pub fn last_synced_blocks(&self) -> Result<HashMap<Url, Option<u64>>, WatcherDBError> {
        let db_txn = self.env.begin_ro_txn()?;
        self.get_url_to_last_synced(&db_txn)
    }

    /// In the case where a synced block did not have a signature, update last synced.
    pub fn update_last_synced(
        &self,
        src_url: &Url,
        block_index: u64,
    ) -> Result<(), WatcherDBError> {
        if !self.write_allowed {
            return Err(WatcherDBError::ReadOnly);
        }

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

    /// Get the highest block that all currently-configured urls have synced.
    /// Note: In the case where one watched consensus validator dies and is no longer
    ///       reporting blocks to S3, this will cause the highest_common_block to
    ///       always remain at the lowest common denominator, so in the case where the
    ///       the highest_common_block is being used to determine if the watcher is
    ///       behind, the watcher will need to be restarted with the dead node removed
    ///       from the set of watched URLs.
    pub fn highest_common_block(&self) -> Result<u64, WatcherDBError> {
        let db_txn = self.env.begin_ro_txn()?;

        let last_synced_map = self.get_url_to_last_synced(&db_txn)?;

        let last_synced: Vec<u64> = last_synced_map
            .values()
            .map(|opt_block_index| {
                // If this URL has never added a signature, it is at 0
                opt_block_index.unwrap_or(0)
            })
            .collect();

        Ok(*last_synced.iter().min().unwrap_or(&0))
    }

    /// Store the current configuration into the database.
    fn store_config(&self, tx_source_urls: &[Url]) -> Result<(), WatcherDBError> {
        assert!(self.write_allowed);

        let mut db_txn = self.env.begin_rw_txn()?;

        match db_txn.del(self.config, &CONFIG_DB_KEY_TX_SOURCE_URLS, None) {
            Ok(_) | Err(lmdb::Error::NotFound) => {}
            Err(err) => return Err(WatcherDBError::LmdbError(err)),
        };
        for url in tx_source_urls.iter() {
            db_txn.put(
                self.config,
                &CONFIG_DB_KEY_TX_SOURCE_URLS,
                &url.to_string(),
                WriteFlags::empty(),
            )?;
        }

        db_txn.commit()?;

        Ok(())
    }

    /// Get the current set of configured URLs.
    pub fn get_config_urls_with_txn(
        &self,
        db_txn: &impl Transaction,
    ) -> Result<Vec<Url>, WatcherDBError> {
        let mut cursor = db_txn.open_ro_cursor(self.config)?;

        Ok(cursor
            .iter_dup_of(&CONFIG_DB_KEY_TX_SOURCE_URLS)
            .filter_map(|r| r.ok())
            .map(|(_db_key, db_value)| {
                Url::from_str(
                    &String::from_utf8(db_value.to_vec())
                        .expect("from_utf8 failed: corrupted config db?"),
                )
                .expect("Url::from_str failed: corrupted config db?")
            })
            .collect())
    }

    // Helper method to get a map of Url -> Last Synced Block
    fn get_url_to_last_synced(
        &self,
        db_txn: &RoTransaction,
    ) -> Result<HashMap<Url, Option<u64>>, WatcherDBError> {
        let src_urls = self.get_config_urls_with_txn(db_txn)?;

        let mut results = HashMap::default();
        for src_url in src_urls.iter() {
            match db_txn.get(self.last_synced, &src_url.to_string()) {
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
}

/// Open an existing WatcherDB or create a new one in read-write mode.
pub fn create_or_open_rw_watcher_db(
    watcher_db_path: PathBuf,
    src_urls: &[Url],
    logger: Logger,
) -> Result<WatcherDB, WatcherDBError> {
    // Create the path if it does not exist.
    if !watcher_db_path.exists() {
        std::fs::create_dir_all(watcher_db_path.clone())?;
    }

    // Attempt to open the WatcherDB and see if it has anything in it.
    if let Ok(watcher_db) = WatcherDB::open_rw(watcher_db_path.clone(), src_urls, logger.clone()) {
        if let Ok(last_synced) = watcher_db.last_synced_blocks() {
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
    WatcherDB::open_rw(watcher_db_path, src_urls, logger)
}

#[cfg(test)]
mod test {
    use super::*;
    use mc_account_keys::AccountKey;
    use mc_common::logger::{test_with_logger, Logger};
    use mc_crypto_keys::Ed25519Pair;
    use mc_transaction_core::{Block, BlockContents};
    use mc_transaction_core_test_utils::get_blocks;
    use mc_util_from_random::FromRandom;
    use mc_util_test_helper::run_with_one_seed;
    use rand_core::SeedableRng;
    use rand_hc::Hc128Rng;
    use tempdir::TempDir;

    fn setup_watcher_db(src_urls: &[Url], logger: Logger) -> WatcherDB {
        let db_tmp = TempDir::new("wallet_db").expect("Could not make tempdir for wallet db");
        WatcherDB::create(db_tmp.path().to_path_buf()).unwrap();
        WatcherDB::open_rw(db_tmp.path().to_path_buf(), src_urls, logger).unwrap()
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
        let watcher_db = setup_watcher_db(&urls, logger.clone());

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

    // Highest synced block should return the minimum highest synced block for all URLs
    #[test_with_logger]
    fn test_highest_synced(logger: Logger) {
        run_with_one_seed(|mut rng| {
            let url1 = Url::parse("http://www.my_url1.com").unwrap();
            let url2 = Url::parse("http://www.my_url2.com").unwrap();
            let urls = vec![url1, url2];
            let watcher_db = setup_watcher_db(&urls, logger.clone());

            let blocks = setup_blocks();

            let signing_key_a = Ed25519Pair::from_random(&mut rng);
            let signing_key_b = Ed25519Pair::from_random(&mut rng);

            let filename1 = String::from("00/01");

            let signed_block_a1 =
                BlockSignature::from_block_and_keypair(&blocks[1].0, &signing_key_a).unwrap();
            watcher_db
                .add_block_signature(&urls[0], 1, signed_block_a1, filename1.clone())
                .unwrap();

            let signed_block_b1 =
                BlockSignature::from_block_and_keypair(&blocks[1].0, &signing_key_b).unwrap();
            watcher_db
                .add_block_signature(&urls[1], 1, signed_block_b1, filename1)
                .unwrap();

            assert_eq!(watcher_db.highest_common_block().unwrap(), 1);

            let filename2 = String::from("00/02");

            let signed_block_a2 =
                BlockSignature::from_block_and_keypair(&blocks[2].0, &signing_key_a).unwrap();
            watcher_db
                .add_block_signature(&urls[0], 2, signed_block_a2, filename2.clone())
                .unwrap();

            assert_eq!(watcher_db.highest_common_block().unwrap(), 1);

            let signed_block_b2 =
                BlockSignature::from_block_and_keypair(&blocks[2].0, &signing_key_b).unwrap();
            watcher_db
                .add_block_signature(&urls[1], 2, signed_block_b2, filename2)
                .unwrap();

            assert_eq!(watcher_db.highest_common_block().unwrap(), 2);
        });
    }

    // Config URL storage should behave as expected.
    #[test_with_logger]
    fn test_config_urls(logger: Logger) {
        let watcher_db = setup_watcher_db(&[], logger.clone());

        // Initially, the configuration is empty.
        assert!(watcher_db
            .get_config_urls()
            .expect("get_config_urls failed")
            .is_empty());

        // Store 2 URLs and make sure they can be retreived successfully.
        let tx_source_urls = vec![
            Url::parse("http://www.url1.com").unwrap(),
            Url::parse("http://www.url2.com").unwrap(),
        ];
        watcher_db
            .store_config(&tx_source_urls)
            .expect("store_config failed");

        assert_eq!(
            tx_source_urls,
            watcher_db
                .get_config_urls()
                .expect("get_config_urls failed")
        );

        // Store a different set of URLs and verify they replace the previous set.
        let tx_source_urls = vec![
            Url::parse("http://www.url3.com").unwrap(),
            Url::parse("http://www.url4.com").unwrap(),
            Url::parse("http://www.url5.com").unwrap(),
        ];

        watcher_db
            .store_config(&tx_source_urls)
            .expect("store_config failed");

        assert_eq!(
            tx_source_urls,
            watcher_db
                .get_config_urls()
                .expect("get_config_urls failed")
        );
    }

    // Watcher should return timestamps based on watched nodes' signature.signed_at values
    #[test_with_logger]
    fn test_timestamps(logger: Logger) {
        run_with_one_seed(|mut rng| {
            let url1 = Url::parse("http://www.my_url1.com").unwrap();
            let url2 = Url::parse("http://www.my_url2.com").unwrap();
            let urls = vec![url1, url2];
            let watcher_db = setup_watcher_db(&urls, logger.clone());

            let blocks = setup_blocks();

            let signing_key_a = Ed25519Pair::from_random(&mut rng);
            let signing_key_b = Ed25519Pair::from_random(&mut rng);

            let filename1 = String::from("00/01");

            let mut signed_block_a1 =
                BlockSignature::from_block_and_keypair(&blocks[1].0, &signing_key_a).unwrap();
            signed_block_a1.set_signed_at(1594679718);
            watcher_db
                .add_block_signature(&urls[0], 1, signed_block_a1, filename1.clone())
                .unwrap();

            let mut signed_block_b1 =
                BlockSignature::from_block_and_keypair(&blocks[1].0, &signing_key_b).unwrap();
            signed_block_b1.set_signed_at(1594679727);
            watcher_db
                .add_block_signature(&urls[1], 1, signed_block_b1, filename1)
                .unwrap();

            // Timestamp for 1st block should be the minimum of the available timestamps
            assert_eq!(
                watcher_db.get_block_timestamp(1).unwrap(),
                (1594679718, TimestampResultCode::TimestampFound)
            );

            assert_eq!(watcher_db.highest_common_block().unwrap(), 1);
            // Timestamp does not exist for block 2, but we are not yet fully synced
            assert_eq!(
                watcher_db.get_block_timestamp(2).unwrap(),
                (u64::MAX, TimestampResultCode::WatcherBehind)
            );

            watcher_db.update_last_synced(&urls[0], 2).unwrap();
            watcher_db.update_last_synced(&urls[1], 2).unwrap();

            assert_eq!(watcher_db.highest_common_block().unwrap(), 2);
            // We are fully synced,
            assert_eq!(
                watcher_db.get_block_timestamp(2).unwrap(),
                (u64::MAX, TimestampResultCode::Unavailable)
            );

            // Verify that block index 0 is out of bounds
            assert_eq!(
                watcher_db.get_block_timestamp(0).unwrap(),
                (u64::MAX, TimestampResultCode::BlockIndexOutOfBounds)
            );

            // Verify that u64::MAX is out of bounds
            assert_eq!(
                watcher_db.get_block_timestamp(u64::MAX).unwrap(),
                (u64::MAX, TimestampResultCode::BlockIndexOutOfBounds)
            );
        });
    }
}
