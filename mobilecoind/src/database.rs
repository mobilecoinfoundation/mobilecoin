// Copyright (c) 2018-2023 The MobileCoin Foundation

//! The mobilecoind database

use crate::{
    db_crypto::{CryptoContext, CryptoFormat, DbCryptoProvider},
    error::Error,
    monitor_store::{MonitorData, MonitorId, MonitorStore},
    processed_block_store::{ProcessedBlockStore, ProcessedTxOut},
    subaddress_store::{SubaddressId, SubaddressSPKId, SubaddressStore},
    t3_store::T3Store,
    utxo_store::{UtxoId, UtxoStore},
};

use crate::utxo_store::UnspentTxOut;
use lmdb::{Environment, Transaction};
use mc_common::{
    logger::{log, Logger},
    HashMap,
};
use mc_t3_api::TransparentTransaction;
use mc_transaction_core::ring_signature::KeyImage;
use mc_util_lmdb::{MetadataStore, MetadataStoreSettings};
use std::{
    path::Path,
    sync::{Arc, RwLock},
};

// LMDB Constants
/// Database format before per-record random nonces and encryption-generation
/// salts.
#[allow(clippy::inconsistent_digit_grouping)] // Group the date as YYYY_MM_DD.
const PRE_RANDOM_NONCE_DB_VERSION: u64 = 2020_08_05;

const MAX_LMDB_FILE_SIZE: usize = 1_099_511_627_776; // 1 TB

/// Metadata store settings that are used for version control.
#[derive(Clone, Default, Debug)]
pub struct MobilecoindDbMetadataStoreSettings;
impl MetadataStoreSettings for MobilecoindDbMetadataStoreSettings {
    // Default database version. This should be bumped when breaking changes are
    // introduced. If this is properly maintained, we could check during ledger
    // db opening for any incompatibilities, and either refuse to open or
    // perform a migration.
    #[allow(clippy::inconsistent_digit_grouping)] // Group the date as YYYY_MM_DD.
    const LATEST_VERSION: u64 = 2026_10_16;

    /// The current crate version that manages the database.
    const CRATE_VERSION: &'static str = env!("CARGO_PKG_VERSION");

    /// LMDB Database name to use for storing the metadata information.
    const DB_NAME: &'static str = "mobilecoind_db_metadata";
}

/// The main mobilecoind database.
#[derive(Clone)]
pub struct Database {
    // LMDB Environment (database).
    env: Arc<Environment>,

    /// Database format metadata, committed with encrypted records.
    metadata_store: MetadataStore<MobilecoindDbMetadataStoreSettings>,

    /// Shared encryption state. The lock keeps database records and their key
    /// in sync.
    ///
    /// Take the lock before opening an LMDB transaction. Normal reads and
    /// writes hold a read lock until the transaction ends. Unlock,
    /// migration, and password changes hold a write lock until records are
    /// committed and the key is updated.
    crypto_provider: Arc<RwLock<DbCryptoProvider>>,

    /// Monitor store.
    monitor_store: MonitorStore,

    /// Subaddress store.
    subaddress_store: SubaddressStore,

    /// Utxo store.
    utxo_store: UtxoStore,

    /// Processed block store.
    processed_block_store: ProcessedBlockStore,

    /// T3 store.
    t3_store: T3Store,

    /// Logger.
    logger: Logger,
}

impl Database {
    pub fn new<P: AsRef<Path>>(path: P, logger: Logger) -> Result<Self, Error> {
        let env = Arc::new(
            Environment::new()
                .set_max_dbs(13)
                .set_map_size(MAX_LMDB_FILE_SIZE)
                .open(path.as_ref())?,
        );

        let metadata_store =
            MetadataStore::<MobilecoindDbMetadataStoreSettings>::open_or_create(&env)?;

        let db_txn = env.begin_ro_txn()?;
        let version = metadata_store.get_version(&db_txn)?;
        log::info!(
            logger,
            "Mobilecoind db is currently at version: {:?}",
            version
        );
        db_txn.commit()?;

        let format = if version.database_format_version == PRE_RANDOM_NONCE_DB_VERSION {
            CryptoFormat::Legacy
        } else {
            version.is_compatible_with_latest()?;
            CryptoFormat::V1
        };

        let mut crypto_provider = DbCryptoProvider::new(&env, format)?;
        if format == CryptoFormat::Legacy && !crypto_provider.is_db_encrypted() {
            let mut txn = env.begin_rw_txn()?;
            metadata_store.set_version_to_latest(&mut txn)?;
            txn.commit()?;
            crypto_provider.activate_context(CryptoContext::Plaintext);
        }

        let monitor_store = MonitorStore::new(env.clone(), logger.clone())?;
        let subaddress_store = SubaddressStore::new(env.clone(), logger.clone())?;
        let utxo_store = UtxoStore::new(env.clone(), logger.clone())?;
        let processed_block_store = ProcessedBlockStore::new(env.clone(), logger.clone())?;
        let t3_store = T3Store::new(env.clone(), logger.clone())?;

        Ok(Self {
            env,
            metadata_store,
            crypto_provider: Arc::new(RwLock::new(crypto_provider)),
            monitor_store,
            subaddress_store,
            utxo_store,
            processed_block_store,
            t3_store,
            logger,
        })
    }

    /// Check if data is currently being encrypted.
    pub fn is_db_encrypted(&self) -> bool {
        let crypto = self.crypto_provider.read().expect("crypto lock poisoned");
        crypto.is_db_encrypted()
    }

    /// Check if the data is currently accessible (this checks if the correct
    /// encryption key has been provided)
    pub fn is_unlocked(&self) -> bool {
        let crypto = self.crypto_provider.read().expect("crypto lock poisoned");
        crypto.is_unlocked()
    }

    /// Check if a given password is the correct password to decrypt the
    /// database. This also stores it for future encryption/decryption
    /// operations. Legacy encrypted databases are migrated atomically before
    /// the unlocked state becomes visible.
    pub fn check_and_store_password(&self, password: &[u8]) -> Result<(), Error> {
        let mut crypto = self.crypto_provider.write().expect("crypto lock poisoned");
        let txn = self.env.begin_ro_txn()?;
        let source = crypto.validate_password(&txn, password)?;
        let legacy = self
            .metadata_store
            .get_version(&txn)?
            .database_format_version
            == PRE_RANDOM_NONCE_DB_VERSION;
        drop(txn);
        if legacy {
            log::info!(self.logger, "Migrating encrypted mobilecoind database");
            let destination = CryptoContext::new(password)?;
            self.re_encrypt_with_contexts(&mut crypto, &source, destination)?;
            log::info!(
                self.logger,
                "Encrypted mobilecoind database migration completed"
            );
        } else {
            crypto.activate_context(source);
        }
        Ok(())
    }

    /// Re-encrypt the encrypted parts of the database with a new password.
    /// This will fail if the current password is not set in the crypto_provider
    /// since part of the re-encryption process relies on being able to
    /// decrypt the existing data.
    pub fn re_encrypt(&self, new_password: &[u8]) -> Result<(), Error> {
        let mut crypto = self.crypto_provider.write().expect("crypto lock poisoned");
        let source = crypto.context()?.clone();
        let destination = CryptoContext::new(new_password)?;
        self.re_encrypt_with_contexts(&mut crypto, &source, destination)
    }

    /// Caller holds the provider write guard. Activate the context only after
    /// all writes and the format version have committed successfully.
    fn re_encrypt_with_contexts(
        &self,
        crypto: &mut DbCryptoProvider,
        source: &CryptoContext,
        destination: CryptoContext,
    ) -> Result<(), Error> {
        let mut txn = self.env.begin_rw_txn()?;
        self.monitor_store
            .re_encrypt(&mut txn, source, &destination)?;
        crypto.write_metadata(&mut txn, &destination)?;
        self.metadata_store.set_version_to_latest(&mut txn)?;
        txn.commit()?;
        crypto.activate_context(destination);
        Ok(())
    }

    pub fn add_monitor(&self, data: &MonitorData) -> Result<MonitorId, Error> {
        let crypto = self.crypto_provider.read().expect("crypto lock poisoned");
        mc_common::trace_time!(self.logger, "add_monitor");

        let mut db_txn = self.env.begin_rw_txn()?;
        let id = self.monitor_store.add(&mut db_txn, &crypto, data)?;

        //for index in 0..data.num_subaddresses {
        for index in data.subaddress_indexes() {
            self.subaddress_store
                .insert(&mut db_txn, &id, data, index)?;
        }

        db_txn.commit()?;
        Ok(id)
    }

    pub fn remove_monitor(&self, id: &MonitorId) -> Result<(), Error> {
        let crypto = self.crypto_provider.read().expect("crypto lock poisoned");
        mc_common::trace_time!(self.logger, "remove_monitor");

        let mut db_txn = self.env.begin_rw_txn()?;

        let data = self.monitor_store.get_data(&db_txn, &crypto, id)?;

        for index in data.subaddress_indexes() {
            self.subaddress_store.delete(&mut db_txn, &data, index)?;
            self.utxo_store.remove_utxos(&mut db_txn, id, index)?;
        }

        self.processed_block_store.remove(&mut db_txn, id)?;

        self.monitor_store.remove(&mut db_txn, id)?;

        db_txn.commit()?;

        Ok(())
    }

    pub fn get_monitor_data(&self, id: &MonitorId) -> Result<MonitorData, Error> {
        let crypto = self.crypto_provider.read().expect("crypto lock poisoned");
        let db_txn = self.env.begin_ro_txn()?;
        self.monitor_store.get_data(&db_txn, &crypto, id)
    }

    pub fn get_monitor_map(&self) -> Result<HashMap<MonitorId, MonitorData>, Error> {
        let crypto = self.crypto_provider.read().expect("crypto lock poisoned");
        let db_txn = self.env.begin_ro_txn()?;
        self.monitor_store.get_map(&db_txn, &crypto)
    }

    pub fn get_monitor_ids(&self) -> Result<Vec<MonitorId>, Error> {
        let _crypto = self.crypto_provider.read().expect("crypto lock poisoned");
        let db_txn = self.env.begin_ro_txn()?;
        self.monitor_store.get_ids(&db_txn)
    }

    pub fn get_subaddress_id_by_spk(
        &self,
        subaddress_spk: &SubaddressSPKId,
    ) -> Result<SubaddressId, Error> {
        let _crypto = self.crypto_provider.read().expect("crypto lock poisoned");
        let db_txn = self.env.begin_ro_txn()?;
        self.subaddress_store
            .get_index_data(&db_txn, subaddress_spk)
    }

    pub fn get_subaddress_id_by_utxo_id(&self, utxo_id: &UtxoId) -> Result<SubaddressId, Error> {
        let _crypto = self.crypto_provider.read().expect("crypto lock poisoned");
        let db_txn = self.env.begin_ro_txn()?;
        self.utxo_store
            .get_subaddress_id_by_utxo_id(&db_txn, utxo_id)
    }

    pub fn get_utxos_for_subaddress(
        &self,
        monitor_id: &MonitorId,
        index: u64,
    ) -> Result<Vec<UnspentTxOut>, Error> {
        let _crypto = self.crypto_provider.read().expect("crypto lock poisoned");
        let db_txn = self.env.begin_ro_txn()?;
        self.utxo_store.get_utxos(&db_txn, monitor_id, index)
    }

    pub fn get_utxos_for_monitor(
        &self,
        monitor_id: &MonitorId,
    ) -> Result<Vec<UnspentTxOut>, Error> {
        let _crypto = self.crypto_provider.read().expect("crypto lock poisoned");
        let db_txn = self.env.begin_ro_txn()?;
        self.utxo_store.get_utxos_for_monitor(&db_txn, monitor_id)
    }

    pub fn update_attempted_spend(
        &self,
        utxo_ids: &[UtxoId],
        attempted_spend_height: u64,
        attempted_spend_tombstone: u64,
    ) -> Result<(), Error> {
        let _crypto = self.crypto_provider.read().expect("crypto lock poisoned");
        let mut db_txn = self.env.begin_rw_txn()?;

        self.utxo_store.update_attempted_spend(
            &mut db_txn,
            utxo_ids,
            attempted_spend_height,
            attempted_spend_tombstone,
        )?;

        db_txn.commit()?;

        Ok(())
    }

    /// Feed data processed from a given block into the various stores.
    pub fn block_processed(
        &self,
        monitor_id: &MonitorId,
        block_num: u64,
        discovered_utxos: &[UnspentTxOut],
        spent_key_images: &[KeyImage],
    ) -> Result<(), Error> {
        let crypto = self.crypto_provider.read().expect("crypto lock poisoned");
        let mut db_txn = self.env.begin_rw_txn()?;

        // Get monitor data.
        let mut monitor_data = self.monitor_store.get_data(&db_txn, &crypto, monitor_id)?;

        // If the block being handed to us is not the one we expect, error out.
        if block_num != monitor_data.next_block {
            return Err(Error::InvalidArgument(
                "block_num".to_string(),
                format!(
                    "Expected block {}, got block {}",
                    monitor_data.next_block, block_num
                ),
            ));
        }

        // Store new utxos
        for utxo in discovered_utxos {
            self.utxo_store
                .append_utxo(&mut db_txn, monitor_id, utxo.subaddress_index, utxo)?;
            self.t3_store
                .process_utxo(&mut db_txn, &monitor_data, utxo)?;
        }

        // Remove spent utxos
        let removed_utxos = self.utxo_store.remove_utxos_by_key_images(
            &mut db_txn,
            monitor_id,
            spent_key_images,
        )?;

        // Update monitor data.
        monitor_data.next_block += 1;
        self.monitor_store
            .set_data(&mut db_txn, &crypto, monitor_id, &monitor_data)?;

        // Update processed blocks store.
        self.processed_block_store.block_processed(
            &mut db_txn,
            monitor_id,
            block_num,
            discovered_utxos,
            &removed_utxos,
        )?;

        // Commit.
        db_txn.commit()?;

        // Success.
        if discovered_utxos.is_empty() && removed_utxos.is_empty() {
            log::debug!(
                self.logger,
                "Processed {} utxos and {} key images in block {} for monitor id {}",
                discovered_utxos.len(),
                removed_utxos.len(),
                block_num,
                monitor_id
            )
        } else {
            log::info!(
                self.logger,
                "Processed {} utxos and {} key images in block {} for monitor id {}",
                discovered_utxos.len(),
                removed_utxos.len(),
                block_num,
                monitor_id
            )
        };
        Ok(())
    }

    /// Get processed block information for a given (monitor id, block number).
    pub fn get_processed_block(
        &self,
        monitor_id: &MonitorId,
        block_num: u64,
    ) -> Result<Vec<ProcessedTxOut>, Error> {
        let crypto = self.crypto_provider.read().expect("crypto lock poisoned");
        let db_txn = self.env.begin_ro_txn()?;

        // Get monitor data to see if the monitor has synced this block.
        let monitor_data = self.monitor_store.get_data(&db_txn, &crypto, monitor_id)?;
        if block_num < monitor_data.first_block {
            return Err(Error::BlockIndexTooSmall(
                block_num,
                monitor_data.first_block,
            ));
        }
        if block_num >= monitor_data.next_block {
            return Err(Error::BlockNotYetProcessed(
                block_num,
                monitor_data.next_block,
            ));
        }

        self.processed_block_store
            .get_processed_block(&db_txn, monitor_id, block_num)
    }

    /// Get the next transparent transaction that needs to be synced to t3.
    /// Additionally return its index so it can then be removed.
    pub fn dequeue_transparent_tx(&self) -> Result<Option<(u64, TransparentTransaction)>, Error> {
        let _crypto = self.crypto_provider.read().expect("crypto lock poisoned");
        let db_txn = self.env.begin_ro_txn()?;
        self.t3_store.dequeue_transparent_tx(&db_txn)
    }

    /// Remove a transparent transaction from the queue.
    pub fn remove_transparent_tx(&self, index: u64) -> Result<(), Error> {
        let _crypto = self.crypto_provider.read().expect("crypto lock poisoned");
        let mut db_txn = self.env.begin_rw_txn()?;
        self.t3_store.remove_transparent_tx(&mut db_txn, index)?;
        db_txn.commit()?;
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::test_utils::get_test_databases;
    use mc_account_keys::AccountKey;
    use mc_blockchain_types::BlockVersion;
    use mc_common::logger::test_with_logger;
    use rand::{rngs::StdRng, SeedableRng};
    use tempfile::TempDir;

    // Test that encryption happy path works as expected.
    #[test_with_logger]
    fn test_encryption_happy_path(logger: Logger) {
        let mut rng: StdRng = SeedableRng::from_seed([123u8; 32]);
        let account_key = AccountKey::random(&mut rng);

        let mobilecoind_db_tmp = TempDir::new().expect("Could not make tempdir for mobilecoind db");
        let mobilecoind_db_path = mobilecoind_db_tmp
            .path()
            .to_str()
            .expect("Could not get path as string");

        let mobilecoind_db = Database::new(mobilecoind_db_path, logger.clone())
            .expect("failed creating new mobilecoind db");

        // The db starts unencrypted.
        assert!(!mobilecoind_db.is_db_encrypted());
        assert!(mobilecoind_db.is_unlocked());

        // Use enough monitors with varied record sizes to exercise cursor updates
        // across multiple LMDB pages during re-encryption.
        let monitors: HashMap<_, _> = (0..64u64)
            .map(|n| {
                let name = format!("monitor-{n}-{}", "x".repeat((n as usize % 7) * 300));
                let monitor_data =
                    MonitorData::new(account_key.clone(), n * 2, 2, 0, &name).unwrap();
                let monitor_id = mobilecoind_db
                    .add_monitor(&monitor_data)
                    .expect("failed adding monitor");
                (monitor_id, monitor_data)
            })
            .collect();

        // We should be able to get all monitors under their original IDs.
        assert_eq!(mobilecoind_db.get_monitor_map().unwrap(), monitors);

        // Re-encrypting with an empty password should not affect things.
        mobilecoind_db.re_encrypt(&[]).unwrap();

        assert!(!mobilecoind_db.is_db_encrypted());
        assert!(mobilecoind_db.is_unlocked());

        assert_eq!(mobilecoind_db.get_monitor_map().unwrap(), monitors);

        // Checking an empty password should not affect anything.
        mobilecoind_db.check_and_store_password(&[]).unwrap();

        assert!(!mobilecoind_db.is_db_encrypted());
        assert!(mobilecoind_db.is_unlocked());

        assert_eq!(mobilecoind_db.get_monitor_map().unwrap(), monitors);

        // Checking a non-empty password should error and not affect things.
        assert!(mobilecoind_db.check_and_store_password(&[1; 32]).is_err());

        assert!(!mobilecoind_db.is_db_encrypted());
        assert!(mobilecoind_db.is_unlocked());

        assert_eq!(mobilecoind_db.get_monitor_map().unwrap(), monitors);

        // Set a password.
        mobilecoind_db.re_encrypt(&[10; 32]).unwrap();

        assert!(mobilecoind_db.is_db_encrypted());
        assert!(mobilecoind_db.is_unlocked());

        assert_eq!(mobilecoind_db.get_monitor_map().unwrap(), monitors);

        // Re-open the db.
        let mobilecoind_db = Database::new(mobilecoind_db_path, logger.clone())
            .expect("failed creating new mobilecoind db");

        // This time we're encrypted and locked.
        assert!(mobilecoind_db.is_db_encrypted());
        assert!(!mobilecoind_db.is_unlocked());

        // We can't get monitors yet.
        assert!(mobilecoind_db.get_monitor_map().is_err());

        // We can't re-encrypt.
        assert!(mobilecoind_db.re_encrypt(&[10; 32]).is_err());

        // Invalid password gets us nothing.
        assert!(mobilecoind_db.check_and_store_password(&[20; 32]).is_err());

        assert!(mobilecoind_db.is_db_encrypted());
        assert!(!mobilecoind_db.is_unlocked());
        assert!(mobilecoind_db.get_monitor_map().is_err());
        assert!(mobilecoind_db.re_encrypt(&[10; 32]).is_err());

        // Correct password allows unlocking.
        mobilecoind_db.check_and_store_password(&[10; 32]).unwrap();

        assert!(mobilecoind_db.is_db_encrypted());
        assert!(mobilecoind_db.is_unlocked());

        assert_eq!(mobilecoind_db.get_monitor_map().unwrap(), monitors);

        // Re-encrypt and repeat the test.
        mobilecoind_db.re_encrypt(&[11; 32]).unwrap();

        let mobilecoind_db = Database::new(mobilecoind_db_path, logger.clone())
            .expect("failed creating new mobilecoind db");

        assert!(mobilecoind_db.is_db_encrypted());
        assert!(!mobilecoind_db.is_unlocked());

        assert!(mobilecoind_db.get_monitor_map().is_err());

        assert!(mobilecoind_db.re_encrypt(&[10; 32]).is_err());

        assert!(mobilecoind_db.check_and_store_password(&[10; 32]).is_err());

        assert!(mobilecoind_db.is_db_encrypted());
        assert!(!mobilecoind_db.is_unlocked());
        assert!(mobilecoind_db.get_monitor_map().is_err());
        assert!(mobilecoind_db.re_encrypt(&[10; 32]).is_err());

        mobilecoind_db.check_and_store_password(&[11; 32]).unwrap();

        assert!(mobilecoind_db.is_db_encrypted());
        assert!(mobilecoind_db.is_unlocked());

        assert_eq!(mobilecoind_db.get_monitor_map().unwrap(), monitors);

        // Remove password and try again.
        mobilecoind_db.re_encrypt(&[]).unwrap();

        let mobilecoind_db =
            Database::new(mobilecoind_db_path, logger).expect("failed creating new mobilecoind db");

        assert!(!mobilecoind_db.is_db_encrypted());
        assert!(mobilecoind_db.is_unlocked());

        assert!(mobilecoind_db.check_and_store_password(&[10; 32]).is_err());

        assert_eq!(mobilecoind_db.get_monitor_map().unwrap(), monitors);
    }

    // Inserting a monitor that overlaps subaddresses of another monitor should
    // result in an error.
    #[test_with_logger]
    fn test_overlapping_add_monitor_fails(logger: Logger) {
        let mut rng: StdRng = SeedableRng::from_seed([123u8; 32]);

        // Set up a db with 3 random recipients and 10 blocks.
        let (_ledger_db, mobilecoind_db) =
            get_test_databases(BlockVersion::ZERO, 3, &[], 10, logger, &mut rng);

        // A test accouunt.
        let account_key = AccountKey::random(&mut rng);

        // Insert the first monitor, with subaddresses 0-9 (inclusive).
        let initial_data = MonitorData::new(
            account_key.clone(),
            0,  // first_subaddress
            10, // num_subaddresses
            0,  // first_block
            "", // name
        )
        .unwrap();

        let monitor_id = mobilecoind_db
            .add_monitor(&initial_data)
            .expect("failed adding monitor");

        // Inserting an identical monitor should fail.
        let data = MonitorData::new(
            account_key.clone(),
            0,  // first_subaddress
            10, // num_subaddresses
            0,  // first_block
            "", // name
        )
        .unwrap();

        match mobilecoind_db.add_monitor(&data) {
            Ok(_) => panic!("unexpected success!"),
            Err(Error::MonitorIdExists) => {}
            Err(err) => panic!("unexpected error {err:?}"),
        };

        // Inserting a monitor with overlapping subaddresses should fail.
        let data = MonitorData::new(
            account_key.clone(),
            5,  // first_subaddress
            10, // num_subaddresses
            0,  // first_block
            "", // name
        )
        .unwrap();

        match mobilecoind_db.add_monitor(&data) {
            Ok(_) => panic!("unexpected success!"),
            Err(Error::SubaddressSPKIdExists) => {}
            Err(err) => panic!("unexpected error {err:?}"),
        };

        // Inserting a monitor with overlapping subaddresses and a different
        // `first_block` should fail.
        let data = MonitorData::new(
            account_key.clone(),
            0,  // first_subaddress
            10, // num_subaddresses
            10, // first_block
            "", // name
        )
        .unwrap();

        match mobilecoind_db.add_monitor(&data) {
            Ok(_) => panic!("unexpected success!"),
            Err(Error::SubaddressSPKIdExists) => {}
            Err(err) => panic!("unexpected error {err:?}"),
        };

        // Inserting a monitor with non overlapping subaddresses should succeed.
        let data = MonitorData::new(
            account_key,
            10, // first_subaddress
            10, // num_subaddresses
            0,  // first_block
            "", // name
        )
        .unwrap();

        let _ = mobilecoind_db
            .add_monitor(&data)
            .expect("failed adding monitor");

        // Removing the first monitor and re-adding it should succeed.
        mobilecoind_db
            .remove_monitor(&monitor_id)
            .expect("failed removing monitor");

        let _ = mobilecoind_db
            .add_monitor(&initial_data)
            .expect("failed adding monitor");
    }
}

#[cfg(test)]
mod encryption_tests {
    //! Persistence-level regression tests using disposable account keys and
    //! LMDB.

    use super::*;
    use crate::monitor_store::MONITOR_ID_TO_MONITOR_DATA_DB_NAME;
    use aes_gcm::{
        aead::{array::typenum::Unsigned, Aead, Nonce},
        AeadCore, Aes256Gcm, KeyInit,
    };
    use lmdb::{Cursor, WriteFlags};
    use mc_account_keys::AccountKey;
    use mc_common::logger::test_with_logger;
    use mc_crypto_hashes::{Blake2b512, Digest};
    use mc_crypto_keys::RistrettoPrivate;
    use tempfile::TempDir;

    const PASSWORD: [u8; 32] = [42; 32];

    fn monitors() -> [MonitorData; 2] {
        [1u8, 3].map(|n| {
            let mut view = [0; 32];
            view[0] = n;
            let mut spend = [0; 32];
            spend[0] = n + 1;
            let account = AccountKey::new(
                &RistrettoPrivate::try_from(&spend[..]).unwrap(),
                &RistrettoPrivate::try_from(&view[..]).unwrap(),
            );
            MonitorData::new(account, 0, 10, 1, "").unwrap()
        })
    }

    /// Deliberately independent copy of the old writer, only for test fixtures.
    fn legacy_encrypt(plaintext: &[u8]) -> Vec<u8> {
        let mut hash = Blake2b512::new();
        hash.update(b"mc_mobilecoind");
        hash.update(PASSWORD);
        let digest = hash.finalize();
        Aes256Gcm::new_from_slice(&digest[..32])
            .unwrap()
            .encrypt(
                <&Nonce<Aes256Gcm>>::try_from(&digest[32..44]).unwrap(),
                plaintext,
            )
            .unwrap()
    }

    fn legacy_database(path: &Path, data: &[MonitorData], logger: Logger) {
        let db = Database::new(path, logger).unwrap();
        for monitor in data {
            db.add_monitor(monitor).unwrap();
        }
        let monitor_store = db
            .env
            .open_db(Some(MONITOR_ID_TO_MONITOR_DATA_DB_NAME))
            .unwrap();
        let crypto = db.env.open_db(Some("db_crypto")).unwrap();
        let mut txn = db.env.begin_rw_txn().unwrap();
        for monitor in data {
            let id = MonitorId::from(monitor);
            txn.put(
                monitor_store,
                &id,
                &legacy_encrypt(&mc_util_serial::encode(monitor)),
                WriteFlags::empty(),
            )
            .unwrap();
        }
        txn.put(
            crypto,
            &b"db_encrypted",
            &legacy_encrypt(b"true"),
            WriteFlags::empty(),
        )
        .unwrap();
        db.metadata_store
            .set_version(&mut txn, PRE_RANDOM_NONCE_DB_VERSION)
            .unwrap();
        txn.commit().unwrap();
    }

    /// Open a separate environment without using Database or a password.
    fn snapshot_values(path: &Path, ids: &[MonitorId]) -> Vec<Vec<u8>> {
        let env = Environment::new().set_max_dbs(13).open(path).unwrap();
        let store = env
            .open_db(Some(MONITOR_ID_TO_MONITOR_DATA_DB_NAME))
            .unwrap();
        let txn = env.begin_ro_txn().unwrap();
        ids.iter()
            .map(|id| txn.get(store, id).unwrap().to_vec())
            .collect()
    }

    /// Extract the nonce and ciphertext, excluding the GCM authentication tag.
    fn encrypted_record_parts(record: &[u8]) -> (&[u8], &[u8]) {
        let (&version, payload) = record.split_first().expect("record version");
        assert_eq!(version, 1);
        let nonce_len = <Aes256Gcm as AeadCore>::NonceSize::USIZE;
        let tag_len = <Aes256Gcm as AeadCore>::TagSize::USIZE;
        let (nonce, ciphertext_and_tag) = payload.split_at(nonce_len);
        let ciphertext_len = ciphertext_and_tag
            .len()
            .checked_sub(tag_len)
            .expect("GCM tag");
        let (ciphertext, _tag) = ciphertext_and_tag.split_at(ciphertext_len);
        (nonce, ciphertext)
    }

    fn recover(known: &[u8], victim: &[u8], known_plaintext: &[u8]) -> Vec<u8> {
        victim
            .iter()
            .zip(known)
            .zip(known_plaintext)
            .map(|((v, k), p)| v ^ k ^ p)
            .collect()
    }

    fn version(db: &Database) -> u64 {
        db.metadata_store
            .get_version(&db.env.begin_ro_txn().unwrap())
            .unwrap()
            .database_format_version
    }

    fn raw_state(db: &Database) -> Vec<(Vec<u8>, Vec<u8>)> {
        // Include rewritten records, metadata, and crypto state in rollback checks.
        let mut result = vec![];
        for name in [
            MONITOR_ID_TO_MONITOR_DATA_DB_NAME,
            "db_crypto",
            "mobilecoind_db_metadata",
        ] {
            let store = db.env.open_db(Some(name)).unwrap();
            let txn = db.env.begin_ro_txn().unwrap();
            let mut cursor = txn.open_ro_cursor(store).unwrap();
            for pair in cursor.iter() {
                let (key, value) = pair.unwrap();
                result.push(([name.as_bytes(), key].concat(), value.to_vec()));
            }
        }
        result
    }

    #[test_with_logger]
    fn legacy_snapshot_attack_fails_after_migration_and_rotation(logger: Logger) {
        let path = TempDir::new().unwrap();
        let data = monitors();
        let ids = data.each_ref().map(MonitorId::from);
        let known = mc_util_serial::encode(&data[0]);
        let victim = mc_util_serial::encode(&data[1]);
        assert_eq!(known.len(), victim.len());
        legacy_database(path.path(), &data, logger.clone());
        let old = snapshot_values(path.path(), &ids);
        assert_eq!(recover(&old[0], &old[1], &known), victim);

        let db = Database::new(path.path(), logger.clone()).unwrap();
        assert!(!db.is_unlocked());
        assert_eq!(version(&db), PRE_RANDOM_NONCE_DB_VERSION);
        let before = raw_state(&db);
        assert!(db.check_and_store_password(&[43; 32]).is_err());
        assert!(!db.is_unlocked());
        assert_eq!(before, raw_state(&db));
        db.check_and_store_password(&PASSWORD).unwrap();
        assert_eq!(
            version(&db),
            MobilecoindDbMetadataStoreSettings::LATEST_VERSION
        );
        for (id, monitor) in ids.iter().zip(&data) {
            assert_eq!(&db.get_monitor_data(id).unwrap(), monitor);
        }
        drop(db);

        let migrated = snapshot_values(path.path(), &ids);
        let (known_nonce, known_ciphertext) = encrypted_record_parts(&migrated[0]);
        let (victim_nonce, victim_ciphertext) = encrypted_record_parts(&migrated[1]);
        assert_eq!(known_ciphertext.len(), known.len());
        assert_eq!(victim_ciphertext.len(), victim.len());
        assert_ne!(known_nonce, victim_nonce);
        assert_ne!(recover(known_ciphertext, victim_ciphertext, &known), victim);
        let db = Database::new(path.path(), logger.clone()).unwrap();
        assert!(!db.is_unlocked());
        db.check_and_store_password(&PASSWORD).unwrap();
        assert_eq!(db.get_monitor_data(&ids[0]).unwrap(), data[0]);
        for password in [PASSWORD, [43; 32]] {
            let before = raw_state(&db);
            let crypto = db.env.open_db(Some("db_crypto")).unwrap();
            let (old_salt, old_marker) = {
                let txn = db.env.begin_ro_txn().unwrap();
                (
                    txn.get(crypto, &b"key_salt").unwrap().to_vec(),
                    txn.get(crypto, &b"db_encrypted").unwrap().to_vec(),
                )
            };
            let old_context = db
                .crypto_provider
                .read()
                .unwrap()
                .context()
                .unwrap()
                .clone();
            db.re_encrypt(&password).unwrap();
            assert_ne!(before, raw_state(&db));
            {
                let txn = db.env.begin_ro_txn().unwrap();
                let marker = txn.get(crypto, &b"db_encrypted").unwrap();
                assert_ne!(old_salt, txn.get(crypto, &b"key_salt").unwrap());
                let (old_marker_nonce, _) = encrypted_record_parts(&old_marker);
                let (marker_nonce, _) = encrypted_record_parts(marker);
                assert_ne!(old_marker_nonce, marker_nonce);
                assert!(old_context.decrypt(marker).is_err());
            }
            assert_eq!(db.get_monitor_data(&ids[1]).unwrap(), data[1]);
            let store = db
                .env
                .open_db(Some(MONITOR_ID_TO_MONITOR_DATA_DB_NAME))
                .unwrap();
            let txn = db.env.begin_ro_txn().unwrap();
            let known_record = txn.get(store, &ids[0]).unwrap();
            let victim_record = txn.get(store, &ids[1]).unwrap();
            let (rotated_known_nonce, rotated_known_ciphertext) =
                encrypted_record_parts(known_record);
            let (rotated_victim_nonce, rotated_victim_ciphertext) =
                encrypted_record_parts(victim_record);
            assert_eq!(rotated_known_ciphertext.len(), known.len());
            assert_eq!(rotated_victim_ciphertext.len(), victim.len());
            assert_ne!(rotated_known_nonce, rotated_victim_nonce);
            assert_ne!(rotated_known_nonce, known_nonce);
            assert_ne!(
                recover(rotated_known_ciphertext, rotated_victim_ciphertext, &known),
                victim
            );
        }
        db.re_encrypt(&[]).unwrap();
        assert_eq!(db.get_monitor_data(&ids[0]).unwrap(), data[0]);
        drop(db);
        assert_eq!(snapshot_values(path.path(), &ids), [known, victim]);
    }

    #[test_with_logger]
    fn inserts_and_sync_updates_use_fresh_nonces(logger: Logger) {
        let path = TempDir::new().unwrap();
        let db = Database::new(path.path(), logger).unwrap();
        db.re_encrypt(&PASSWORD).unwrap();
        let data = monitors();
        let ids = data
            .each_ref()
            .map(|monitor| db.add_monitor(monitor).unwrap());
        let store = db
            .env
            .open_db(Some(MONITOR_ID_TO_MONITOR_DATA_DB_NAME))
            .unwrap();
        let original = {
            let txn = db.env.begin_ro_txn().unwrap();
            let first = txn.get(store, &ids[0]).unwrap().to_vec();
            let second = txn.get(store, &ids[1]).unwrap();
            let (first_nonce, _) = encrypted_record_parts(&first);
            let (second_nonce, _) = encrypted_record_parts(second);
            assert_ne!(first_nonce, second_nonce);
            first
        };
        db.block_processed(&ids[0], 1, &[], &[]).unwrap();
        let txn = db.env.begin_ro_txn().unwrap();
        let updated = txn.get(store, &ids[0]).unwrap();
        let (original_nonce, _) = encrypted_record_parts(&original);
        let (updated_nonce, _) = encrypted_record_parts(updated);
        assert_ne!(original_nonce, updated_nonce);
        drop(txn);
        assert_eq!(db.get_monitor_data(&ids[0]).unwrap().next_block, 2);
    }

    #[test_with_logger]
    fn corrupt_record_rolls_back_migration_and_keeps_database_locked(logger: Logger) {
        let path = TempDir::new().unwrap();
        legacy_database(path.path(), &monitors(), logger.clone());
        let db = Database::new(path.path(), logger.clone()).unwrap();
        let store = db
            .env
            .open_db(Some(MONITOR_ID_TO_MONITOR_DATA_DB_NAME))
            .unwrap();
        let mut txn = db.env.begin_rw_txn().unwrap();
        let (key, mut value) = {
            let mut cursor = txn.open_ro_cursor(store).unwrap();
            let (key, value) = cursor.iter().last().unwrap().unwrap();
            (key.to_vec(), value.to_vec())
        };
        value[0] ^= 1;
        txn.put(store, &key, &value, WriteFlags::empty()).unwrap();
        txn.commit().unwrap();
        let before = raw_state(&db);
        assert!(db.check_and_store_password(&PASSWORD).is_err());
        assert!(!db.is_unlocked());
        assert_eq!(before, raw_state(&db));
        assert_eq!(version(&db), PRE_RANDOM_NONCE_DB_VERSION);
        drop(db);
        let db = Database::new(path.path(), logger).unwrap();
        assert!(!db.is_unlocked());
        assert_eq!(before, raw_state(&db));
    }

    #[test_with_logger]
    fn empty_legacy_database_migrates_and_locked_rotation_is_rejected(logger: Logger) {
        let path = TempDir::new().unwrap();
        legacy_database(path.path(), &[], logger.clone());
        let db = Database::new(path.path(), logger.clone()).unwrap();
        let before = raw_state(&db);
        assert!(db.re_encrypt(&PASSWORD).is_err());
        assert!(db.re_encrypt(&[]).is_err());
        assert_eq!(before, raw_state(&db));
        db.check_and_store_password(&PASSWORD).unwrap();
        assert!(db.is_unlocked());
        assert_eq!(
            version(&db),
            MobilecoindDbMetadataStoreSettings::LATEST_VERSION
        );
        drop(db);
        let db = Database::new(path.path(), logger).unwrap();
        db.check_and_store_password(&PASSWORD).unwrap();
        assert!(db.get_monitor_ids().unwrap().is_empty());
    }

    #[test_with_logger]
    fn plaintext_upgrade_and_incompatible_versions(logger: Logger) {
        let path = TempDir::new().unwrap();
        let db = Database::new(path.path(), logger.clone()).unwrap();
        let data = monitors();
        let id = db.add_monitor(&data[0]).unwrap();
        let mut txn = db.env.begin_rw_txn().unwrap();
        db.metadata_store
            .set_version(&mut txn, PRE_RANDOM_NONCE_DB_VERSION)
            .unwrap();
        txn.commit().unwrap();
        drop(db);
        let db = Database::new(path.path(), logger.clone()).unwrap();
        assert!(db.is_unlocked());
        assert!(!db.is_db_encrypted());
        assert_eq!(db.get_monitor_data(&id).unwrap(), data[0]);
        assert_eq!(
            version(&db),
            MobilecoindDbMetadataStoreSettings::LATEST_VERSION
        );
        let mut txn = db.env.begin_rw_txn().unwrap();
        db.metadata_store.set_version(&mut txn, 99999999).unwrap();
        txn.commit().unwrap();
        drop(db);
        assert!(Database::new(path.path(), logger).is_err());
    }

    #[test_with_logger]
    fn invalid_password_change_preserves_unlocked_state(logger: Logger) {
        let path = TempDir::new().unwrap();
        let db = Database::new(path.path(), logger).unwrap();
        let data = monitors();
        let id = db.add_monitor(&data[0]).unwrap();
        db.re_encrypt(&PASSWORD).unwrap();
        let before = raw_state(&db);
        for password in [vec![0; 31], vec![0; 33]] {
            assert!(db.re_encrypt(&password).is_err());
            assert!(db.is_unlocked());
            assert_eq!(db.get_monitor_data(&id).unwrap(), data[0]);
            assert_eq!(before, raw_state(&db));
        }
    }

    #[test_with_logger]
    fn corrupt_record_rolls_back_password_change(logger: Logger) {
        let path = TempDir::new().unwrap();
        let db = Database::new(path.path(), logger).unwrap();
        for data in monitors() {
            db.add_monitor(&data).unwrap();
        }
        db.re_encrypt(&PASSWORD).unwrap();
        let store = db
            .env
            .open_db(Some(MONITOR_ID_TO_MONITOR_DATA_DB_NAME))
            .unwrap();
        let mut txn = db.env.begin_rw_txn().unwrap();
        let (key, mut value) = {
            let mut cursor = txn.open_ro_cursor(store).unwrap();
            let (key, value) = cursor.iter().last().unwrap().unwrap();
            (key.to_vec(), value.to_vec())
        };
        value[13] ^= 1;
        txn.put(store, &key, &value, WriteFlags::empty()).unwrap();
        txn.commit().unwrap();
        let before = raw_state(&db);
        let context = db
            .crypto_provider
            .read()
            .unwrap()
            .context()
            .unwrap()
            .clone();
        let ciphertext = context.encrypt(b"unchanged key").unwrap();
        assert!(db.re_encrypt(&[43; 32]).is_err());
        assert!(db.is_unlocked());
        assert_eq!(raw_state(&db), before);
        assert_eq!(
            db.crypto_provider
                .read()
                .unwrap()
                .decrypt(&ciphertext)
                .unwrap(),
            b"unchanged key"
        );
    }

    #[test_with_logger]
    fn legacy_binary_version_check_rejects_migrated_database(logger: Logger) {
        #[derive(Clone, Default, Debug)]
        struct LegacySettings;
        impl MetadataStoreSettings for LegacySettings {
            const LATEST_VERSION: u64 = PRE_RANDOM_NONCE_DB_VERSION;
            const CRATE_VERSION: &'static str = "7.1.0";
            const DB_NAME: &'static str = "mobilecoind_db_metadata";
        }
        let path = TempDir::new().unwrap();
        legacy_database(path.path(), &[], logger.clone());
        let db = Database::new(path.path(), logger).unwrap();
        let metadata = MetadataStore::<LegacySettings>::new(&db.env).unwrap();
        assert!(metadata
            .get_version(&db.env.begin_ro_txn().unwrap())
            .unwrap()
            .is_compatible_with_latest()
            .is_ok());
        db.check_and_store_password(&PASSWORD).unwrap();
        assert!(metadata
            .get_version(&db.env.begin_ro_txn().unwrap())
            .unwrap()
            .is_compatible_with_latest()
            .is_err());
    }
}
