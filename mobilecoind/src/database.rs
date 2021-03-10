// Copyright (c) 2018-2021 The MobileCoin Foundation

//! The mobilecoind database

use crate::{
    db_crypto::DbCryptoProvider,
    error::Error,
    monitor_store::{MonitorData, MonitorId, MonitorStore},
    processed_block_store::{ProcessedBlockStore, ProcessedTxOut},
    subaddress_store::{SubaddressId, SubaddressSPKId, SubaddressStore},
    utxo_store::{UtxoId, UtxoStore},
};

use crate::utxo_store::UnspentTxOut;
use lmdb::{Environment, Transaction};
use mc_common::{
    logger::{log, Logger},
    HashMap,
};
use mc_transaction_core::ring_signature::KeyImage;
use mc_util_lmdb::{MetadataStore, MetadataStoreSettings};
use std::{path::Path, sync::Arc};

// LMDB Constants
const MAX_LMDB_FILE_SIZE: usize = 1_099_511_627_776; // 1 TB

/// Metadata store settings that are used for version control.
#[derive(Clone, Default, Debug)]
pub struct MobilecoindDbMetadataStoreSettings;
impl MetadataStoreSettings for MobilecoindDbMetadataStoreSettings {
    // Default database version. This should be bumped when breaking changes are
    // introduced. If this is properly maintained, we could check during ledger
    // db opening for any incompatibilities, and either refuse to open or
    // perform a migration.
    #[allow(clippy::unreadable_literal)]
    const LATEST_VERSION: u64 = 20200805;

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

    /// Crypto provider, used for managing database encryption.
    crypto_provider: DbCryptoProvider,

    /// Monitor store.
    monitor_store: MonitorStore,

    /// Subaddress store.
    subaddress_store: SubaddressStore,

    /// Utxo store.
    utxo_store: UtxoStore,

    /// Processed block store.
    processed_block_store: ProcessedBlockStore,

    /// Metadata store.
    metadata_store: MetadataStore<MobilecoindDbMetadataStoreSettings>,

    /// Logger.
    logger: Logger,
}

impl Database {
    pub fn new<P: AsRef<Path>>(path: P, logger: Logger) -> Result<Self, Error> {
        let env = Arc::new(
            Environment::new()
                .set_max_dbs(10)
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

        version.is_compatible_with_latest()?;

        let crypto_provider = DbCryptoProvider::new(env.clone())?;

        let monitor_store =
            MonitorStore::new(env.clone(), crypto_provider.clone(), logger.clone())?;
        let subaddress_store = SubaddressStore::new(env.clone(), logger.clone())?;
        let utxo_store = UtxoStore::new(env.clone(), logger.clone())?;
        let processed_block_store = ProcessedBlockStore::new(env.clone(), logger.clone())?;

        Ok(Self {
            env,
            crypto_provider,
            monitor_store,
            subaddress_store,
            utxo_store,
            processed_block_store,
            metadata_store,
            logger,
        })
    }

    /// Check if data is currently being encrypted.
    pub fn is_db_encrypted(&self) -> bool {
        self.crypto_provider.is_db_encrypted()
    }

    /// Check if the data is currently accessible (this checks if the correct
    /// encryption key has been provided)
    pub fn is_unlocked(&self) -> bool {
        self.crypto_provider.is_unlocked()
    }

    /// Check if a given password is the correct password to decrypt the
    /// database. This also stores it for future encryption/decryption
    /// operations.
    pub fn check_and_store_password(&self, password: &[u8]) -> Result<(), Error> {
        Ok(self.crypto_provider.check_and_store_password(password)?)
    }

    /// Re-encrypt the encrypted parts of the database with a new password.
    /// This will fail if the current password is not set in the crypto_provider
    /// since part of the re-encryption process relies on being able to
    /// decrypt the existing data.
    pub fn re_encrypt(&self, new_password: &[u8]) -> Result<(), Error> {
        let mut db_txn = self.env.begin_rw_txn()?;

        // Currently only the monitor store stores encrypted data.
        self.monitor_store.re_encrypt(&mut db_txn, new_password)?;

        // set_password consumes the transaction to ensure atomicity.
        self.crypto_provider.change_password(db_txn, new_password)?;

        Ok(())
    }

    pub fn add_monitor(&self, data: &MonitorData) -> Result<MonitorId, Error> {
        mc_common::trace_time!(self.logger, "add_monitor");

        let mut db_txn = self.env.begin_rw_txn()?;
        let id = self.monitor_store.add(&mut db_txn, data)?;

        //for index in 0..data.num_subaddresses {
        for index in data.subaddress_indexes() {
            self.subaddress_store
                .insert(&mut db_txn, &id, data, index)?;
        }

        db_txn.commit()?;
        Ok(id)
    }

    pub fn remove_monitor(&self, id: &MonitorId) -> Result<(), Error> {
        mc_common::trace_time!(self.logger, "remove_monitor");

        let mut db_txn = self.env.begin_rw_txn()?;

        let data = self.monitor_store.get_data(&db_txn, &id)?;

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
        let db_txn = self.env.begin_ro_txn()?;
        self.monitor_store.get_data(&db_txn, id)
    }

    pub fn get_monitor_map(&self) -> Result<HashMap<MonitorId, MonitorData>, Error> {
        let db_txn = self.env.begin_ro_txn()?;
        self.monitor_store.get_map(&db_txn)
    }

    pub fn get_monitor_ids(&self) -> Result<Vec<MonitorId>, Error> {
        let db_txn = self.env.begin_ro_txn()?;
        self.monitor_store.get_ids(&db_txn)
    }

    pub fn get_subaddress_id_by_spk(
        &self,
        subaddress_spk: &SubaddressSPKId,
    ) -> Result<SubaddressId, Error> {
        let db_txn = self.env.begin_ro_txn()?;
        self.subaddress_store
            .get_index_data(&db_txn, subaddress_spk)
    }

    pub fn get_subaddress_id_by_utxo_id(&self, utxo_id: &UtxoId) -> Result<SubaddressId, Error> {
        let db_txn = self.env.begin_ro_txn()?;
        self.utxo_store
            .get_subaddress_id_by_utxo_id(&db_txn, utxo_id)
    }

    pub fn get_utxos_for_subaddress(
        &self,
        monitor_id: &MonitorId,
        index: u64,
    ) -> Result<Vec<UnspentTxOut>, Error> {
        let db_txn = self.env.begin_ro_txn()?;
        self.utxo_store.get_utxos(&db_txn, monitor_id, index)
    }

    pub fn update_attempted_spend(
        &self,
        utxo_ids: &[UtxoId],
        attempted_spend_height: u64,
        attempted_spend_tombstone: u64,
    ) -> Result<(), Error> {
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
        let mut db_txn = self.env.begin_rw_txn()?;

        // Get monitor data.
        let mut monitor_data = self.monitor_store.get_data(&db_txn, monitor_id)?;

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
                .append_utxo(&mut db_txn, &monitor_id, utxo.subaddress_index, &utxo)?;
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
            .set_data(&mut db_txn, monitor_id, &monitor_data)?;

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
        let db_txn = self.env.begin_ro_txn()?;

        // Get monitor data to see if the monitor has synced this block.
        let monitor_data = self.monitor_store.get_data(&db_txn, monitor_id)?;
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
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{error::Error, test_utils::get_test_databases};
    use mc_account_keys::AccountKey;
    use mc_common::logger::{test_with_logger, Logger};
    use rand::{rngs::StdRng, SeedableRng};
    use std::iter::FromIterator;
    use tempdir::TempDir;

    // Test that encryption happy path works as expected.
    #[test_with_logger]
    fn test_encryption_happy_path(logger: Logger) {
        let mut rng: StdRng = SeedableRng::from_seed([123u8; 32]);
        let account_key = AccountKey::random(&mut rng);

        let mobilecoind_db_tmp =
            TempDir::new("mobilecoind_db").expect("Could not make tempdir for mobilecoind db");
        let mobilecoind_db_path = mobilecoind_db_tmp
            .path()
            .to_str()
            .expect("Could not get path as string");

        let mobilecoind_db = Database::new(mobilecoind_db_path.to_string(), logger.clone())
            .expect("failed creating new mobilecoind db");

        // The db starts unencrypted.
        assert!(!mobilecoind_db.is_db_encrypted());
        assert!(mobilecoind_db.is_unlocked());

        // We should be able to insert a monitor at this point.
        let monitor_data = MonitorData::new(
            account_key.clone(),
            0,  // first_subaddress
            10, // num_subaddresses
            0,  // first_block
            "", // name
        )
        .unwrap();

        let monitor_id = mobilecoind_db
            .add_monitor(&monitor_data)
            .expect("failed adding monitor");

        // We should be able to get our monitor.
        assert_eq!(
            mobilecoind_db.get_monitor_map().unwrap(),
            HashMap::from_iter(vec![(monitor_id.clone(), monitor_data.clone())])
        );

        // Re-encrypting with an empty password should not affect things.
        mobilecoind_db.re_encrypt(&[]).unwrap();

        assert!(!mobilecoind_db.is_db_encrypted());
        assert!(mobilecoind_db.is_unlocked());

        assert_eq!(
            mobilecoind_db.get_monitor_map().unwrap(),
            HashMap::from_iter(vec![(monitor_id.clone(), monitor_data.clone())])
        );

        // Checking an empty password should not affect anything.
        mobilecoind_db.check_and_store_password(&[]).unwrap();

        assert!(!mobilecoind_db.is_db_encrypted());
        assert!(mobilecoind_db.is_unlocked());

        assert_eq!(
            mobilecoind_db.get_monitor_map().unwrap(),
            HashMap::from_iter(vec![(monitor_id.clone(), monitor_data.clone())])
        );

        // Checking a non-empty password should error and not affect things.
        assert!(mobilecoind_db.check_and_store_password(&[1; 32]).is_err());

        assert!(!mobilecoind_db.is_db_encrypted());
        assert!(mobilecoind_db.is_unlocked());

        assert_eq!(
            mobilecoind_db.get_monitor_map().unwrap(),
            HashMap::from_iter(vec![(monitor_id.clone(), monitor_data.clone())])
        );

        // Set a password.
        mobilecoind_db.re_encrypt(&[10; 32]).unwrap();

        assert!(mobilecoind_db.is_db_encrypted());
        assert!(mobilecoind_db.is_unlocked());

        assert_eq!(
            mobilecoind_db.get_monitor_map().unwrap(),
            HashMap::from_iter(vec![(monitor_id.clone(), monitor_data.clone())])
        );

        // Re-open the db.
        let mobilecoind_db = Database::new(mobilecoind_db_path.to_string(), logger.clone())
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

        assert_eq!(
            mobilecoind_db.get_monitor_map().unwrap(),
            HashMap::from_iter(vec![(monitor_id.clone(), monitor_data.clone())])
        );

        // Re-encrypt and repeat the test.
        mobilecoind_db.re_encrypt(&[11; 32]).unwrap();

        let mobilecoind_db = Database::new(mobilecoind_db_path.to_string(), logger.clone())
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

        assert_eq!(
            mobilecoind_db.get_monitor_map().unwrap(),
            HashMap::from_iter(vec![(monitor_id.clone(), monitor_data.clone())])
        );

        // Remove password and try again.
        mobilecoind_db.re_encrypt(&[]).unwrap();

        let mobilecoind_db = Database::new(mobilecoind_db_path.to_string(), logger)
            .expect("failed creating new mobilecoind db");

        assert!(!mobilecoind_db.is_db_encrypted());
        assert!(mobilecoind_db.is_unlocked());

        assert!(mobilecoind_db.check_and_store_password(&[10; 32]).is_err());

        assert_eq!(
            mobilecoind_db.get_monitor_map().unwrap(),
            HashMap::from_iter(vec![(monitor_id.clone(), monitor_data.clone())])
        );
    }

    // Inserting a monitor that overlaps subaddresses of another monitor should
    // result in an error.
    #[test_with_logger]
    fn test_overlapping_add_monitor_fails(logger: Logger) {
        let mut rng: StdRng = SeedableRng::from_seed([123u8; 32]);

        // Set up a db with 3 random recipients and 10 blocks.
        let (_ledger_db, mobilecoind_db) =
            get_test_databases(3, &vec![], 10, logger.clone(), &mut rng);

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
            Err(err) => panic!("unexpected error {:?}", err),
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
            Err(err) => panic!("unexpected error {:?}", err),
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
            Err(err) => panic!("unexpected error {:?}", err),
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
