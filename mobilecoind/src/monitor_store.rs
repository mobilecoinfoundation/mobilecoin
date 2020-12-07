// Copyright (c) 2018-2020 MobileCoin Inc.

//! Database storage for monitors
//! * Provides monitor configuration and status from MonitorId.
//! * MonitorId is a hash of the instantiation parameters.

use crate::{database_key::DatabaseByteArrayKey, error::Error};

use aes_gcm::{
    aead::{generic_array::GenericArray, Aead, NewAead},
    Aes256Gcm,
};
use blake2::{Blake2b, Digest};
use lmdb::{Cursor, Database, DatabaseFlags, Environment, RwTransaction, Transaction, WriteFlags};
use mc_account_keys::{AccountKey, PublicAddress};
use mc_common::{
    logger::{log, Logger},
    HashMap,
};
use mc_crypto_digestible::{Digestible, MerlinTranscript};
use mc_util_serial::Message;
use std::{convert::TryFrom, ops::Range, sync::Arc};

// LMDB Database Names
pub const MONITOR_ID_TO_MONITOR_DATA_DB_NAME: &str =
    "mobilecoind_db:monitor_store:monitor_id_to_monitor_data";

// Domain tag for account key encryption
pub const ACCOUNT_KEY_DOMAIN_TAG: &str = "mc_account_key";

/// Type used as the stored data in the monitor_id_to_monitor_data database.
#[derive(Clone, Eq, Hash, PartialEq, Message)]
pub struct MonitorData {
    /// The private key pair for the account this monitor watches.
    #[prost(message, tag = "1")]
    pub account_key: Option<AccountKey>,

    /// The smallest subaddress index in the range this monitor watches.
    #[prost(uint64, tag = "2")]
    pub first_subaddress: u64,

    /// The number of subaddresses this monitor watches.
    #[prost(uint64, tag = "3")]
    pub num_subaddresses: u64,

    /// The first block this monitor should process.
    #[prost(uint64, tag = "4")]
    pub first_block: u64,

    /// The next block this monitor needs to process.
    #[prost(uint64, tag = "5")]
    pub next_block: u64,

    /// Optional monitor name.
    #[prost(string, tag = "6")]
    pub name: String,

    /// Encrypted account key
    #[prost(message, tag = "7")]
    pub encrypted_account_key: Option<Vec<u8>>,
}

impl MonitorData {
    pub fn new(
        account_key: AccountKey,
        first_subaddress: u64,
        num_subaddresses: u64,
        first_block: u64,
        name: &str,
        password_hash: Option<Vec<u8>>,
    ) -> Result<Self, Error> {
        if num_subaddresses == 0 {
            return Err(Error::InvalidArgument(
                "num_subaddresses".to_string(),
                "must be greater than zero".to_string(),
            ));
        }

        if let Some(pw) = password_hash {
            let (key, nonce) = Self::expand_password_hash(&pw)?;

            let key_arr = GenericArray::from_slice(&key[..]);
            let nonce_arr = GenericArray::from_slice(&nonce[..]);

            // Get cipher from hash bytes
            let cipher = Aes256Gcm::new(key_arr);

            let plaintext_bytes = mc_util_serial::encode(&account_key);

            let ciphertext = cipher
                .encrypt(nonce_arr, &plaintext_bytes[..])
                .expect("encryption failure!"); // NOTE: handle this error to avoid panics!

            Ok(Self {
                account_key: None,
                first_subaddress,
                num_subaddresses,
                first_block,
                // The next block we need to sync is our first block.
                next_block: first_block,
                name: name.to_owned(),
                encrypted_account_key: Some(ciphertext.to_vec()),
            })
        } else {
            Ok(Self {
                account_key: Some(account_key),
                first_subaddress,
                num_subaddresses,
                first_block,
                // The next block we need to sync is our first block.
                next_block: first_block,
                name: name.to_owned(),
                encrypted_account_key: None,
            })
        }
    }

    pub fn subaddress_indexes(&self) -> Range<u64> {
        self.first_subaddress..self.first_subaddress + self.num_subaddresses
    }

    fn expand_password_hash(password_hash: &[u8]) -> Result<([u8; 32], [u8; 12]), Error> {
        // Password hash must be 32 bytes
        if password_hash.len() < 32 {
            return Err(Error::PasswordHashLen);
        }
        // Hash the password hash with Blake2b to get 64 bytes, first 32 for aeskey, second 32 for nonce
        let mut hasher = Blake2b::new();
        hasher.update(&ACCOUNT_KEY_DOMAIN_TAG);
        hasher.update(&password_hash);
        let mut key = [0u8; 32];
        let mut nonce = [0u8; 12];
        let result = hasher.finalize();
        key[..32].copy_from_slice(&result.as_slice()[..32]);
        // Nonce is 96 bits
        nonce[..12].copy_from_slice(&result.as_slice()[32..44]);

        Ok((key, nonce))
    }

    pub fn get_account_key(
        &self,
        opt_password_hash: Option<&Vec<u8>>,
    ) -> Result<AccountKey, Error> {
        // If we are storing the account key unencrypted, return it directly.
        if let Some(ac) = self.account_key.clone() {
            Ok(ac)
        } else if self.encrypted_account_key.is_some() {
            if let Some(password_hash) = opt_password_hash {
                let (key, nonce) = Self::expand_password_hash(password_hash)?;
                let key_arr = GenericArray::from_slice(&key[..]);
                let nonce_arr = GenericArray::from_slice(&nonce[..]);

                let cipher = Aes256Gcm::new(key_arr);
                if let Some(encrypted_bytes) = self.encrypted_account_key.clone() {
                    let plaintext = cipher.decrypt(nonce_arr, encrypted_bytes.as_ref())?;

                    let decrypted_account_key = mc_util_serial::decode(&plaintext)?;
                    Ok(decrypted_account_key)
                } else {
                    Err(Error::AccountKeyNotEncrypted)
                }
            } else {
                // Password required to decrypt account key
                Err(Error::AccountKeyDecryption)
            }
        } else {
            // We should not get here, but always good to error just in case.
            Err(Error::NoAccountKeyInMonitor)
        }
    }
}

/// Type used as the key in the monitor_id_to_monitor_data database
pub type MonitorId = DatabaseByteArrayKey;

impl MonitorId {
    // When constructing a MonitorId we only want to hash the data that doesn't change over time.
    // Name isn't included here - two monitors with identical address/subaddress range/first_block
    // should have the same id even if they have a different name,
    // Note that because a Monitor can have either unencrypted or encrypted account key data,
    // and that data can only be decrypted with the password hash stored in memory, you can only
    // construct a MonitorId when you have the plaintext account key.
    pub fn new(
        account_key: AccountKey,
        first_subaddress: u64,
        num_subaddresses: u64,
        first_block: u64,
    ) -> MonitorId {
        #[derive(Digestible)]
        struct ConstMonitorData {
            // We use PublicAddress and not AccountKey so that the monitor_id is not sensitive.
            pub address: PublicAddress,
            pub first_subaddress: u64,
            pub num_subaddresses: u64,
            pub first_block: u64,
        }
        let const_data = ConstMonitorData {
            address: account_key.default_subaddress(),
            first_subaddress,
            num_subaddresses,
            first_block,
        };

        let temp: [u8; 32] = const_data.digest32::<MerlinTranscript>(b"monitor_data");
        Self::from(temp)
    }
}

/// Wrapper for the monitor_id_to_monitor_data database
#[derive(Clone)]
pub struct MonitorStore {
    env: Arc<Environment>,

    /// Mapping of MonitorId -> MonitorData
    monitor_id_to_monitor_data: Database,

    /// Logger.
    logger: Logger,
}

/// A DB mapping account IDs to keys
impl MonitorStore {
    pub fn new(env: Arc<Environment>, logger: Logger) -> Result<Self, Error> {
        let monitor_id_to_monitor_data = env.create_db(
            Some(MONITOR_ID_TO_MONITOR_DATA_DB_NAME),
            DatabaseFlags::empty(),
        )?;

        Ok(Self {
            env,
            monitor_id_to_monitor_data,
            logger,
        })
    }

    /// Add a new monitor.
    pub fn add<'env>(
        &self,
        db_txn: &mut RwTransaction<'env>,
        monitor_id: &MonitorId,
        data: &MonitorData,
    ) -> Result<(), Error> {
        let key_bytes = monitor_id.as_bytes();

        let value_bytes = mc_util_serial::encode(data);

        log::trace!(self.logger, "adding new monitor {}: {:?}", monitor_id, data);

        match db_txn.put(
            self.monitor_id_to_monitor_data,
            key_bytes,
            &value_bytes,
            WriteFlags::NO_OVERWRITE,
        ) {
            Ok(_) => Ok(()),
            Err(lmdb::Error::KeyExist) => Err(Error::MonitorIdExists),
            Err(err) => Err(err.into()),
        }
    }

    /// Delete data for a given monitor.
    pub fn remove<'env>(
        &self,
        db_txn: &mut RwTransaction<'env>,
        monitor_id: &MonitorId,
    ) -> Result<(), Error> {
        db_txn.del(self.monitor_id_to_monitor_data, monitor_id, None)?;
        Ok(())
    }

    /// Get the MonitorData for a given `monitor_id`.
    pub fn get_data(
        &self,
        db_txn: &impl Transaction,
        monitor_id: &MonitorId,
    ) -> Result<MonitorData, Error> {
        match db_txn.get(self.monitor_id_to_monitor_data, monitor_id) {
            Ok(value_bytes) => {
                let data: MonitorData = mc_util_serial::decode(value_bytes)?;
                Ok(data)
            }
            Err(lmdb::Error::NotFound) => Err(Error::MonitorIdNotFound),
            Err(err) => Err(Error::LMDB(err)),
        }
    }

    /// Get a hashmap of all MonitorId -> MonitorData.
    pub fn get_map(
        &self,
        db_txn: &impl Transaction,
    ) -> Result<HashMap<MonitorId, MonitorData>, Error> {
        let mut cursor = db_txn.open_ro_cursor(self.monitor_id_to_monitor_data)?;

        Ok(cursor
            .iter()
            .map(|result| {
                result
                    .map_err(Error::from)
                    .and_then(|(key_bytes, value_bytes)| {
                        let monitor_id = MonitorId::try_from(key_bytes)
                            .map_err(|_| Error::KeyDeserializationError)?;
                        let data: MonitorData = mc_util_serial::decode(value_bytes)?;

                        Ok((monitor_id, data))
                    })
            })
            .collect::<Result<HashMap<_, _>, Error>>()?)
    }

    /// Get a list of all MonitorIds in database.
    pub fn get_ids(&self, db_txn: &impl Transaction) -> Result<Vec<MonitorId>, Error> {
        let mut cursor = db_txn.open_ro_cursor(self.monitor_id_to_monitor_data)?;
        Ok(cursor
            .iter()
            .map(|result| {
                result
                    .map_err(Error::from)
                    .and_then(|(key_bytes, _value_bytes)| {
                        MonitorId::try_from(key_bytes).map_err(|_| Error::KeyDeserializationError)
                    })
            })
            .collect::<Result<Vec<_>, Error>>()?)
    }

    /// Set the MonitorData for an existing monitor
    pub fn set_data<'env>(
        &self,
        db_txn: &mut RwTransaction<'env>,
        monitor_id: &MonitorId,
        data: &MonitorData,
    ) -> Result<(), Error> {
        let key_bytes = monitor_id.to_vec();
        match db_txn.get(self.monitor_id_to_monitor_data, &key_bytes) {
            Ok(_value_bytes) => {
                let new_value_bytes = mc_util_serial::encode(data);
                db_txn.put(
                    self.monitor_id_to_monitor_data,
                    &key_bytes,
                    &new_value_bytes,
                    WriteFlags::empty(),
                )?;
                Ok(())
            }
            Err(lmdb::Error::NotFound) => Err(Error::MonitorIdNotFound),
            Err(err) => Err(Error::LMDB(err)),
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{
        error::Error,
        test_utils::{get_test_databases, get_test_monitor_data_and_id},
    };
    use mc_account_keys::RootIdentity;
    use mc_common::logger::{test_with_logger, Logger};
    use mc_util_from_random::FromRandom;
    use rand::{rngs::StdRng, SeedableRng};
    use rand_core::RngCore;

    // MonitorStore basic functionality tests
    #[test_with_logger]
    fn test_monitor_store(logger: Logger) {
        let mut rng: StdRng = SeedableRng::from_seed([123u8; 32]);

        // Set up a db with 3 random recipients and 10 blocks.
        let (_ledger_db, mobilecoind_db) =
            get_test_databases(3, &vec![], 10, logger.clone(), &mut rng);

        // Check that there are no monitors yet.
        assert_eq!(
            mobilecoind_db
                .get_monitor_map()
                .expect("failed to get empty map")
                .keys()
                .cloned()
                .collect::<Vec<MonitorId>>(),
            vec![]
        );

        log::trace!(logger, "confirmed database was created with no monitors");

        // Insert the monitors and check that that they appear in the db.
        let (mut monitor_data0, monitor_id0) = get_test_monitor_data_and_id(&mut rng);
        let (monitor_data1, monitor_id1) = get_test_monitor_data_and_id(&mut rng);
        let (_monitor_data, monitor_id2) = get_test_monitor_data_and_id(&mut rng);

        monitor_data0.name = "test name".to_owned();

        let account_key0 = monitor_data0.get_account_key(None).unwrap();
        mobilecoind_db
            .add_monitor(&monitor_id0, &account_key0, &monitor_data0)
            .expect("failed inserting monitor 0");
        assert_eq!(
            mobilecoind_db
                .get_monitor_map()
                .expect("failed to get map")
                .keys()
                .cloned()
                .collect::<Vec<MonitorId>>(),
            vec![monitor_id0.clone()]
        );

        let account_key1 = monitor_data1.get_account_key(None).unwrap();
        mobilecoind_db
            .add_monitor(&monitor_id1, &account_key1, &monitor_data1)
            .expect("failed inserting monitor 1");
        assert_eq!(
            mobilecoind_db
                .get_monitor_map()
                .expect("failed to get map")
                .keys()
                .cloned()
                .collect::<Vec<MonitorId>>()
                .sort(),
            vec![monitor_id0.clone(), monitor_id1.clone()].sort()
        );

        // Check that monitor data is recoverable.
        assert_eq!(
            mobilecoind_db
                .get_monitor_data(&monitor_id1)
                .expect("failed getting monitor data 1"),
            monitor_data1.clone()
        );
        assert_eq!(
            mobilecoind_db
                .get_monitor_data(&monitor_id0)
                .expect("failed getting monitor data 0"),
            monitor_data0.clone()
        );

        // monitor_id2 was never inserted into the database, so getting its data should fail.
        #[allow(clippy::match_wild_err_arm)]
        match mobilecoind_db.get_monitor_data(&monitor_id2) {
            Ok(_) => {
                panic!("shouldn't happen");
            }
            Err(Error::MonitorIdNotFound) => {}
            Err(_) => {
                panic!("shouldn't happen");
            }
        }
    }

    #[test_with_logger]
    fn test_account_key_encryption(_logger: Logger) {
        let mut rng: StdRng = SeedableRng::from_seed([123u8; 32]);

        let mut password_hash = vec![0u8; 32];
        rng.fill_bytes(&mut password_hash);

        let account_key = AccountKey::from(&RootIdentity::from_random(&mut rng));
        let monitor_data = MonitorData::new(
            account_key.clone(),
            0,
            1,
            0,
            "",
            Some(password_hash.clone()),
        )
        .unwrap();

        let decrypted_account_key = monitor_data.get_account_key(Some(&password_hash)).unwrap();

        assert_eq!(decrypted_account_key, account_key);
    }
}
