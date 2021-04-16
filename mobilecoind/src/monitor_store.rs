// Copyright (c) 2018-2021 The MobileCoin Foundation

//! Database storage for monitors
//! * Provides monitor configuration and status from MonitorId.
//! * MonitorId is a hash of the instantiation parameters.

use crate::{database_key::DatabaseByteArrayKey, db_crypto::DbCryptoProvider, error::Error};

use lmdb::{Cursor, Database, DatabaseFlags, Environment, RwTransaction, Transaction, WriteFlags};
use mc_account_keys::AccountKey;
use mc_common::{
    logger::{log, Logger},
    HashMap,
};
use mc_crypto_digestible::{Digestible, MerlinTranscript};
use mc_crypto_keys::RistrettoPublic;
use mc_util_serial::Message;
use std::{convert::TryFrom, ops::Range, sync::Arc};

// LMDB Database Names
pub const MONITOR_ID_TO_MONITOR_DATA_DB_NAME: &str =
    "mobilecoind_db:monitor_store:monitor_id_to_monitor_data";

/// Type used as the stored data in the monitor_id_to_monitor_data database.
#[derive(Clone, Eq, Hash, PartialEq, Message)]
pub struct MonitorData {
    /// The private key pair for the account this monitor watches.
    #[prost(message, required, tag = "1")]
    pub account_key: AccountKey,

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
}

impl MonitorData {
    pub fn new(
        account_key: AccountKey,
        first_subaddress: u64,
        num_subaddresses: u64,
        first_block: u64,
        name: &str,
    ) -> Result<Self, Error> {
        if num_subaddresses == 0 {
            return Err(Error::InvalidArgument(
                "num_subaddresses".to_string(),
                "must be greater than zero".to_string(),
            ));
        }

        Ok(Self {
            account_key,
            first_subaddress,
            num_subaddresses,
            first_block,
            // The next block we need to sync is our first block.
            next_block: first_block,
            name: name.to_owned(),
        })
    }

    pub fn subaddress_indexes(&self) -> Range<u64> {
        self.first_subaddress..self.first_subaddress + self.num_subaddresses
    }
}

/// Type used as the key in the monitor_id_to_monitor_data database
pub type MonitorId = DatabaseByteArrayKey;

impl From<&MonitorData> for MonitorId {
    // When constructing a MonitorId from a given MonitorData object we only want to
    // hash the data that doesn't change over time.
    // Name isn't included here - two monitors with identical address/subaddress
    // range/first_block should have the same id even if they have a different
    // name,
    fn from(src: &MonitorData) -> MonitorId {
        // The structure of mc_account_keys::PublicAddress changed when the fog
        // signature scheme was implemented. This re-implements the original
        // structure in order to maintain a consistent hash in the database.
        //
        // This should eventually be removed.
        #[derive(Debug, Digestible)]
        struct PublicAddress {
            view_public_key: RistrettoPublic,
            spend_public_key: RistrettoPublic,
            fog_report_url: String,
            fog_report_id: String,
            fog_authority_fingerprint_sig: Vec<u8>,
        }

        #[derive(Debug, Digestible)]
        struct ConstMonitorData {
            // We use PublicAddress and not AccountKey so that the monitor_id is not sensitive.
            pub address: PublicAddress,
            pub first_subaddress: u64,
            pub num_subaddresses: u64,
            pub first_block: u64,
        }

        let real_subaddress = src.account_key.default_subaddress();

        let const_data = ConstMonitorData {
            address: PublicAddress {
                view_public_key: *real_subaddress.view_public_key(),
                spend_public_key: *real_subaddress.spend_public_key(),
                fog_report_url: real_subaddress
                    .fog_report_url()
                    .unwrap_or_default()
                    .to_owned(),
                fog_report_id: real_subaddress
                    .fog_report_id()
                    .unwrap_or_default()
                    .to_owned(),
                fog_authority_fingerprint_sig: real_subaddress
                    .fog_authority_sig()
                    .unwrap_or_default()
                    .to_vec(),
            },
            first_subaddress: src.first_subaddress,
            num_subaddresses: src.num_subaddresses,
            first_block: src.first_block,
        };

        let temp: [u8; 32] = const_data.digest32::<MerlinTranscript>(b"monitor_data");

        Self::from(temp)
    }
}

/// Wrapper for the monitor_id_to_monitor_data database
#[derive(Clone)]
pub struct MonitorStore {
    env: Arc<Environment>,

    /// Crypto provider, used for managing database encryption.
    crypto_provider: DbCryptoProvider,

    /// Mapping of MonitorId -> MonitorData
    monitor_id_to_monitor_data: Database,

    /// Logger.
    logger: Logger,
}

/// A DB mapping account IDs to keys
impl MonitorStore {
    pub fn new(
        env: Arc<Environment>,
        crypto_provider: DbCryptoProvider,
        logger: Logger,
    ) -> Result<Self, Error> {
        let monitor_id_to_monitor_data = env.create_db(
            Some(MONITOR_ID_TO_MONITOR_DATA_DB_NAME),
            DatabaseFlags::empty(),
        )?;

        Ok(Self {
            env,
            crypto_provider,
            monitor_id_to_monitor_data,
            logger,
        })
    }

    /// Add a new monitor.
    pub fn add<'env>(
        &self,
        db_txn: &mut RwTransaction<'env>,
        data: &MonitorData,
    ) -> Result<MonitorId, Error> {
        let monitor_id = MonitorId::from(data);
        let key_bytes = monitor_id.as_bytes();

        let value_bytes = self
            .crypto_provider
            .encrypt(&mc_util_serial::encode(data))?;

        log::trace!(self.logger, "adding new monitor {}: {:?}", monitor_id, data);

        match db_txn.put(
            self.monitor_id_to_monitor_data,
            key_bytes,
            &value_bytes,
            WriteFlags::NO_OVERWRITE,
        ) {
            Ok(_) => Ok(monitor_id),
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
                let value_bytes = self.crypto_provider.decrypt(value_bytes)?;
                let data: MonitorData = mc_util_serial::decode(&value_bytes)?;
                Ok(data)
            }
            Err(lmdb::Error::NotFound) => Err(Error::MonitorIdNotFound),
            Err(err) => Err(Error::Lmdb(err)),
        }
    }

    /// Get a hashmap of all MonitorId -> MonitorData.
    pub fn get_map(
        &self,
        db_txn: &impl Transaction,
    ) -> Result<HashMap<MonitorId, MonitorData>, Error> {
        let mut cursor = db_txn.open_ro_cursor(self.monitor_id_to_monitor_data)?;

        cursor
            .iter()
            .map(|result| {
                result
                    .map_err(Error::from)
                    .and_then(|(key_bytes, value_bytes)| {
                        let monitor_id = MonitorId::try_from(key_bytes)
                            .map_err(|_| Error::KeyDeserializationError)?;
                        let value_bytes = self.crypto_provider.decrypt(value_bytes)?;
                        let data: MonitorData = mc_util_serial::decode(&value_bytes)?;

                        Ok((monitor_id, data))
                    })
            })
            .collect::<Result<HashMap<_, _>, Error>>()
    }

    /// Get a list of all MonitorIds in database.
    pub fn get_ids(&self, db_txn: &impl Transaction) -> Result<Vec<MonitorId>, Error> {
        let mut cursor = db_txn.open_ro_cursor(self.monitor_id_to_monitor_data)?;
        cursor
            .iter()
            .map(|result| {
                result
                    .map_err(Error::from)
                    .and_then(|(key_bytes, _value_bytes)| {
                        MonitorId::try_from(key_bytes).map_err(|_| Error::KeyDeserializationError)
                    })
            })
            .collect::<Result<Vec<_>, Error>>()
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
                let new_value_bytes = self
                    .crypto_provider
                    .encrypt(&mc_util_serial::encode(data))?;
                db_txn.put(
                    self.monitor_id_to_monitor_data,
                    &key_bytes,
                    &new_value_bytes,
                    WriteFlags::empty(),
                )?;
                Ok(())
            }
            Err(lmdb::Error::NotFound) => Err(Error::MonitorIdNotFound),
            Err(err) => Err(Error::Lmdb(err)),
        }
    }

    /// Re-encrypt the encrypted parts of the database with a new password.
    /// This will fail if the current password is not set in the crypto_provider
    /// since part of the re-encryption process relies on being able to
    /// decrypt the existing data.
    pub fn re_encrypt<'env>(
        &self,
        db_txn: &mut RwTransaction<'env>,
        new_password: &[u8],
    ) -> Result<(), Error> {
        let mut cursor = db_txn.open_rw_cursor(self.monitor_id_to_monitor_data)?;

        for (key_bytes, value_bytes) in cursor.iter().filter_map(|r| r.ok()) {
            let decrypted_bytes = self.crypto_provider.decrypt(value_bytes)?;
            let encrypted_bytes = self
                .crypto_provider
                .encrypt_with_password(new_password, &decrypted_bytes)?;
            cursor.put(&key_bytes, &encrypted_bytes, WriteFlags::CURRENT)?;
        }

        Ok(())
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
    use rand_chacha::ChaChaRng;
    use rand_core::SeedableRng;

    /// A randomly generated RSA subjectPublicKeyInfo, used as a fog authority.
    const AUTHORITY_PUBKEY: &str = r"-----BEGIN PUBLIC KEY-----
MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAobfcLcLdKL3O4d1XOLE6
lGgcFOKZHsXT2Pbh+NF14EEwMCpvPiaOwfuLvycItdE3P2K+725B2CiAJdurx5yj
8ctc1M0N+Hed0vkO6R9FtYFLTZVPipTLqc03iowZALfqV6M0b3POXMyEMLTC14B0
wYerb58o1uACwmCzt5lXGdL3ZbiMZ+y8GdCIBEeqLHYpyC5nXg0L9U5EsYfUuYkN
tDZT6zE7/D+tWYArLtnRMBw4h3sPgKNWbu6wMDnBpiWXTKHsaJS3sfthlyLL0gyX
lb3gVdL7kBpUTTLGXE96VjojmPwM34+qNu4B39wLWhUuQ9ugjeDK1mMfYMJvVydm
nqH0WdmPFprsiYxMQgioP3mCThKcKGBBbdn3Ii8ZtFQN/NM8WteLgmUVZQ+fwF4G
L1OWnw6IEnHa8a0Shh8t8DGUl2dFjp8YCjOgyk0VqPGkD3c1Z6j95BZEDXSCziYj
C17bXAtQjU1ra+Uxg/e2vaEn7r8lzvPs/Iyc8Y8zt8eHRWgSr14trvxJRQhvXwwp
iX3vQok+sdmBmOS0Ox6nL4LLbnMxNkJ6c1P+LKE5eqz4oiShLDVCgWsdWyQSMuJU
pa4ba4HyA6JNtKvb8sk2CYXrBtp3PlBwclBOxSEAZDVq82o6dJ31MklpF0EG1y8C
pKZkdp8MQU5TLFOE9qjNeVsCAwEAAQ==
-----END PUBLIC KEY-----";

    /// Ensure the monitor ID for a test-vector key has not changed.
    #[test]
    fn monitor_id_stability() {
        /// The constant output by mobilecoind when the 1.0.1 release has been
        /// patched with stability-1.0.1.diff from the root of this tree.
        const HEXPECTED: &str = r"cd57649f325d525cf96120dd303ab3bba6d15071861425c62fad6949335cc604";
        /// The fog output by mobilecoind when the 1.0.1 release has been
        /// patched with stability-1.0.1.diff from the root of this tree.
        const FOG_HEXPECTED: &str =
            r"e4bc6cd685d5b272e5a34c6b0aacf820029ad108df0007c46b0df1ba645107e5";

        let mut rng = ChaChaRng::seed_from_u64(0);

        let identity = RootIdentity::from_random(&mut rng);
        let key = AccountKey::try_from(&identity)
            .expect("Could not create account key from non-fog identity");
        let data = MonitorData::new(key, 1, 10, 1, "test").expect("Could not create monitor data");
        let id = MonitorId::from(&data);
        let expected = hex::decode(HEXPECTED).expect("Could not decode expected data to bytes");
        assert_eq!(expected, id.as_bytes().to_vec(), "{}", hex_fmt::HexFmt(id));

        let fog_authority_spki = pem::parse(AUTHORITY_PUBKEY)
            .expect("Could not parse pubkey")
            .contents;
        let fog_identity = RootIdentity::random_with_fog(
            &mut rng,
            "fog://fog.unittest.mobilecoin.com",
            "",
            &fog_authority_spki,
        );
        let fog_key = AccountKey::from(&fog_identity);
        let fog_data = MonitorData::new(fog_key, 10, 100, 10, "fog test")
            .expect("Could not create monitor data");
        let fog_id = MonitorId::from(&fog_data);
        let fog_expected =
            hex::decode(FOG_HEXPECTED).expect("Could not decode expected data to bytes");
        assert_eq!(
            fog_expected,
            fog_id.as_bytes().to_vec(),
            "{}/{}",
            FOG_HEXPECTED,
            HEXPECTED
        );
    }

    // MonitorStore basic functionality tests
    #[test_with_logger]
    fn test_monitor_store(logger: Logger) {
        let mut rng = ChaChaRng::from_seed([123u8; 32]);

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

        let _ = mobilecoind_db
            .add_monitor(&monitor_data0)
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

        let _ = mobilecoind_db
            .add_monitor(&monitor_data1)
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

        // monitor_id2 was never inserted into the database, so getting its data should
        // fail.
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
}
