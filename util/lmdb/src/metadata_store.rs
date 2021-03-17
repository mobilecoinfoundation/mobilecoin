// Copyright (c) 2018-2021 The MobileCoin Foundation

//! MetadataStore - an LMDB database that stores metadata about the database.
//! Right now this is limited to versioning information.

use displaydoc::Display;
use lmdb::{
    Database, DatabaseFlags, Environment, Error as LmdbError, RwTransaction, Transaction,
    WriteFlags,
};
use mc_util_serial::{decode, encode};
use prost::Message;

/// An error type.
#[derive(Debug, Display, Eq, PartialEq, Copy, Clone)]
pub enum MetadataStoreError {
    /// LMDB Error: {0}
    Lmdb(LmdbError),

    /// Database version {0} is incompatible with {1}
    VersionIncompatible(u64, u64),

    /// Serialization
    Serialization,

    /// Deserialization
    Deserialization,
}

impl From<LmdbError> for MetadataStoreError {
    fn from(src: LmdbError) -> Self {
        Self::Lmdb(src)
    }
}

impl From<mc_util_serial::DecodeError> for MetadataStoreError {
    fn from(_: mc_util_serial::DecodeError) -> Self {
        Self::Deserialization
    }
}

impl From<mc_util_serial::EncodeError> for MetadataStoreError {
    fn from(_: mc_util_serial::EncodeError) -> Self {
        Self::Serialization
    }
}

/// A trait that defines the per-db settings for a MetadataStore.
pub trait MetadataStoreSettings: Default {
    /// Default database version. This should be bumped when breaking changes
    /// are introduced. If this is properly maintained, we could check
    /// during database opening for any incompatibilities, and either refuse
    /// to open or perform a migration.
    const LATEST_VERSION: u64;

    /// The current crate version that manages the database.
    const CRATE_VERSION: &'static str;

    /// LMDB Database name to use for storing the metadata information.
    const DB_NAME: &'static str;

    /// Check if a given version is compatible with the latest version.
    /// The default implementation assumes only the latest version is
    /// compatible.
    fn is_compatible_with_latest(
        metadata_version: &MetadataVersion<Self>,
    ) -> Result<(), MetadataStoreError> {
        let latest = MetadataVersion::<Self>::latest();
        if metadata_version.database_format_version != latest.database_format_version {
            Err(MetadataStoreError::VersionIncompatible(
                metadata_version.database_format_version,
                latest.database_format_version,
            ))
        } else {
            Ok(())
        }
    }
}

/// Metadata information stored inside the LMDB database.
#[derive(Clone, Message)]
struct StoredMetadataVersion {
    /// Database format version.
    #[prost(uint64)]
    pub database_format_version: u64,

    /// Crate version that created the database. This could be bumped by a
    /// migration in a future release.
    #[prost(string)]
    pub created_by_crate_version: String,
}
impl<S: MetadataStoreSettings> From<&MetadataVersion<S>> for StoredMetadataVersion {
    fn from(src: &MetadataVersion<S>) -> Self {
        Self {
            database_format_version: src.database_format_version,
            created_by_crate_version: src.created_by_crate_version.clone(),
        }
    }
}

/// Metadata information about a database instance.
#[derive(Clone, Debug)]
pub struct MetadataVersion<S: MetadataStoreSettings> {
    /// Database format version.
    pub database_format_version: u64,

    /// Crate version that created the database. This could be bumped by a
    /// migration in a future release.
    pub created_by_crate_version: String,

    _s: S,
}
impl<S: MetadataStoreSettings> From<&StoredMetadataVersion> for MetadataVersion<S> {
    fn from(src: &StoredMetadataVersion) -> Self {
        Self {
            database_format_version: src.database_format_version,
            created_by_crate_version: src.created_by_crate_version.clone(),
            _s: Default::default(),
        }
    }
}

impl<S: MetadataStoreSettings> MetadataVersion<S> {
    /// Construct a MetadataVersion instance with the most up to date versioning
    /// information.
    pub fn latest() -> Self {
        Self::with_database_format_version(S::LATEST_VERSION)
    }

    /// Construct a MetadataVersion instance with a specific
    /// database_format_version.
    pub fn with_database_format_version(database_format_version: u64) -> Self {
        Self {
            database_format_version,
            created_by_crate_version: S::CRATE_VERSION.to_owned(),
            _s: Default::default(),
        }
    }

    /// Check if a given version is compatible with the latest version.
    pub fn is_compatible_with_latest(&self) -> Result<(), MetadataStoreError> {
        S::is_compatible_with_latest(&self)
    }
}

// Keys in the metadata database
const METADATA_VERSION_KEY: &str = "version";

#[derive(Clone)]
pub struct MetadataStore<S: MetadataStoreSettings> {
    metadata: Database,
    _s: S,
}

impl<S: MetadataStoreSettings> MetadataStore<S> {
    /// Opens an existing MetadataStore.
    pub fn new(env: &Environment) -> Result<Self, MetadataStoreError> {
        Ok(Self {
            metadata: env.open_db(Some(S::DB_NAME))?,
            _s: Default::default(),
        })
    }

    /// Creates a fresh MetadataStore on disk.
    pub fn create(env: &Environment) -> Result<(), MetadataStoreError> {
        let metadata = env.create_db(Some(S::DB_NAME), DatabaseFlags::empty())?;

        let mut db_transaction = env.begin_rw_txn()?;

        db_transaction.put(
            metadata,
            &METADATA_VERSION_KEY,
            &encode(&StoredMetadataVersion::from(&MetadataVersion::<S>::latest())),
            WriteFlags::empty(),
        )?;

        db_transaction.commit()?;
        Ok(())
    }

    /// Open an existing MetadadataStore, or create a default one if it does not
    /// exist.
    pub fn open_or_create(env: &Environment) -> Result<Self, MetadataStoreError> {
        Self::new(&env).or_else(|err| {
            if err == MetadataStoreError::Lmdb(lmdb::Error::NotFound) {
                Self::create(&env)?;
                Self::new(&env)
            } else {
                Err(err)
            }
        })
    }

    /// Get version data from the database.
    pub fn get_version(
        &self,
        db_txn: &impl Transaction,
    ) -> Result<MetadataVersion<S>, MetadataStoreError> {
        let stored: StoredMetadataVersion =
            decode(db_txn.get(self.metadata, &METADATA_VERSION_KEY)?)?;
        Ok(MetadataVersion::from(&stored))
    }

    /// Set version to latest.
    pub fn set_version_to_latest(
        &self,
        db_txn: &mut RwTransaction,
    ) -> Result<(), MetadataStoreError> {
        Ok(db_txn.put(
            self.metadata,
            &METADATA_VERSION_KEY,
            &encode(&StoredMetadataVersion::from(&MetadataVersion::<S>::latest())),
            WriteFlags::empty(),
        )?)
    }

    /// Set version to a specific version.
    pub fn set_version(
        &self,
        db_txn: &mut RwTransaction,
        database_format_version: u64,
    ) -> Result<(), MetadataStoreError> {
        let metadata_version =
            MetadataVersion::<S>::with_database_format_version(database_format_version);

        Ok(db_txn.put(
            self.metadata,
            &METADATA_VERSION_KEY,
            &encode(&StoredMetadataVersion::from(&metadata_version)),
            WriteFlags::empty(),
        )?)
    }
}
