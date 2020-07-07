use crate::Error;
use lmdb::{Database, DatabaseFlags, Environment, RwTransaction, Transaction, WriteFlags};
use mc_util_serial::{decode, encode};
use prost::Message;

// Default database version. This should be bumped when breaking changes are introduced.
// If this is properly maintained, we could check during ledger db opening for any
// incompatibilities, and either refuse to open or perform a migration.
#[allow(clippy::unreadable_literal)]
pub const LATEST_VERSION: u64 = 20200707;

// Metadata information about the ledger databse.
#[derive(Clone, Message)]
pub struct MetadataVersion {
    // Database format version.
    #[prost(uint64)]
    pub database_format_version: u64,

    // Crate version that created the database. This could be bumped by a migration in a future
    // release.
    #[prost(string)]
    pub created_by_crate_version: String,
}

impl MetadataVersion {
    /// Construct a MetadataVersion instance with the most up to date versioning information.
    pub fn latest() -> Self {
        Self {
            database_format_version: LATEST_VERSION,
            created_by_crate_version: env!("CARGO_PKG_VERSION").to_owned(),
        }
    }

    /// Check if a given version is compatible with the latest version.
    pub fn is_compatible_with_latest(&self) -> Result<(), Error> {
        let latest = Self::latest();
        if self.database_format_version != latest.database_format_version {
            Err(Error::VersionIncompatible(
                self.database_format_version,
                latest.database_format_version,
            ))
        } else {
            Ok(())
        }
    }
}

// LMDB Database names.
const METADATA_DB_NAME: &str = "ledger_db_metadata";

// Keys in the metadata database
const METADATA_VERSION_KEY: &str = "version";

#[derive(Clone)]
pub struct MetadataStore {
    metadata: Database,
}

impl MetadataStore {
    /// Opens an existing MetadataStore.
    pub fn new(env: &Environment) -> Result<Self, Error> {
        Ok(Self {
            metadata: env.open_db(Some(METADATA_DB_NAME))?,
        })
    }

    // Creates a fresh MetadataStore on disk.
    pub fn create(env: &Environment) -> Result<(), Error> {
        let metadata = env.create_db(Some(METADATA_DB_NAME), DatabaseFlags::empty())?;

        let mut db_transaction = env.begin_rw_txn()?;

        db_transaction.put(
            metadata,
            &METADATA_VERSION_KEY,
            &encode(&MetadataVersion::latest()),
            WriteFlags::empty(),
        )?;

        db_transaction.commit()?;
        Ok(())
    }

    // Get version data from the database.
    pub fn get_version(&self, db_txn: &impl Transaction) -> Result<MetadataVersion, Error> {
        Ok(decode(db_txn.get(self.metadata, &METADATA_VERSION_KEY)?)?)
    }

    // Set version to latest.
    pub fn set_version_to_latest(&self, db_txn: &mut RwTransaction) -> Result<(), Error> {
        Ok(db_txn.put(
            self.metadata,
            &METADATA_VERSION_KEY,
            &encode(&MetadataVersion::latest()),
            WriteFlags::empty(),
        )?)
    }
}
