// Copyright (c) 2018-2021 The MobileCoin Foundation

//! The watcher database

use crate::{block_data_store::BlockDataStore, error::WatcherDBError};

use mc_attest_core::VerificationReport;
use mc_common::{
    logger::{log, Logger},
    HashMap,
};
use mc_crypto_digestible::{Digestible, MerlinTranscript};
use mc_crypto_keys::Ed25519Public;
use mc_transaction_core::{BlockData, BlockIndex, BlockSignature};
use mc_util_lmdb::{MetadataStore, MetadataStoreSettings};
use mc_util_repr_bytes::ReprBytes;
use mc_util_serial::{decode, encode, Message};
use mc_watcher_api::TimestampResultCode;

use lmdb::{
    Cursor, Database, DatabaseFlags, Environment, EnvironmentFlags, RwTransaction, Transaction,
    WriteFlags,
};
use mc_util_repr_bytes::typenum::Unsigned;
use std::{
    convert::{TryFrom, TryInto},
    path::Path,
    str::FromStr,
    sync::Arc,
    time::{Duration, Instant},
};
use url::Url;

/// LMDB Constant.
const MAX_LMDB_FILE_SIZE: usize = 1_099_511_627_776; // 1 TB

/// Metadata store settings that are used for version control.
#[derive(Clone, Default, Debug)]
pub struct WatcherDbMetadataStoreSettings;
impl MetadataStoreSettings for WatcherDbMetadataStoreSettings {
    // Default database version. This should be bumped when breaking changes are
    // introduced. If this is properly maintained, we could check during ledger
    // db opening for any incompatibilities, and either refuse to open or
    // perform a migration.
    #[allow(clippy::unreadable_literal)]
    const LATEST_VERSION: u64 = 20210127;

    /// The current crate version that manages the database.
    const CRATE_VERSION: &'static str = env!("CARGO_PKG_VERSION");

    /// LMDB Database name to use for storing the metadata information.
    const DB_NAME: &'static str = "watcher_db_metadata";
}

/// Block signatures database name.
pub const BLOCK_SIGNATURES_DB_NAME: &str = "watcher_db:block_signatures";

/// VerificationReports database name.
pub const VERIFICATION_REPORTS_BY_BLOCK_SIGNER_DB_NAME: &str =
    "watcher_db:verification_reports_by_block_signer";

/// Verification reports poll queue database name.
pub const VERIFICATION_REPORTS_POLL_QUEUE_DB_NAME: &str =
    "watcher_db:verification_reports_poll_queue";

/// Verification reports by report hash database name.
pub const VERIFICATION_REPORTS_BY_HASH_DB_NAME: &str = "watcher_db:verification_reports_by_hash";

/// Last synced archive blocks database name.
pub const LAST_SYNCED_DB_NAME: &str = "watcher_db:last_synced";

/// Last known config database name.
pub const CONFIG_DB_NAME: &str = "watcher_db:config";

/// Keys used by the `config` database.
pub const CONFIG_DB_KEY_TX_SOURCE_URLS: &str = "tx_source_urls";

/// Poll block timestamp polling frequency for new data every 10 ms
pub const POLL_BLOCK_TIMESTAMP_POLLING_FREQUENCY: Duration = Duration::from_millis(10);

/// Poll block timestamp error retry frequency. The reason we have an error
/// retry frequency is because when  a database invariant is violated, e.g. we
/// get block but not block contents, it typically will not be fixed and so we
/// won't be able to proceed. Generally when an invariant is violated we would
/// panic, but this code is used in services that are expensive to restart (such
/// as the ingest enclave and ledger enclave)
///
/// So instead, if this happens, we log an error, and retry in 1s.
/// This avoids logging at > 1hz when there is this error, which would be
/// very spammy. But the retries are unlikely to eventually lead to
/// progress. Another strategy might be for the server to enter a
/// "paused" state and signal for intervention.
pub const POLL_BLOCK_TIMESTAMP_ERROR_RETRY_FREQUENCY: Duration = Duration::from_millis(1000);

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

    /// BlockData store.
    block_data_store: BlockDataStore,

    /// Signature store.
    block_signatures: Database,

    /// Verification reports by block signer (and tx source url) database.
    /// This actually points to report hashes, which then allow getting the
    /// actual report contents from the verification_reports_by_hash
    /// database. This is needed because LMDB limits the value size in
    /// DUP_SORT databases to 511 bytes, not enough to fit the report. This
    /// database needs to be DUP_SORT since we want to support the
    /// odd case of different reports showing up for the same signer/url pair.
    /// It shouldn't happen, but we sure don't want to miss it if it does.
    verification_reports_by_signer: Database,

    /// Verification report hash -> VerificationReport.
    verification_reports_by_hash: Database,

    /// Verification reports poll queue database.
    /// This database holds a map of tx source url -> list of observed block
    /// signers. A background thread polls this database, trying to fetch
    /// the attestation verification report for each of queued tx source
    /// urls, and if successfull match the reported block signer identity
    /// with the list of observed signers. The verification report is then
    /// stored using `add_verification_report` and the tx source url is
    /// removed from the queue.
    verification_reports_poll_queue: Database,

    /// Last synced archive block.
    last_synced: Database,

    /// Config database - stores the settings the watcher was started with.
    /// This allows the code that reads data from the database to only look at
    /// the set of URLs currently being polled.
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
    pub fn open_ro(path: &Path, logger: Logger) -> Result<Self, WatcherDBError> {
        let env = Arc::new(
            Environment::new()
                .set_max_dbs(10)
                .set_map_size(MAX_LMDB_FILE_SIZE)
                // TODO - needed because currently our test cloud machines have slow disks.
                .set_flags(EnvironmentFlags::NO_SYNC)
                .open(path)?,
        );

        let metadata_store = MetadataStore::<WatcherDbMetadataStoreSettings>::new(&env)?;

        let db_txn = env.begin_ro_txn()?;
        let version = metadata_store.get_version(&db_txn)?;
        log::info!(logger, "Watcher db is currently at version: {:?}", version);
        db_txn.commit()?;

        version.is_compatible_with_latest()?;

        let block_signatures = env.open_db(Some(BLOCK_SIGNATURES_DB_NAME))?;
        let verification_reports_by_signer =
            env.open_db(Some(VERIFICATION_REPORTS_BY_BLOCK_SIGNER_DB_NAME))?;
        let verification_reports_by_hash =
            env.open_db(Some(VERIFICATION_REPORTS_BY_HASH_DB_NAME))?;
        let verification_reports_poll_queue =
            env.open_db(Some(VERIFICATION_REPORTS_POLL_QUEUE_DB_NAME))?;
        let last_synced = env.open_db(Some(LAST_SYNCED_DB_NAME))?;
        let config = env.open_db(Some(CONFIG_DB_NAME))?;

        let block_data_store = BlockDataStore::new(env.clone(), logger.clone())?;

        Ok(WatcherDB {
            env,
            block_data_store,
            block_signatures,
            verification_reports_by_signer,
            verification_reports_by_hash,
            verification_reports_poll_queue,
            last_synced,
            config,
            write_allowed: false,
            metadata_store,
            logger,
        })
    }

    /// Open an existing WatcherDB for read-write operations.
    pub fn open_rw(
        path: &Path,
        tx_source_urls: &[Url],
        logger: Logger,
    ) -> Result<Self, WatcherDBError> {
        let mut db = Self::open_ro(path, logger)?;
        db.write_allowed = true;
        db.store_config(tx_source_urls)?;
        Ok(db)
    }

    /// Create a fresh WatcherDB.
    pub fn create(path: &Path) -> Result<(), WatcherDBError> {
        let env = Arc::new(
            Environment::new()
                .set_max_dbs(10)
                .set_map_size(MAX_LMDB_FILE_SIZE)
                .open(path)?,
        );

        MetadataStore::<WatcherDbMetadataStoreSettings>::create(&env)?;

        env.create_db(Some(BLOCK_SIGNATURES_DB_NAME), DatabaseFlags::DUP_SORT)?;
        env.create_db(
            Some(VERIFICATION_REPORTS_BY_BLOCK_SIGNER_DB_NAME),
            DatabaseFlags::DUP_SORT,
        )?;
        env.create_db(
            Some(VERIFICATION_REPORTS_BY_HASH_DB_NAME),
            DatabaseFlags::empty(),
        )?;
        env.create_db(
            Some(VERIFICATION_REPORTS_POLL_QUEUE_DB_NAME),
            DatabaseFlags::DUP_SORT,
        )?;
        env.create_db(Some(LAST_SYNCED_DB_NAME), DatabaseFlags::empty())?;
        env.create_db(Some(CONFIG_DB_NAME), DatabaseFlags::DUP_SORT)?;

        BlockDataStore::create(env)?;

        Ok(())
    }

    /// Get the current set of configured URLs.
    pub fn get_config_urls(&self) -> Result<Vec<Url>, WatcherDBError> {
        let db_txn = self.env.begin_ro_txn()?;
        self.get_config_urls_with_txn(&db_txn)
    }

    /// Store BlockData for a URL at a given block index (the block index comes
    /// from the BlockData).
    pub fn add_block_data(
        &self,
        src_url: &Url,
        block_data: &BlockData,
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

        // Add.
        self.block_data_store
            .add_block_data(&mut db_txn, src_url, block_data)?;

        // Done
        db_txn.commit()?;
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
        if !self.write_allowed {
            return Err(WatcherDBError::ReadOnly);
        }

        let mut db_txn = self.env.begin_rw_txn()?;

        // Sanity test - the URL needs to be configured.
        let urls = self.get_config_urls_with_txn(&db_txn)?;
        if !urls.contains(&src_url) {
            log::trace!(self.logger, "{} not in {:?}", src_url, urls);
            return Err(WatcherDBError::NotFound);
        }

        // Store the block signature.
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

        // Add the block signer to our polling queue, unless we already have a report
        // for it.
        if !self.has_verification_report_for_signer_and_url(
            &db_txn,
            signature_data.block_signature.signer(),
            src_url,
        )? {
            log::trace!(
                self.logger,
                "Attempting to queue signer {:?} from {} for polling",
                hex::encode(signature_data.block_signature.signer().to_bytes()),
                src_url
            );

            self.queue_verification_report_poll(
                &mut db_txn,
                src_url,
                signature_data.block_signature.signer(),
            )?;
        } else {
            log::trace!(
                self.logger,
                "Not queuing signer {:?} from {} for polling - already have results",
                hex::encode(signature_data.block_signature.signer().to_bytes()),
                src_url
            );
        }

        // Done
        db_txn.commit()?;
        Ok(())
    }

    /// Get the signatures for a block.
    pub fn get_block_signatures(
        &self,
        block_index: u64,
    ) -> Result<Vec<BlockSignatureData>, WatcherDBError> {
        let db_txn = self.env.begin_ro_txn()?;
        self.get_block_signatures_impl(&db_txn, block_index)
    }

    fn get_block_signatures_impl(
        &self,
        db_txn: &impl Transaction,
        block_index: u64,
    ) -> Result<Vec<BlockSignatureData>, WatcherDBError> {
        let mut cursor = db_txn.open_ro_cursor(self.block_signatures)?;
        let key_bytes = block_index.to_be_bytes();

        log::trace!(
            self.logger,
            "Getting block signatures for {:?}",
            block_index
        );

        cursor
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
            .collect::<Result<Vec<_>, WatcherDBError>>()
    }

    /// Get the earliest timestamp for a given block.
    /// The earliest timestamp reflects the time closest to when the block
    /// passed consensus. If no timestamp is present, return u64::MAX, and a
    /// status code.
    ///
    /// Note: If there are no Signatures (and therefore no timestamps) for the
    /// given       block, the result from get_signatures will be
    /// Ok(vec![]).       A consensus validator only writes a signature for
    /// a block in which it       participated in consensus. Therefore, if
    /// the watcher is only watching       a subset of nodes, and those
    /// nodes happened to not participate in this       block, the timestamp
    /// result will be unavailable for this block. It is       also possible
    /// to be in a temporary state where there are no signatures
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

    /// Poll the timestamp from the watcher, or an error code,
    /// using retries if the watcher fell behind
    /// The block index and watcher timeout set is the time that has elapsed to
    /// indicate watcher is behind in the ingest or ledger for example
    pub fn poll_block_timestamp(&self, block_index: BlockIndex, watcher_timeout: Duration) -> u64 {
        // special case the origin block has a timestamp of u64::MAX
        if block_index == 0 {
            return u64::MAX;
        }

        // Timer that tracks how long we have had WatcherBehind error for,
        // if this exceeds watcher_timeout, we log a warning.
        let mut watcher_behind_timer = Instant::now();
        loop {
            match self.get_block_timestamp(block_index) {
                Ok((ts, res)) => match res {
                    TimestampResultCode::WatcherBehind => {
                        if watcher_behind_timer.elapsed() > watcher_timeout {
                            log::warn!(self.logger, "watcher is still behind on block index = {} after waiting {} seconds, caller will be blocked", block_index, watcher_timeout.as_secs());
                            watcher_behind_timer = Instant::now();
                        }
                        std::thread::sleep(POLL_BLOCK_TIMESTAMP_POLLING_FREQUENCY);
                    }
                    TimestampResultCode::BlockIndexOutOfBounds => {
                        log::warn!(self.logger, "block index {} was out of bounds, we should not be scanning it, we will have junk timestamps for it", block_index);
                        return u64::MAX;
                    }
                    TimestampResultCode::Unavailable => {
                        log::crit!(self.logger, "watcher configuration is wrong and timestamps will not be available with this configuration. caller is blocked at block index {}", block_index);
                        std::thread::sleep(POLL_BLOCK_TIMESTAMP_ERROR_RETRY_FREQUENCY);
                    }
                    TimestampResultCode::WatcherDatabaseError => {
                        log::crit!(self.logger, "The watcher database has an error which prevents us from getting timestamps. caller is blocked at block index {}", block_index);
                        std::thread::sleep(POLL_BLOCK_TIMESTAMP_ERROR_RETRY_FREQUENCY);
                    }
                    TimestampResultCode::TimestampFound => {
                        return ts;
                    }
                },
                Err(err) => {
                    log::error!(
                            self.logger,
                            "Could not obtain timestamp for block {} due to error {}, this may mean the watcher is not correctly configured. will retry",
                            block_index,
                            err
                        );
                    std::thread::sleep(POLL_BLOCK_TIMESTAMP_ERROR_RETRY_FREQUENCY);
                }
            };
        }
    }

    /// Get the last synced block per configured url.
    pub fn last_synced_blocks(&self) -> Result<HashMap<Url, Option<u64>>, WatcherDBError> {
        let db_txn = self.env.begin_ro_txn()?;
        self.get_url_to_last_synced(&db_txn)
    }

    /// In the case where a synced block did not have a signature, update last
    /// synced.
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
    /// Note: In the case where one watched consensus validator dies and is no
    /// longer       reporting blocks to S3, this will cause the
    /// highest_common_block to       always remain at the lowest common
    /// denominator, so in the case where the       the highest_common_block
    /// is being used to determine if the watcher is       behind, the
    /// watcher will need to be restarted with the dead node removed
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
        db_txn: &impl Transaction,
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

    /// Get BlockData for a given block index provided by a specific tx source
    /// url.
    pub fn get_block_data(
        &self,
        src_url: &Url,
        block_index: BlockIndex,
    ) -> Result<BlockData, WatcherDBError> {
        let db_txn = self.env.begin_ro_txn()?;
        self.block_data_store
            .get_block_data(&db_txn, src_url, block_index)
    }

    /// Get all known BlockDatas for a given block index, mapped by tx source
    /// url.
    pub fn get_block_data_map(
        &self,
        block_index: BlockIndex,
    ) -> Result<HashMap<Url, BlockData>, WatcherDBError> {
        let db_txn = self.env.begin_ro_txn()?;
        self.block_data_store
            .get_block_data_map(&db_txn, block_index)
    }

    /// Record a verification report for a given source URL, that is associated
    /// with a specific block signer.
    /// Additionally, record no report for an optional list of expected block
    /// signers. When going over the blockchain we are likely going to
    /// encounter a few block signers for a given src_url since every time
    /// the node restarts a new block signer key is generated. If we
    /// are back-filling the database and not polling in real time, we will only
    /// manage to get a verification report for the current signer identity.
    /// The previous ones are then lost, and
    /// we use `potential_block_signers` to mark them as such in order to stop
    /// trying to get reports for them from this particular node (identified
    /// by `src_url`).
    ///
    /// Note that it is possible for us to extract
    /// `verification_report_block_signer` out of `verification_report` but
    /// we let the caller handle that in case the report format changes over
    /// time.
    pub fn add_verification_report(
        &self,
        src_url: &Url,
        verification_report_block_signer: &Ed25519Public,
        verification_report: &VerificationReport,
        potential_block_signers: &[Ed25519Public],
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

        // Write the verification report for `verification_report_block_signer`.
        self.write_verification_report(
            &mut db_txn,
            src_url,
            verification_report_block_signer,
            Some(verification_report),
        )?;

        // Write no reports for all the other block signers we missed.
        for block_signer in potential_block_signers.iter() {
            // The verification_report_block_signer gets written together with the
            // verification_report outside of this loop.
            if block_signer == verification_report_block_signer {
                continue;
            }

            self.write_verification_report(&mut db_txn, src_url, block_signer, None)?;
        }

        // Remove all the keys we encountered from the queue - we no longer need to poll
        // for them.
        self.remove_verification_report_poll_from_queue(
            &mut db_txn,
            src_url,
            verification_report_block_signer,
        )?;
        for block_signer in potential_block_signers.iter() {
            self.remove_verification_report_poll_from_queue(&mut db_txn, src_url, block_signer)?;
        }

        // Done
        db_txn.commit()?;
        Ok(())
    }

    /// A helper for writing a single (src_url, signer) -> VerificationReport
    /// entry in the database.
    fn write_verification_report<'env>(
        &self,
        db_txn: &mut RwTransaction<'env>,
        src_url: &Url,
        signer: &Ed25519Public,
        verification_report: Option<&VerificationReport>,
    ) -> Result<(), WatcherDBError> {
        let mut key_bytes = signer.to_bytes().to_vec();
        key_bytes.extend(src_url.as_str().as_bytes());

        let value_bytes = verification_report
            .map(mc_util_serial::encode)
            .unwrap_or_else(Vec::new);

        log::trace!(
            self.logger,
            "write_verification_report: src_url:{} signer:{} report-provided:{} report-len:{}",
            src_url,
            hex::encode(signer.to_bytes()),
            verification_report.is_some(),
            value_bytes.len(),
        );

        // First, write the hash -> verification report entry.
        let hash: [u8; 32] = value_bytes.digest32::<MerlinTranscript>(b"verification_report");
        match db_txn.put(
            self.verification_reports_by_hash,
            &hash,
            &value_bytes,
            WriteFlags::NO_OVERWRITE,
        ) {
            Ok(()) => Ok(()),
            Err(lmdb::Error::KeyExist) => {
                log::trace!(
                    self.logger,
                    "write_verification_report: report hash already in db"
                );
                Ok(())
            }
            Err(err) => Err(err),
        }?;

        // Now, write the entry that points at the hash.
        match db_txn.put(
            self.verification_reports_by_signer,
            &key_bytes,
            &hash,
            WriteFlags::NO_DUP_DATA,
        ) {
            Ok(()) => Ok(()),
            Err(lmdb::Error::KeyExist) => {
                log::trace!(
                    self.logger,
                    "write_verification_report: report already associated with signer+src_url"
                );
                Ok(())
            }
            Err(err) => Err(err),
        }?;

        // Done
        Ok(())
    }

    /// Get a VerificationReport by hash.
    fn get_verification_report_by_hash(
        &self,
        db_txn: &impl Transaction,
        hash: &[u8],
    ) -> Result<Option<VerificationReport>, WatcherDBError> {
        let value_bytes = db_txn.get(self.verification_reports_by_hash, &hash)?;
        if value_bytes.is_empty() {
            Ok(None)
        } else {
            Ok(Some(mc_util_serial::decode(value_bytes)?))
        }
    }

    /// Get a verification report for a given block signer.
    /// Returns a map of tx source url to all verification reports seen for the
    /// given signer. Notes:
    /// 1) In general there should only be one report per given block signer
    /// since the key is    unique to an enclave. However, the database is
    /// structured in such a way that if    something funky is happening,
    /// and somehow different reports are seen in the wild for a
    ///    given signer, they will all get logged.
    /// 2) The VerificationReport is wrapped in an Option to indicate that at
    /// some point we tried    getting a report for the given Url, but
    /// failed since the report we got referenced a    different signer.
    /// This could happen if we're trying to get reports for old block signers
    ///    whose enclaves are no longer alive.
    pub fn get_verification_reports_for_signer(
        &self,
        block_signer: &Ed25519Public,
    ) -> Result<HashMap<Url, Vec<Option<VerificationReport>>>, WatcherDBError> {
        let db_txn = self.env.begin_ro_txn()?;
        let mut cursor = db_txn.open_ro_cursor(self.verification_reports_by_signer)?;
        let signer_key_bytes = block_signer.to_bytes().to_vec();

        log::trace!(
            self.logger,
            "Getting verification reports for signer {:?}",
            block_signer
        );

        let mut results = HashMap::default();
        for (key_bytes, value_bytes) in cursor.iter_from(&signer_key_bytes).filter_map(Result::ok) {
            // Try and get the signer key bytes and tx source url from the database key.
            // Remember that the key is the signer key, followed by the source url.
            if key_bytes.len() < signer_key_bytes.len() {
                continue;
            }

            let signer_key_bytes2 = &key_bytes[0..signer_key_bytes.len()];
            if signer_key_bytes != signer_key_bytes2 {
                // Moved to a different signer key, we're done.
                break;
            }

            let tx_source_url_bytes = &key_bytes[signer_key_bytes.len()..];
            let tx_source_url = Url::from_str(&String::from_utf8(tx_source_url_bytes.to_vec())?)?;

            // Resolve the hash into the actual report.
            let verification_report = self.get_verification_report_by_hash(&db_txn, value_bytes)?;

            // Add to hashmap
            results
                .entry(tx_source_url)
                .or_insert_with(Vec::new)
                .push(verification_report);
        }

        Ok(results)
    }

    /// Get verification reports seen for a specific block signer/URL pair.
    /// In theory there should only ever be a single report (or none) for a
    /// given block_signer+src_url pair but if something weird is going on
    /// we want to capture that, and as such multiple reports are supported.
    /// See more detailed explanation above
    /// `get_verification_reports_for_signer`.
    /// Returns an empty array if we have no record of block_signer+src_url in
    /// the database.
    pub fn get_verification_report_for_signer_and_url(
        &self,
        block_signer: &Ed25519Public,
        src_url: &Url,
    ) -> Result<Vec<Option<VerificationReport>>, WatcherDBError> {
        let db_txn = self.env.begin_ro_txn()?;

        let mut key_bytes = block_signer.to_bytes().to_vec();
        key_bytes.extend(src_url.as_str().as_bytes());

        let mut cursor = db_txn.open_ro_cursor(self.verification_reports_by_signer)?;
        let mut results = Vec::new();
        for (key_bytes2, value_bytes) in cursor.iter_dup_of(&key_bytes).filter_map(Result::ok) {
            assert_eq!(key_bytes, key_bytes2);

            let report = self.get_verification_report_by_hash(&db_txn, value_bytes)?;
            results.push(report);
        }

        Ok(results)
    }

    /// Check if a given pair of src_url/block_signer have already been polled.
    fn has_verification_report_for_signer_and_url(
        &self,
        db_txn: &impl Transaction,
        block_signer: &Ed25519Public,
        src_url: &Url,
    ) -> Result<bool, WatcherDBError> {
        let mut key_bytes = block_signer.to_bytes().to_vec();
        key_bytes.extend(src_url.as_str().as_bytes());

        match db_txn.get(self.verification_reports_by_signer, &key_bytes) {
            Ok(_value_bytes) => Ok(true),
            Err(lmdb::Error::NotFound) => Ok(false),
            Err(err) => Err(err.into()),
        }
    }

    /// Queue a tx source url for attestation verification report polling. We
    /// keep track of the expected block signer so that when we get the
    /// report we can see if we were able to confirm the block signer and
    /// associate to a report, or have to mark the block signer as having no
    /// report. That will happen if we have missed an opportunity to poll for a
    /// report and the report has changed.
    ///
    /// Note that this method is not exposed outside of this object. It is used
    /// inside `add_block_signature` to ensure all block signers get queued
    /// up automatically.
    fn queue_verification_report_poll<'env>(
        &self,
        db_txn: &mut RwTransaction<'env>,
        src_url: &Url,
        expected_block_signer: &Ed25519Public,
    ) -> Result<(), WatcherDBError> {
        if !self.write_allowed {
            return Err(WatcherDBError::ReadOnly);
        }

        // Sanity test - the URL needs to be configured.
        let urls = self.get_config_urls_with_txn(db_txn)?;
        if !urls.contains(&src_url) {
            return Err(WatcherDBError::NotFound);
        }

        let key_bytes = src_url.as_str().as_bytes();
        let value_bytes = expected_block_signer.to_bytes();

        match db_txn.put(
            self.verification_reports_poll_queue,
            &key_bytes,
            &value_bytes,
            WriteFlags::NO_DUP_DATA,
        ) {
            Ok(_) => {
                log::trace!(
                    self.logger,
                    "Added src_url:{} signer:{} to poll queue",
                    src_url,
                    hex::encode(expected_block_signer.to_bytes())
                );
                Ok(())
            }
            Err(lmdb::Error::KeyExist) => {
                log::trace!(
                    self.logger,
                    "Not adding src_url:{} signer:{} to poll queue - already queued",
                    src_url,
                    hex::encode(expected_block_signer.to_bytes())
                );
                Ok(())
            }
            Err(err) => Err(err.into()),
        }
    }

    /// Get a map of queued-for-verification-report-polling tx source urls ->
    /// encountered block signers.
    pub fn get_verification_report_poll_queue(
        &self,
    ) -> Result<HashMap<Url, Vec<Ed25519Public>>, WatcherDBError> {
        let db_txn = self.env.begin_ro_txn()?;
        let mut cursor = db_txn.open_ro_cursor(self.verification_reports_poll_queue)?;

        let mut results = HashMap::default();
        for (key_bytes, value_bytes) in cursor.iter_start().filter_map(Result::ok) {
            let url_str = String::from_utf8(key_bytes.to_vec())?;
            let url = Url::from_str(&url_str)?;

            let block_signer = Ed25519Public::try_from(value_bytes)?;

            results
                .entry(url)
                .or_insert_with(Vec::new)
                .push(block_signer);
        }
        Ok(results)
    }

    /// Remove a single entry from the verification report polling queue
    fn remove_verification_report_poll_from_queue<'env>(
        &self,
        db_txn: &mut RwTransaction<'env>,
        src_url: &Url,
        block_signer: &Ed25519Public,
    ) -> Result<(), WatcherDBError> {
        let key_bytes = src_url.as_str().as_bytes();
        let value_bytes = block_signer.to_bytes();

        match db_txn.del(
            self.verification_reports_poll_queue,
            &key_bytes,
            Some(&value_bytes),
        ) {
            Ok(()) => Ok(()),
            Err(lmdb::Error::NotFound) => Ok(()),
            Err(err) => Err(err.into()),
        }
    }

    /// Remove all the data associated with a given source url.
    pub fn remove_all_for_source_url(&self, src_url: &Url) -> Result<(), WatcherDBError> {
        if !self.write_allowed {
            return Err(WatcherDBError::ReadOnly);
        }

        let mut db_txn = self.env.begin_rw_txn()?;

        // Figure out the last synced block index for this url.
        let last_synced_map = self.get_url_to_last_synced(&db_txn)?;
        let last_synced_block_index = last_synced_map.get(src_url).unwrap_or(&None).unwrap_or(0);

        // Remove any stored block data.
        self.block_data_store.remove_all_for_source_url(
            &mut db_txn,
            src_url,
            last_synced_block_index,
        )?;

        // Remove any block signatures associated with this source URL.
        for block_index in 0..=last_synced_block_index {
            let block_signatures = self.get_block_signatures_impl(&db_txn, block_index)?;
            for block_signature in block_signatures {
                if block_signature.src_url == src_url.as_str() {
                    let key_bytes = block_index.to_be_bytes();
                    let value_bytes = encode(&block_signature);
                    db_txn.del(self.block_signatures, &key_bytes, Some(&value_bytes))?;
                }
            }
        }

        // Remove last synced.
        match db_txn.del(self.last_synced, &src_url.as_str().as_bytes(), None) {
            Ok(()) => {}
            Err(lmdb::Error::NotFound) => {}
            Err(err) => {
                return Err(err.into());
            }
        };

        // Remove verification reports.
        let signer_key_size = <Ed25519Public as ReprBytes>::Size::USIZE;
        let mut cursor = db_txn.open_rw_cursor(self.verification_reports_by_signer)?;
        for (key_bytes, _value_bytes) in cursor.iter_start().filter_map(Result::ok) {
            // The key format is 32 bytes signer public key followed by tx source url.
            if key_bytes.len() < signer_key_size {
                continue;
            }

            let tx_source_url_bytes = &key_bytes[signer_key_size..];
            let tx_source_url = Url::from_str(&String::from_utf8(tx_source_url_bytes.to_vec())?)?;
            if &tx_source_url == src_url {
                cursor.del(WriteFlags::empty())?;
            }
        }
        drop(cursor);

        // Done
        db_txn.commit()?;
        Ok(())
    }
}

/// Open an existing WatcherDB or create a new one in read-write mode.
pub fn create_or_open_rw_watcher_db(
    watcher_db_path: &Path,
    src_urls: &[Url],
    logger: Logger,
) -> Result<WatcherDB, WatcherDBError> {
    // Create the path if it does not exist.
    if !watcher_db_path.exists() {
        std::fs::create_dir_all(watcher_db_path)?;
    }

    // Attempt to open the WatcherDB and see if it has anything in it.
    if let Ok(watcher_db) = WatcherDB::open_rw(watcher_db_path, src_urls, logger.clone()) {
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
    WatcherDB::create(watcher_db_path)?;
    WatcherDB::open_rw(watcher_db_path, src_urls, logger)
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use mc_account_keys::AccountKey;
    use mc_attest_core::VerificationSignature;
    use mc_common::logger::{test_with_logger, Logger};
    use mc_crypto_keys::Ed25519Pair;
    use mc_transaction_core::{Block, BlockContents};
    use mc_transaction_core_test_utils::get_blocks;
    use mc_util_from_random::FromRandom;
    use mc_util_test_helper::run_with_one_seed;
    use rand_core::SeedableRng;
    use rand_hc::Hc128Rng;
    use std::iter::FromIterator;
    use tempdir::TempDir;

    pub fn setup_watcher_db(src_urls: &[Url], logger: Logger) -> WatcherDB {
        let db_tmp = TempDir::new("wallet_db").expect("Could not make tempdir for wallet db");
        WatcherDB::create(db_tmp.path()).unwrap();
        WatcherDB::open_rw(db_tmp.path(), src_urls, logger).unwrap()
    }

    pub fn setup_blocks() -> Vec<(Block, BlockContents)> {
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

    // Highest synced block should return the minimum highest synced block for all
    // URLs
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

    // Watcher should return timestamps based on watched nodes' signature.signed_at
    // values
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

    // Storing and fetching of verification reports should work.
    #[test_with_logger]
    fn test_verification_report_insert_and_get(logger: Logger) {
        run_with_one_seed(|mut rng| {
            let url1 = Url::parse("http://www.my_url1.com").unwrap();
            let url2 = Url::parse("http://www.my_url2.com").unwrap();
            let url3 = Url::parse("http://www.my_url3.com").unwrap();
            let urls = vec![url1.clone(), url2.clone()];

            let signing_key_a = Ed25519Pair::from_random(&mut rng).public_key();
            let signing_key_b = Ed25519Pair::from_random(&mut rng).public_key();
            let signing_key_c = Ed25519Pair::from_random(&mut rng).public_key();
            let signing_key_d = Ed25519Pair::from_random(&mut rng).public_key();

            let verification_report_a = VerificationReport {
                sig: VerificationSignature::from(vec![1; 32]),
                chain: vec![vec![2; 16], vec![3; 32]],
                http_body: "test body a".to_owned(),
            };

            let verification_report_b = VerificationReport {
                sig: VerificationSignature::from(vec![10; 32]),
                chain: vec![vec![20; 16], vec![30; 32]],
                http_body: "test body b".to_owned(),
            };

            {
                let watcher_db = setup_watcher_db(&urls, logger.clone());

                // Add a verification report for signing_key_a, and also include signing_key_b.
                // Result should be report is assocaited with signing_key_a and None is
                // associated with signing_key_b. Nothing is associated with
                // signing_key_c.
                for _ in 0..5 {
                    watcher_db
                        .add_verification_report(
                            &url1,
                            &signing_key_a,
                            &verification_report_a,
                            &[signing_key_b],
                        )
                        .unwrap();

                    assert_eq!(
                        watcher_db
                            .get_verification_reports_for_signer(&signing_key_a)
                            .unwrap(),
                        HashMap::from_iter(vec![(
                            url1.clone(),
                            vec![Some(verification_report_a.clone())]
                        )])
                    );

                    assert_eq!(
                        watcher_db
                            .get_verification_reports_for_signer(&signing_key_b)
                            .unwrap(),
                        HashMap::from_iter(vec![(url1.clone(), vec![None])])
                    );

                    assert_eq!(
                        watcher_db
                            .get_verification_reports_for_signer(&signing_key_c)
                            .unwrap(),
                        HashMap::from_iter(vec![])
                    );

                    assert_eq!(
                        watcher_db
                            .get_verification_report_for_signer_and_url(&signing_key_a, &url1)
                            .unwrap(),
                        vec![Some(verification_report_a.clone())],
                    );

                    assert_eq!(
                        watcher_db
                            .get_verification_report_for_signer_and_url(&signing_key_a, &url2)
                            .unwrap(),
                        vec![],
                    );

                    assert_eq!(
                        watcher_db
                            .get_verification_report_for_signer_and_url(&signing_key_b, &url1)
                            .unwrap(),
                        vec![None],
                    );

                    assert_eq!(
                        watcher_db
                            .get_verification_report_for_signer_and_url(&signing_key_b, &url2)
                            .unwrap(),
                        vec![],
                    );

                    assert_eq!(
                        watcher_db
                            .get_verification_report_for_signer_and_url(&signing_key_c, &url1)
                            .unwrap(),
                        vec![],
                    );
                }

                // Add a second verification report for signing_key_a and test that we can fetch
                // it.
                for _ in 0..5 {
                    watcher_db
                        .add_verification_report(
                            &url1,
                            &signing_key_a,
                            &verification_report_b,
                            &[signing_key_b],
                        )
                        .unwrap();

                    assert_eq!(
                        watcher_db
                            .get_verification_reports_for_signer(&signing_key_a)
                            .unwrap(),
                        HashMap::from_iter(vec![(
                            url1.clone(),
                            vec![
                                Some(verification_report_a.clone()),
                                Some(verification_report_b.clone())
                            ]
                        )])
                    );

                    assert_eq!(
                        watcher_db
                            .get_verification_reports_for_signer(&signing_key_b)
                            .unwrap(),
                        HashMap::from_iter(vec![(url1.clone(), vec![None])])
                    );

                    assert_eq!(
                        watcher_db
                            .get_verification_reports_for_signer(&signing_key_c)
                            .unwrap(),
                        HashMap::from_iter(vec![])
                    );

                    assert_eq!(
                        watcher_db
                            .get_verification_report_for_signer_and_url(&signing_key_a, &url1)
                            .unwrap(),
                        vec![
                            Some(verification_report_a.clone()),
                            Some(verification_report_b.clone())
                        ]
                    );

                    assert_eq!(
                        watcher_db
                            .get_verification_report_for_signer_and_url(&signing_key_b, &url1)
                            .unwrap(),
                        vec![None]
                    );

                    assert_eq!(
                        watcher_db
                            .get_verification_report_for_signer_and_url(&signing_key_c, &url1)
                            .unwrap(),
                        vec![]
                    );

                    assert_eq!(
                        watcher_db
                            .get_verification_report_for_signer_and_url(&signing_key_c, &url2)
                            .unwrap(),
                        vec![]
                    );
                }
            }

            // While this should never happen in the real world, test that the database
            // supports adding the same verification report to two different
            // URLs.
            {
                let watcher_db = setup_watcher_db(&urls, logger.clone());

                // This is done in a loop since repeated executions should not result in
                // different results
                for _ in 0..5 {
                    watcher_db
                        .add_verification_report(
                            &url1,
                            &signing_key_a,
                            &verification_report_a,
                            &[signing_key_b],
                        )
                        .unwrap();

                    watcher_db
                        .add_verification_report(
                            &url2,
                            &signing_key_a,
                            &verification_report_a,
                            &[signing_key_b],
                        )
                        .unwrap();

                    assert_eq!(
                        watcher_db
                            .get_verification_reports_for_signer(&signing_key_a)
                            .unwrap(),
                        HashMap::from_iter(vec![
                            (url1.clone(), vec![Some(verification_report_a.clone())]),
                            (url2.clone(), vec![Some(verification_report_a.clone())]),
                        ])
                    );

                    assert_eq!(
                        watcher_db
                            .get_verification_reports_for_signer(&signing_key_b)
                            .unwrap(),
                        HashMap::from_iter(vec![
                            (url1.clone(), vec![None]),
                            (url2.clone(), vec![None])
                        ])
                    );

                    assert_eq!(
                        watcher_db
                            .get_verification_reports_for_signer(&signing_key_c)
                            .unwrap(),
                        HashMap::from_iter(vec![])
                    );

                    assert_eq!(
                        watcher_db
                            .get_verification_report_for_signer_and_url(&signing_key_a, &url1)
                            .unwrap(),
                        vec![Some(verification_report_a.clone())]
                    );

                    assert_eq!(
                        watcher_db
                            .get_verification_report_for_signer_and_url(&signing_key_a, &url2)
                            .unwrap(),
                        vec![Some(verification_report_a.clone())]
                    );

                    assert_eq!(
                        watcher_db
                            .get_verification_report_for_signer_and_url(&signing_key_a, &url3)
                            .unwrap(),
                        vec![]
                    );
                }
            }

            // Add a None verification report and then add an actual verification report to
            // some key.
            {
                let watcher_db = setup_watcher_db(&urls, logger.clone());

                for _ in 0..5 {
                    // Adds None to signing_key_b
                    watcher_db
                        .add_verification_report(
                            &url1,
                            &signing_key_a,
                            &verification_report_a,
                            &[signing_key_b],
                        )
                        .unwrap();

                    // Add verification_report_b to signing_key_b
                    watcher_db
                        .add_verification_report(
                            &url1,
                            &signing_key_b,
                            &verification_report_b,
                            &[signing_key_c],
                        )
                        .unwrap();

                    assert_eq!(
                        watcher_db
                            .get_verification_reports_for_signer(&signing_key_a)
                            .unwrap(),
                        HashMap::from_iter(vec![(
                            url1.clone(),
                            vec![Some(verification_report_a.clone())]
                        ),])
                    );

                    assert_eq!(
                        watcher_db
                            .get_verification_reports_for_signer(&signing_key_b)
                            .unwrap(),
                        HashMap::from_iter(vec![(
                            url1.clone(),
                            vec![Some(verification_report_b.clone()), None]
                        ),])
                    );

                    assert_eq!(
                        watcher_db
                            .get_verification_reports_for_signer(&signing_key_c)
                            .unwrap(),
                        HashMap::from_iter(vec![(url1.clone(), vec![None])])
                    );

                    assert_eq!(
                        watcher_db
                            .get_verification_reports_for_signer(&signing_key_d)
                            .unwrap(),
                        HashMap::from_iter(vec![])
                    );
                }
            }
        })
    }

    // Verification report polling queue should behave as expected.
    #[test_with_logger]
    fn test_verification_report_poll_queue(logger: Logger) {
        run_with_one_seed(|mut rng| {
            let url1 = Url::parse("http://www.my_url1.com").unwrap();
            let url2 = Url::parse("http://www.my_url2.com").unwrap();
            let url3 = Url::parse("http://www.my_url3.com").unwrap();
            let urls = vec![url1.clone(), url2.clone(), url3.clone()];

            let verification_report_a = VerificationReport {
                sig: VerificationSignature::from(vec![1; 32]),
                chain: vec![vec![2; 16], vec![3; 32]],
                http_body: "test body a".to_owned(),
            };

            let blocks = setup_blocks();
            let signing_key_a = Ed25519Pair::from_random(&mut rng);
            let signing_key_b = Ed25519Pair::from_random(&mut rng);
            let signing_key_c = Ed25519Pair::from_random(&mut rng);
            let filename = String::from("00/00");

            let watcher_db = setup_watcher_db(&urls, logger.clone());

            // Queue starts empty.
            assert_eq!(
                watcher_db.get_verification_report_poll_queue().unwrap(),
                HashMap::default()
            );

            // Add a block signature, the signing key should make it into the queue.
            let signed_block_a1 =
                BlockSignature::from_block_and_keypair(&blocks[0].0, &signing_key_a).unwrap();
            watcher_db
                .add_block_signature(&url1, 1, signed_block_a1, filename.clone())
                .unwrap();

            // Repeated calls should all behave the same.
            for _ in 0..5 {
                assert_eq!(
                    watcher_db.get_verification_report_poll_queue().unwrap(),
                    HashMap::from_iter(vec![(url1.clone(), vec![signing_key_a.public_key()])])
                );
            }

            // Adding another block with the same signing key should not affect the queue.
            let signed_block_a2 =
                BlockSignature::from_block_and_keypair(&blocks[1].0, &signing_key_a).unwrap();
            watcher_db
                .add_block_signature(&url1, 2, signed_block_a2, filename.clone())
                .unwrap();

            for _ in 0..5 {
                assert_eq!(
                    watcher_db.get_verification_report_poll_queue().unwrap(),
                    HashMap::from_iter(vec![(url1.clone(), vec![signing_key_a.public_key()])])
                );
            }

            // Adding a block with a different key should show up in the queue.
            let signed_block_b1 =
                BlockSignature::from_block_and_keypair(&blocks[0].0, &signing_key_b).unwrap();
            watcher_db
                .add_block_signature(&url1, 1, signed_block_b1.clone(), filename.clone())
                .unwrap();

            for _ in 0..5 {
                assert_eq!(
                    watcher_db.get_verification_report_poll_queue().unwrap(),
                    HashMap::from_iter(vec![(
                        url1.clone(),
                        vec![signing_key_b.public_key(), signing_key_a.public_key()]
                    )])
                );
            }

            // Adding a block with the same signing key but a different url should make it
            // into the queue.
            watcher_db
                .add_block_signature(&url2, 1, signed_block_b1, filename.clone())
                .unwrap();

            for _ in 0..5 {
                assert_eq!(
                    watcher_db.get_verification_report_poll_queue().unwrap(),
                    HashMap::from_iter(vec![
                        (
                            url1.clone(),
                            vec![signing_key_b.public_key(), signing_key_a.public_key()]
                        ),
                        (url2.clone(), vec![signing_key_b.public_key()]),
                    ])
                );
            }

            // Adding a verification report for some key that is not in the queue should not
            // affect things.
            watcher_db
                .add_verification_report(
                    &url1,
                    &signing_key_c.public_key(),
                    &verification_report_a,
                    &[],
                )
                .unwrap();

            assert_eq!(
                watcher_db.get_verification_report_poll_queue().unwrap(),
                HashMap::from_iter(vec![
                    (
                        url1.clone(),
                        vec![signing_key_b.public_key(), signing_key_a.public_key()]
                    ),
                    (url2.clone(), vec![signing_key_b.public_key()]),
                ])
            );

            // Adding a verification report that references one of the keys in the queue
            // should cause it to get removed.
            watcher_db
                .add_verification_report(
                    &url2,
                    &signing_key_b.public_key(),
                    &verification_report_a,
                    &[],
                )
                .unwrap();

            assert_eq!(
                watcher_db.get_verification_report_poll_queue().unwrap(),
                HashMap::from_iter(vec![(
                    url1.clone(),
                    vec![signing_key_b.public_key(), signing_key_a.public_key()]
                ),])
            );

            // Adding a block signature for a key that already has a verification report
            // should not affect the queue.
            let signed_block_b2 =
                BlockSignature::from_block_and_keypair(&blocks[1].0, &signing_key_b).unwrap();
            watcher_db
                .add_block_signature(&url2, 2, signed_block_b2.clone(), filename.clone())
                .unwrap();

            assert_eq!(
                watcher_db.get_verification_report_poll_queue().unwrap(),
                HashMap::from_iter(vec![(
                    url1.clone(),
                    vec![signing_key_b.public_key(), signing_key_a.public_key()]
                ),])
            );

            // Unless it is added to a url we have not encountered before.
            watcher_db
                .add_block_signature(&url3, 2, signed_block_b2, filename.clone())
                .unwrap();

            assert_eq!(
                watcher_db.get_verification_report_poll_queue().unwrap(),
                HashMap::from_iter(vec![
                    (
                        url1.clone(),
                        vec![signing_key_b.public_key(), signing_key_a.public_key()]
                    ),
                    (url3.clone(), vec![signing_key_b.public_key()]),
                ])
            );

            // Referencing signing_key_a and signing_key_b for url1 will cause them to be
            // removed from the queue but only when the correct url is used.
            watcher_db
                .add_verification_report(
                    &url2,
                    &signing_key_b.public_key(),
                    &verification_report_a,
                    &[signing_key_a.public_key()],
                )
                .unwrap();

            assert_eq!(
                watcher_db.get_verification_report_poll_queue().unwrap(),
                HashMap::from_iter(vec![
                    (
                        url1.clone(),
                        vec![signing_key_b.public_key(), signing_key_a.public_key()]
                    ),
                    (url3.clone(), vec![signing_key_b.public_key()]),
                ])
            );

            watcher_db
                .add_verification_report(
                    &url1,
                    &signing_key_b.public_key(),
                    &verification_report_a,
                    &[signing_key_a.public_key()],
                )
                .unwrap();

            assert_eq!(
                watcher_db.get_verification_report_poll_queue().unwrap(),
                HashMap::from_iter(vec![(url3.clone(), vec![signing_key_b.public_key()]),])
            );
        })
    }

    // Verification report polling queue should behave as expected.
    #[test_with_logger]
    fn test_remove_all_for_source_url(logger: Logger) {
        run_with_one_seed(|mut rng| {
            let url1 = Url::parse("http://www.my_url1.com").unwrap();
            let url2 = Url::parse("http://www.my_url2.com").unwrap();
            let urls = vec![url1.clone(), url2.clone()];

            let verification_report_a = VerificationReport {
                sig: VerificationSignature::from(vec![1; 32]),
                chain: vec![vec![2; 16], vec![3; 32]],
                http_body: "test body a".to_owned(),
            };

            let blocks = setup_blocks();
            let filename = String::from("00/00");

            let block_datas = blocks
                .iter()
                .map(|(block, contents)| {
                    BlockData::new(
                        block.clone(),
                        contents.clone(),
                        Some(
                            BlockSignature::from_block_and_keypair(
                                block,
                                &Ed25519Pair::from_random(&mut rng),
                            )
                            .unwrap(),
                        ),
                    )
                })
                .collect::<Vec<_>>();

            let watcher_db = setup_watcher_db(&urls, logger.clone());

            // Removing a URL that has no data should work.
            watcher_db.remove_all_for_source_url(&url1).unwrap();

            // Add data for url1 and url2.
            for block_data in block_datas.iter() {
                watcher_db.add_block_data(&url1, block_data).unwrap();
                watcher_db
                    .add_block_signature(
                        &url1,
                        block_data.block().index,
                        block_data.signature().clone().unwrap(),
                        filename.clone(),
                    )
                    .unwrap();

                watcher_db.add_block_data(&url2, block_data).unwrap();
                watcher_db
                    .add_block_signature(
                        &url2,
                        block_data.block().index,
                        block_data.signature().clone().unwrap(),
                        filename.clone(),
                    )
                    .unwrap();

                watcher_db
                    .add_verification_report(
                        &url1,
                        block_data.signature().clone().unwrap().signer(),
                        &verification_report_a,
                        &[],
                    )
                    .unwrap();

                watcher_db
                    .add_verification_report(
                        &url2,
                        block_data.signature().clone().unwrap().signer(),
                        &verification_report_a,
                        &[],
                    )
                    .unwrap();
            }

            // Both should be in the database.
            for block_data in block_datas.iter() {
                let block_sigs = watcher_db
                    .get_block_signatures(block_data.block().index)
                    .unwrap();
                assert_eq!(
                    block_sigs,
                    vec![
                        BlockSignatureData {
                            src_url: url1.as_str().to_string(),
                            archive_filename: filename.clone(),
                            block_signature: block_data.signature().clone().unwrap(),
                        },
                        BlockSignatureData {
                            src_url: url2.as_str().to_string(),
                            archive_filename: filename.clone(),
                            block_signature: block_data.signature().clone().unwrap(),
                        }
                    ]
                );

                let verification_reports = watcher_db
                    .get_verification_reports_for_signer(
                        block_data.signature().clone().unwrap().signer(),
                    )
                    .unwrap();
                assert_eq!(
                    verification_reports,
                    HashMap::from_iter(vec![
                        (url1.clone(), vec![Some(verification_report_a.clone())]),
                        (url2.clone(), vec![Some(verification_report_a.clone())]),
                    ])
                );
            }

            let last_synced = watcher_db.last_synced_blocks().unwrap();
            assert_eq!(
                last_synced,
                HashMap::from_iter(vec![
                    (
                        url1.clone(),
                        Some(block_datas.last().unwrap().block().index)
                    ),
                    (
                        url2.clone(),
                        Some(block_datas.last().unwrap().block().index)
                    ),
                ])
            );

            // Remove url1 and ensure only url2 remains in the database.
            watcher_db.remove_all_for_source_url(&url1).unwrap();

            for block_data in block_datas.iter() {
                let block_sigs = watcher_db
                    .get_block_signatures(block_data.block().index)
                    .unwrap();
                assert_eq!(
                    block_sigs,
                    vec![BlockSignatureData {
                        src_url: url2.as_str().to_string(),
                        archive_filename: filename.clone(),
                        block_signature: block_data.signature().clone().unwrap(),
                    }]
                );

                let verification_reports = watcher_db
                    .get_verification_reports_for_signer(
                        block_data.signature().clone().unwrap().signer(),
                    )
                    .unwrap();
                assert_eq!(
                    verification_reports,
                    HashMap::from_iter(vec![(
                        url2.clone(),
                        vec![Some(verification_report_a.clone())]
                    ),])
                );
            }

            let last_synced = watcher_db.last_synced_blocks().unwrap();
            assert_eq!(
                last_synced,
                HashMap::from_iter(vec![
                    (url1.clone(), None),
                    (
                        url2.clone(),
                        Some(block_datas.last().unwrap().block().index)
                    ),
                ])
            );
        })
    }
}
