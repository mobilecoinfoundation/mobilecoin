// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Data access abstraction for Gnosis Safe transactions stored in the auditor database.

use lmdb::{Database, Environment, DatabaseFlags, RwTransaction, WriteFlags, Transaction};
//use crate::gnosis::error::Error as GnosisError;
use crate::error::Error;
use crate::gnosis::fetcher::{GnosisSafeTransaction, EthTxHash};
use mc_util_serial::{encode, decode, Message};

/// LMDB database names.
pub const HASH_TO_SAFE_TX_DB_NAME: &str = "gnosis_store:hash_to_safe_tx";

#[derive(Clone, Message)]
struct StoredGnosisSafeTransaction {
    #[prost(string, tag = "1")]
    pub tx_json: String,
}

#[derive(Clone)]
pub struct GnosisSafeStore {
    /// [EthTxHash] -> [StoredGnosisSafeTransaction]
    hash_to_safe_tx: Database,
}

impl GnosisSafeStore {
    /// Open an existing [GnosisSafeStore].
    pub fn new(env: &Environment) -> Result<Self, Error> {
        let hash_to_safe_tx = env.open_db(Some(HASH_TO_SAFE_TX_DB_NAME))?;

        Ok(Self { hash_to_safe_tx })
    }

    /// Create a fresh [GnosisSafeStore].
    pub fn create(env: &Environment) -> Result<(), Error> {
        env.create_db(Some(HASH_TO_SAFE_TX_DB_NAME), DatabaseFlags::empty())?;
        Ok(())
    }

    /// Store a single safe transaction.
    pub fn write_safe_tx(&self, safe_tx: &GnosisSafeTransaction, db_txn: &mut RwTransaction) -> Result<(), Error> {
        let tx_hash = safe_tx.tx_hash()?;
        db_txn.put(self.hash_to_safe_tx, &tx_hash, &safe_tx.to_json_string(), WriteFlags::NO_OVERWRITE)?;
        Ok(())
    }

    /// Get a safe transaction by hash.
    pub fn get_safe_tx_by_hash(&self, tx_hash: &EthTxHash, db_txn: &impl Transaction) -> Result<GnosisSafeTransaction, Error> {
        let tx_json = db_txn.get(self.hash_to_safe_tx, &tx_hash)?;
        let tx = GnosisSafeTransaction::from_json_bytes(&tx_json)?;
        Ok(tx)
    }
}