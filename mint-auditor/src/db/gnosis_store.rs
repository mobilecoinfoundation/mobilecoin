// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Data access abstraction for Gnosis Safe transactions stored in the auditor database.

use lmdb::{Database, Environment, DatabaseFlags, RwTransaction, WriteFlags, Transaction};
//use crate::gnosis::error::Error as GnosisError;
use crate::error::Error;
use crate::gnosis::fetcher::{GnosisSafeTransaction, EthTxHash};
use mc_util_serial::{encode, decode, Message};
use mc_common::logger::{Logger, log};

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

    /// Logger.
    logger: Logger,
}

impl GnosisSafeStore {
    /// Open an existing [GnosisSafeStore].
    pub fn new(env: &Environment, logger: Logger) -> Result<Self, Error> {
        let hash_to_safe_tx = env.open_db(Some(HASH_TO_SAFE_TX_DB_NAME))?;

        Ok(Self { hash_to_safe_tx, logger })
    }

    /// Create a fresh [GnosisSafeStore].
    pub fn create(env: &Environment) -> Result<(), Error> {
        env.create_db(Some(HASH_TO_SAFE_TX_DB_NAME), DatabaseFlags::empty())?;
        Ok(())
    }

    /// Store safe transactions.
    pub fn write_safe_txs(&self, safe_txs: &[GnosisSafeTransaction], db_txn: &mut RwTransaction) -> Result<(), Error> {
        for safe_tx in safe_txs {
            let tx_hash = safe_tx.tx_hash()?;
            let json_tx = safe_tx.to_json_string();

            match db_txn.put(self.hash_to_safe_tx, &tx_hash, &json_tx, WriteFlags::NO_OVERWRITE) {
                Ok(_) => {
                },
                Err(lmdb::Error::KeyExist) => {
                    let existing_tx = db_txn.get(self.hash_to_safe_tx, &tx_hash)?;
                    if existing_tx != json_tx.as_bytes() {
                        log::error!(self.logger, "Encountered duplicate gnosis tx hash {} and data mismatch", tx_hash);
                        log::error!(self.logger, "Existing tx: {}", String::from_utf8_lossy(&existing_tx));
                        log::error!(self.logger, "New tx: {}", json_tx);
                        return Err(Error::TxHashConflict(tx_hash));
                    }
                    log::trace!(self.logger, "Encountered duplicate gnosis tx hash {} but data is identical", tx_hash);
                }
                Err(err) => return Err(err.into()),
            }
        }
        Ok(())
    }

    /// Get a safe transaction by hash.
    pub fn get_safe_tx_by_hash(&self, tx_hash: &EthTxHash, db_txn: &impl Transaction) -> Result<GnosisSafeTransaction, Error> {
        let tx_json = db_txn.get(self.hash_to_safe_tx, &tx_hash)?;
        let tx = GnosisSafeTransaction::from_json_bytes(&tx_json)?;
        Ok(tx)
    }
}