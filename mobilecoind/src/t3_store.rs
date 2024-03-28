// Copyright (c) 2018-2024 The MobileCoin Foundation

//! Database storage for queued data we want to sync to T3.

use crate::{
    error::Error,
    monitor_store::{MonitorId, MonitorStore},
    utxo_store::UnspentTxOut,
};
use hex_fmt::HexFmt;
use lmdb::{Cursor, Database, DatabaseFlags, Environment, RwTransaction, Transaction, WriteFlags};
use mc_account_keys::ShortAddressHash;
use mc_common::logger::{log, Logger};
use mc_t3_api::TransparentTransaction;
use mc_transaction_core::MemoPayload;
use mc_transaction_extra::MemoType;
use protobuf::Message;
use std::sync::Arc;

// LMDB Database Names
pub const QUEUES_DB_NAME: &str = "mobilecoind_db:t3_store:queues";
pub const COUNTERS_DB_NAME: &str = "mobilecoind_db:t3_store:counters";
pub const INDEX_TO_TRANSPARENT_TX_DB_NAME: &str = "mobilecoind_db:t3_store:index_to_transparent_tx";

// Key we use for storing a queue of transparent transactions we still need to
// submit to T3.
// Each entry here is a u64 index (as big endian bytes) mapping to a serialized
// TransparentTransaction.
pub const TRANSPARENT_TXS_QUEUE_KEY: &str = "transparent_txs_queue";

// Key we use for storing how many transparent transactions we have added to the
// queue. This gives us a monotonically increasing index for each transaction.
// We need that since LMDB will not allow us to store multiple large
// (TransparentTransactions) objects in a single key, so instead we store them
// in a separate database (INDEX_TO_TRANSPARENT_TX_DB_NAME) and use this index
// to reference them.
pub const TRANSPARENT_TXS_COUNTER_KEY: &str = "transparent_txs_counter";

/// The T3 database.
#[derive(Clone)]
pub struct T3Store {
    /// Retain a reference to the Environment so the Database handles are valid.
    _env: Arc<Environment>,

    /// Right now this contains a single key: `TRANSPARENT_TXS_QUEUE_KEY` which
    /// contains a list of txo global indices we still need to submit to T3.
    /// The actual data is stored inside the index_to_transparent_tx
    /// database.
    queues: Database,

    /// Database for keeping track of counters.
    /// Right now this is only used for TRANSPARENT_TXS_COUNTER_KEY.
    counters: Database,

    /// Database that maps an index to a `TransparentTransaction`
    /// This is used to store the txo data for the txos we still need to submit
    /// to T3.
    index_to_transparent_tx: Database,

    /// Logger.
    logger: Logger,
}

impl T3Store {
    pub fn new(env: Arc<Environment>, logger: Logger) -> Result<Self, Error> {
        let queues = env.create_db(
            Some(QUEUES_DB_NAME),
            // DUP_SORT is needed here since we are storing multiple UtxoIds per SubaddressId.
            // Note that values in a DUP_SORT db must be < 511 bytes!
            DatabaseFlags::DUP_SORT | DatabaseFlags::DUP_FIXED,
        )?;

        let counters = env.create_db(Some(COUNTERS_DB_NAME), DatabaseFlags::empty())?;

        let index_to_transparent_tx = env.create_db(
            Some(INDEX_TO_TRANSPARENT_TX_DB_NAME),
            DatabaseFlags::empty(), // here we can store larger values
        )?;

        Ok(Self {
            _env: env,
            queues,
            counters,
            index_to_transparent_tx,
            logger,
        })
    }

    pub fn process_utxo(
        &self,
        db_txn: &mut RwTransaction<'_>,
        monitor_id: &MonitorId,
        monitor_store: &MonitorStore,
        utxo: &UnspentTxOut,
    ) -> Result<(), Error> {
        if utxo.memo_payload.is_empty() {
            return Ok(());
        };

        let monitor_data = monitor_store.get_data(db_txn, monitor_id)?;
        let Ok(memo_payload) = MemoPayload::try_from(&utxo.memo_payload[..]) else {
            return Ok(());
        };
        let Ok(memo_type) = MemoType::try_from(&memo_payload) else {
            return Ok(());
        };

        let our_short_address_hash =
            ShortAddressHash::from(&monitor_data.account_key.subaddress(utxo.subaddress_index));

        let (sender_address_hash, recipient_address_hash) = match memo_type {
            MemoType::AuthenticatedSender(contents) => {
                (contents.sender_address_hash(), our_short_address_hash)
            }

            MemoType::AuthenticatedSenderWithPaymentRequestId(contents) => {
                (contents.sender_address_hash(), our_short_address_hash)
            }

            MemoType::AuthenticatedSenderWithPaymentIntentId(contents) => {
                (contents.sender_address_hash(), our_short_address_hash)
            }

            MemoType::Destination(contents) => {
                (our_short_address_hash, *contents.get_address_hash())
            }

            MemoType::DestinationWithPaymentRequestId(contents) => {
                (our_short_address_hash, *contents.get_address_hash())
            }

            MemoType::DestinationWithPaymentIntentId(contents) => {
                (our_short_address_hash, *contents.get_address_hash())
            }

            _ => {
                return Ok(());
            }
        };

        let public_key = mc_t3_api::external::CompressedRistretto {
            data: utxo.tx_out.public_key.as_bytes().to_vec(),
            ..Default::default()
        };

        let reported_direction = if sender_address_hash == our_short_address_hash {
            mc_t3_api::ReportedDirection::REPORTED_DIRECTION_SEND
        } else {
            mc_t3_api::ReportedDirection::REPORTED_DIRECTION_RECEIVE
        };

        let ttx = TransparentTransaction {
            sender_address_hash: sender_address_hash.as_ref().to_vec(),
            recipient_address_hash: recipient_address_hash.as_ref().to_vec(),
            token_id: utxo.token_id,
            amount: utxo.value,
            public_key: Some(public_key).into(),
            public_key_hex: format!("{}", HexFmt(utxo.tx_out.public_key.as_bytes())),
            reported_direction,
            ..Default::default()
        };

        self.append_transparent_tx(db_txn, &ttx)?;

        log::debug!(
            self.logger,
            "Added transparent transaction to t3 queue: {:?}",
            ttx
        );

        Ok(())
    }

    /// Append a transparent transaction to the queue of transactions we want to
    /// submit to T3.
    pub fn append_transparent_tx(
        &self,
        db_txn: &mut RwTransaction<'_>,
        tx: &TransparentTransaction,
    ) -> Result<(), Error> {
        let index = self.get_transparent_tx_counter(db_txn)?;
        let index_bytes = index.to_be_bytes();
        let tx_bytes = tx.write_to_bytes()?;

        db_txn.put(
            self.index_to_transparent_tx,
            &index_bytes,
            &tx_bytes,
            WriteFlags::NO_OVERWRITE,
        )?;

        db_txn.put(
            self.queues,
            &TRANSPARENT_TXS_QUEUE_KEY,
            &index_bytes,
            WriteFlags::NO_DUP_DATA,
        )?;

        db_txn.put(
            self.counters,
            &TRANSPARENT_TXS_COUNTER_KEY,
            &(index + 1).to_be_bytes(),
            WriteFlags::empty(),
        )?;

        Ok(())
    }

    /// Get the next transaction to submit to T3 (or None if the queue is
    /// empty). Returns both the transparent transaction and its index (so
    /// it can later be removed by the index).
    pub fn dequeue_transparent_tx(
        &self,
        db_txn: &impl Transaction,
    ) -> Result<Option<(u64, TransparentTransaction)>, Error> {
        let mut cursor = db_txn.open_ro_cursor(self.queues)?;

        let Some(first_index_result) = cursor.iter_dup_of(&TRANSPARENT_TXS_QUEUE_KEY).next() else {
            return Ok(None);
        };
        let (_key, first_index_bytes) = first_index_result?;
        let first_index = u64::from_be_bytes(
            first_index_bytes
                .try_into()
                .map_err(|_| Error::ValueDeserialization)?,
        );

        let transparent_tx_bytes = db_txn.get(self.index_to_transparent_tx, &first_index_bytes)?;

        Ok(Some((
            first_index,
            TransparentTransaction::parse_from_bytes(&transparent_tx_bytes)?,
        )))
    }

    /// Remove a transaction from the queue of transparent txs.
    pub fn remove_transparent_tx(
        &self,
        db_txn: &mut RwTransaction<'_>,
        index: u64,
    ) -> Result<(), Error> {
        let index_bytes = index.to_be_bytes();

        // Remove the index -> TransparentTx mapping.
        db_txn.del(self.index_to_transparent_tx, &index_bytes, None)?;

        // Remove the index from the queue.
        db_txn.del(self.queues, &TRANSPARENT_TXS_QUEUE_KEY, Some(&index_bytes))?;

        Ok(())
    }

    fn get_transparent_tx_counter(&self, db_txn: &impl Transaction) -> Result<u64, Error> {
        match db_txn.get(self.counters, &TRANSPARENT_TXS_COUNTER_KEY) {
            Ok(bytes) => {
                let counter =
                    u64::from_be_bytes(bytes.try_into().map_err(|_| Error::ValueDeserialization)?);
                Ok(counter)
            }
            Err(lmdb::Error::NotFound) => Ok(0),
            Err(e) => Err(e.into()),
        }
    }
}

#[cfg(test)]
mod test {
    use std::assert_matches::assert_matches;

    use super::*;
    use crate::test_utils::{get_test_databases, get_test_monitor_data_and_id, BlockVersion};
    use mc_common::{
        logger::{test_with_logger, Logger},
        HashSet,
    };
    use mc_ledger_db::{Ledger, LedgerDB};
    use mc_rand::{CryptoRng, RngCore};
    use mc_transaction_core::{tokens::Mob, Token};
    use rand::{rngs::StdRng, SeedableRng};
    use tempfile::TempDir;

    fn setup_test_t3_store(logger: &Logger) -> (Arc<Environment>, T3Store) {
        let db_tmp = TempDir::new().expect("Could not make tempdir for utxo store db");
        let db_path = db_tmp
            .path()
            .to_str()
            .expect("Could not get path as string");

        let env = Arc::new(
            Environment::new()
                .set_max_dbs(10)
                .set_map_size(10000000)
                .open(db_path.as_ref())
                .unwrap(),
        );

        let t3_store = T3Store::new(env.clone(), logger.clone()).unwrap();

        (env, t3_store)
    }

    fn rnd_transparent_transaction(rng: &mut (impl CryptoRng + RngCore)) -> TransparentTransaction {
        let mut sender_address_hash = [0u8; 16];
        rng.fill_bytes(&mut sender_address_hash);

        let mut receiver_address_hash = [0u8; 16];
        rng.fill_bytes(&mut receiver_address_hash);

        TransparentTransaction {
            sender_address_hash: sender_address_hash.to_vec(),
            recipient_address_hash: receiver_address_hash.to_vec(),
            ..Default::default()
        }
    }

    #[test_with_logger]
    fn test_t3_store_transparent_tx_happy_path(logger: Logger) {
        let mut rng: StdRng = SeedableRng::from_seed([123u8; 32]);
        let (env, t3_store) = setup_test_t3_store(&logger);

        let mut txs = (0..10)
            .map(|_| rnd_transparent_transaction(&mut rng))
            .collect::<Vec<_>>();

        let mut db_txn = env.begin_rw_txn().unwrap();
        for tx in txs.iter() {
            t3_store.append_transparent_tx(&mut db_txn, tx).unwrap();
        }
        db_txn.commit().unwrap();

        let db_txn = env.begin_ro_txn().unwrap();
        assert_eq!(
            t3_store.dequeue_transparent_tx(&db_txn).unwrap(),
            Some((0, txs[0].clone()))
        );
        assert_eq!(
            t3_store.dequeue_transparent_tx(&db_txn).unwrap(),
            Some((0, txs[0].clone()))
        );
        drop(db_txn);

        let mut db_txn = env.begin_rw_txn().unwrap();
        for i in 0..10 {
            assert_eq!(
                t3_store.dequeue_transparent_tx(&db_txn).unwrap(),
                Some((i, txs[0].clone()))
            );

            t3_store.remove_transparent_tx(&mut db_txn, i).unwrap();
            txs.remove(0);

            if !txs.is_empty() {
                assert_eq!(
                    t3_store.dequeue_transparent_tx(&db_txn).unwrap(),
                    Some((i + 1, txs[0].clone()))
                );
            }
        }
    }

    #[test_with_logger]
    fn test_t3_store_transparent_tx_empty_queue(logger: Logger) {
        let (env, t3_store) = setup_test_t3_store(&logger);

        let db_txn = env.begin_ro_txn().unwrap();
        assert_eq!(t3_store.dequeue_transparent_tx(&db_txn).unwrap(), None);
    }

    #[test_with_logger]
    fn test_t3_store_remove_nonexistent_transparent_tx(logger: Logger) {
        let (env, t3_store) = setup_test_t3_store(&logger);

        let mut db_txn = env.begin_rw_txn().unwrap();
        assert_matches!(
            t3_store.remove_transparent_tx(&mut db_txn, 0),
            Err(Error::Lmdb(lmdb::Error::NotFound))
        );
    }
}
