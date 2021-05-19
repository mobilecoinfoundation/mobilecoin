// Copyright (c) 2018-2021 The MobileCoin Foundation

//! Database storage for data obtained by processing blocks.
//! * Stores a map of (monitor id, block number) -> list of transactions that
//!   appeared in the given block number and belong to a given monitor id.

use crate::{error::Error, monitor_store::MonitorId, utxo_store::UnspentTxOut};
use lmdb::{Cursor, Database, DatabaseFlags, Environment, RwTransaction, Transaction, WriteFlags};
use mc_common::logger::Logger;
use mc_crypto_keys::CompressedRistrettoPublic;
use mc_transaction_core::ring_signature::KeyImage;
use prost::{Enumeration, Message};
use std::{convert::TryFrom, sync::Arc};

// LMDB Database Names
pub const PROCESSED_BLOCK_KEY_TO_PROCESSED_TX_OUTS_DB_NAME: &str =
    "mobilecoind_db:processed_block_store:processed_block_key_to_processed_tx_outs";

/// Type used as the key in the databases managed by the processed block store.
#[derive(Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct ProcessedBlockKey {
    /// The monitor_id for which the data belongs to.
    pub monitor_id: MonitorId,

    /// The block index.
    pub block_index: u64,
}
impl ProcessedBlockKey {
    pub fn new(monitor_id: &MonitorId, block_index: u64) -> Self {
        Self {
            monitor_id: *monitor_id,
            block_index,
        }
    }

    // 40 bytes: 32 for MonitorId, 8 for block index.
    pub fn to_bytes(&self) -> [u8; 40] {
        let mut buf = [0u8; 40];
        buf[0..32].copy_from_slice(self.monitor_id.as_bytes());
        buf[32..40].copy_from_slice(&self.block_index.to_be_bytes());
        buf
    }

    pub fn to_vec(&self) -> Vec<u8> {
        self.to_bytes().to_vec()
    }
}

impl TryFrom<&[u8]> for ProcessedBlockKey {
    type Error = Error;

    fn try_from(src: &[u8]) -> Result<Self, Self::Error> {
        if src.len() != 40 {
            return Err(Error::InvalidArgument(
                "src".to_string(),
                "src length must be exactly 40".to_string(),
            ));
        }

        let monitor_id = MonitorId::try_from(&src[0..32])?;

        let mut index_bytes = [0u8; 8];
        index_bytes.copy_from_slice(&src[32..40]);
        let block_index = u64::from_be_bytes(index_bytes);

        Ok(Self {
            monitor_id,
            block_index,
        })
    }
}

/// Direction of a ProcessedTxOut
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Enumeration)]
pub enum ProcessedTxOutDirection {
    Invalid = 0,
    Received = 1,
    Spent = 2,
}

/// Type used as the stored data in the processed_block_id_to_processed_tx_outs
/// database. Note that this is different than
/// `mobilecoind_api::ProcessedTxOut`, as that one contains some extra data that
/// can be derived upon construction.
#[derive(Clone, Eq, Hash, PartialEq, Message)]
pub struct ProcessedTxOut {
    /// The subaddress index the tx out belongs to/
    #[prost(uint64, tag = "1")]
    pub subaddress_index: u64,

    /// The public key of the TxOut.
    #[prost(message, required, tag = "2")]
    pub public_key: CompressedRistrettoPublic,

    /// Key image of the TxOut.
    #[prost(message, required, tag = "3")]
    pub key_image: KeyImage,

    /// Value of this TxOut.
    #[prost(uint64, tag = "4")]
    pub value: u64,

    /// Direction.
    #[prost(enumeration = "ProcessedTxOutDirection", tag = "5")]
    pub direction: i32,
}

impl ProcessedTxOut {
    pub fn from_received_utxo(src: &UnspentTxOut) -> Self {
        Self {
            subaddress_index: src.subaddress_index,
            public_key: src.tx_out.public_key,
            key_image: src.key_image,
            value: src.value,
            direction: ProcessedTxOutDirection::Received as i32,
        }
    }

    pub fn from_spent_utxo(src: &UnspentTxOut) -> Self {
        Self {
            subaddress_index: src.subaddress_index,
            public_key: src.tx_out.public_key,
            key_image: src.key_image,
            value: src.value,
            direction: ProcessedTxOutDirection::Spent as i32,
        }
    }
}

/// the processed blocks database.
#[derive(Clone)]
pub struct ProcessedBlockStore {
    /// LMDB Environment.
    env: Arc<Environment>,

    /// Mapping of ProcessedBlockKey -> [ProcessedTxOut].
    processed_block_key_to_processed_tx_outs: Database,

    /// Logger.
    logger: Logger,
}

impl ProcessedBlockStore {
    pub fn new(env: Arc<Environment>, logger: Logger) -> Result<Self, Error> {
        let processed_block_key_to_processed_tx_outs = env.create_db(
            Some(PROCESSED_BLOCK_KEY_TO_PROCESSED_TX_OUTS_DB_NAME),
            DatabaseFlags::DUP_SORT,
        )?;

        Ok(Self {
            env,
            processed_block_key_to_processed_tx_outs,
            logger,
        })
    }

    /// Get processed block information for a given (monitor id, block number).
    pub fn get_processed_block(
        &self,
        db_txn: &impl Transaction,
        monitor_id: &MonitorId,
        block_index: u64,
    ) -> Result<Vec<ProcessedTxOut>, Error> {
        let mut cursor = db_txn.open_ro_cursor(self.processed_block_key_to_processed_tx_outs)?;

        let key = ProcessedBlockKey::new(monitor_id, block_index);
        let key_bytes = key.to_vec();

        cursor
            .iter_dup_of(&key_bytes)
            .map(|result| {
                result.map_err(Error::from).and_then(|(db_key, db_value)| {
                    // Sanity check.
                    assert_eq!(key_bytes, db_key);

                    Ok(mc_util_serial::decode(db_value)?)
                })
            })
            .collect::<Result<Vec<_>, Error>>()
    }

    /// Remove the data associated with a given monitor id.
    pub fn remove<'env>(
        &self,
        db_txn: &mut RwTransaction<'env>,
        monitor_id: &MonitorId,
    ) -> Result<(), Error> {
        let start_key = ProcessedBlockKey::new(monitor_id, 0);
        let start_key_bytes = start_key.to_vec();

        let mut cursor = db_txn.open_rw_cursor(self.processed_block_key_to_processed_tx_outs)?;

        for (db_key, _db_value) in cursor.iter_from(&start_key_bytes).filter_map(|r| r.ok()) {
            let key = ProcessedBlockKey::try_from(db_key)?;
            if key.monitor_id == *monitor_id {
                cursor.del(WriteFlags::NO_DUP_DATA)?;
            } else {
                break;
            }
        }

        Ok(())
    }

    /// Feed data processed from a given block.
    pub fn block_processed<'env>(
        &self,
        db_txn: &mut RwTransaction<'env>,
        monitor_id: &MonitorId,
        block_index: u64,
        discovered_utxos: &[UnspentTxOut],
        spent_utxos: &[UnspentTxOut],
    ) -> Result<(), Error> {
        let key = ProcessedBlockKey::new(monitor_id, block_index);
        let key_bytes = key.to_vec();

        for utxo in discovered_utxos.iter() {
            let processed_tx_out = ProcessedTxOut::from_received_utxo(utxo);
            let processed_tx_out_bytes = mc_util_serial::encode(&processed_tx_out);
            db_txn.put(
                self.processed_block_key_to_processed_tx_outs,
                &key_bytes,
                &processed_tx_out_bytes,
                WriteFlags::empty(),
            )?;
        }

        for utxo in spent_utxos.iter() {
            let processed_tx_out = ProcessedTxOut::from_spent_utxo(utxo);
            let processed_tx_out_bytes = mc_util_serial::encode(&processed_tx_out);
            db_txn.put(
                self.processed_block_key_to_processed_tx_outs,
                &key_bytes,
                &processed_tx_out_bytes,
                WriteFlags::empty(),
            )?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{
        monitor_store::MonitorData,
        test_utils::{get_test_databases, DEFAULT_PER_RECIPIENT_AMOUNT},
    };
    use mc_account_keys::AccountKey;
    use mc_common::{
        logger::{test_with_logger, Logger},
        HashSet,
    };
    use mc_crypto_keys::RistrettoPublic;
    use mc_crypto_rand::{CryptoRng, RngCore};
    use mc_ledger_db::{Ledger, LedgerDB};
    use mc_transaction_core::{onetime_keys::recover_onetime_private_key, tx::TxOut};
    use rand::{rngs::StdRng, SeedableRng};
    use std::iter::FromIterator;
    use tempdir::TempDir;

    const TEST_SUBADDRESS: u64 = 10;

    fn setup_test_processed_block_store(
        mut rng: &mut (impl CryptoRng + RngCore),
        logger: &Logger,
    ) -> (LedgerDB, ProcessedBlockStore, AccountKey, Vec<UnspentTxOut>) {
        let account_key = AccountKey::random(&mut rng);

        // Set up a db with a known recipient, 3 random recipients and 10 blocks.
        let (ledger_db, _mobilecoind_db) = get_test_databases(
            3,
            &vec![account_key.subaddress(TEST_SUBADDRESS)],
            10,
            logger.clone(),
            &mut rng,
        );

        // Get all utxos belonging to the test account. This assumes knowledge about how
        // the test ledger is constructed by the test utils.
        let num_blocks = ledger_db.num_blocks().expect("failed getting num blocks");
        let account_tx_outs: Vec<TxOut> = (0..num_blocks)
            .map(|idx| {
                let block_contents = ledger_db.get_block_contents(idx as u64).unwrap();
                // We grab the 4th tx out in each block since the test ledger had 3 random
                // recipients, followed by our known recipient.
                // See the call to `get_testing_environment` at the beginning of the test.
                block_contents.outputs[3].clone()
            })
            .collect();

        let account_utxos: Vec<UnspentTxOut> = account_tx_outs
            .iter()
            .map(|tx_out| {
                // Calculate the key image for this tx out.
                let tx_public_key = RistrettoPublic::try_from(&tx_out.public_key).unwrap();
                let onetime_private_key = recover_onetime_private_key(
                    &tx_public_key,
                    account_key.view_private_key(),
                    &account_key.subaddress_spend_private(TEST_SUBADDRESS),
                );
                let key_image = KeyImage::from(&onetime_private_key);

                // Craft the expected UnspentTxOut
                UnspentTxOut {
                    tx_out: tx_out.clone(),
                    subaddress_index: TEST_SUBADDRESS,
                    key_image,
                    value: DEFAULT_PER_RECIPIENT_AMOUNT,
                    attempted_spend_height: 0,
                    attempted_spend_tombstone: 0,
                }
            })
            .collect();

        // The instance to test.
        let db_tmp =
            TempDir::new("utxo_store_db").expect("Could not make tempdir for utxo store db");
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

        let processed_block_store = ProcessedBlockStore::new(env, logger.clone()).unwrap();

        // Return
        (ledger_db, processed_block_store, account_key, account_utxos)
    }

    // ProcessedBlockStore basic functionality tests
    #[test_with_logger]
    fn test_processed_block_store(logger: Logger) {
        let mut rng: StdRng = SeedableRng::from_seed([123u8; 32]);
        let (ledger_db, store, account, utxos) =
            setup_test_processed_block_store(&mut rng, &logger);

        let num_blocks = ledger_db
            .num_blocks()
            .expect("failed getting number of blocks in ledger");
        assert_eq!(num_blocks, utxos.len() as u64);

        // Create a monitor id for our account.
        let monitor_data = MonitorData::new(
            account.clone(),
            0,  // first_subaddress
            20, // num_subaddresses
            0,  // first_block
            "", // name
        )
        .expect("failed to create data");

        let monitor_id = MonitorId::from(&monitor_data);

        // Initially, we should have no data for any of our blocks.
        {
            let db_txn = store.env.begin_ro_txn().unwrap();
            for block_index in 0..num_blocks + 10 {
                let tx_outs = store
                    .get_processed_block(&db_txn, &monitor_id, block_index)
                    .expect("get_processed_block failed");
                assert!(tx_outs.is_empty());
            }
        }

        // Associate the first 3 utxos with the first block and the rest into the second
        // block.
        {
            let mut db_txn = store.env.begin_rw_txn().unwrap();

            // Add in two chunks
            store
                .block_processed(&mut db_txn, &monitor_id, 0, &utxos[..2], &[])
                .expect("block_processed failed");
            store
                .block_processed(&mut db_txn, &monitor_id, 0, &utxos[2..3], &[])
                .expect("block_processed failed");

            store
                .block_processed(&mut db_txn, &monitor_id, 1, &utxos[3..], &[])
                .expect("block_processed failed");

            db_txn.commit().unwrap();
        }

        // Query the data to ensure it got properly stored.
        {
            let db_txn = store.env.begin_ro_txn().unwrap();

            // First block
            let processed_tx_outs = store
                .get_processed_block(&db_txn, &monitor_id, 0)
                .expect("get_processed_block failed");
            assert_eq!(processed_tx_outs.len(), 3);

            let expected_processed_tx_outs: HashSet<_> = utxos
                .iter()
                .take(3)
                .map(ProcessedTxOut::from_received_utxo)
                .collect();
            assert_eq!(
                expected_processed_tx_outs,
                HashSet::from_iter(processed_tx_outs)
            );

            // Second block
            let processed_tx_outs = store
                .get_processed_block(&db_txn, &monitor_id, 1)
                .expect("get_processed_block failed");
            assert_eq!(processed_tx_outs.len(), utxos.len() - 3);

            let expected_processed_tx_outs: HashSet<_> = utxos
                .iter()
                .skip(3)
                .map(ProcessedTxOut::from_received_utxo)
                .collect();
            assert_eq!(
                expected_processed_tx_outs,
                HashSet::from_iter(processed_tx_outs)
            );
        }

        // Querying with a different monitor id should return no results.
        {
            let monitor_data = MonitorData::new(
                account.clone(),
                30, // first_subaddress
                20, // num_subaddresses
                0,  // first_block
                "", // name
            )
            .expect("failed to create data");

            let monitor_id = MonitorId::from(&monitor_data);

            let mut db_txn = store.env.begin_rw_txn().unwrap();

            let processed_tx_outs = store
                .get_processed_block(&db_txn, &monitor_id, 0)
                .expect("get_processed_block failed");
            assert!(processed_tx_outs.is_empty());

            // Removing monitor id with no data should not result in an error.
            store
                .remove(&mut db_txn, &monitor_id)
                .expect("remove failed");
        }

        // Remove the monitor id and ensure data has been removed
        {
            let mut db_txn = store.env.begin_rw_txn().unwrap();

            let processed_tx_outs = store
                .get_processed_block(&db_txn, &monitor_id, 0)
                .expect("get_processed_block failed");
            assert!(!processed_tx_outs.is_empty());

            let processed_tx_outs = store
                .get_processed_block(&db_txn, &monitor_id, 1)
                .expect("get_processed_block failed");
            assert!(!processed_tx_outs.is_empty());

            store
                .remove(&mut db_txn, &monitor_id)
                .expect("remove failed");

            let processed_tx_outs = store
                .get_processed_block(&db_txn, &monitor_id, 0)
                .expect("get_processed_block failed");
            assert!(processed_tx_outs.is_empty());

            let processed_tx_outs = store
                .get_processed_block(&db_txn, &monitor_id, 1)
                .expect("get_processed_block failed");
            assert!(processed_tx_outs.is_empty());

            db_txn.commit().unwrap();
        }

        // Re-add utxos and verify correct behavior.
        {
            let mut db_txn = store.env.begin_rw_txn().unwrap();

            // Add in two chunks for the original monitor id and one chunk for a new monitor
            // id.
            store
                .block_processed(&mut db_txn, &monitor_id, 0, &utxos[1..5], &[])
                .expect("block_processed failed");

            store
                .block_processed(&mut db_txn, &monitor_id, 1, &utxos[5..], &[])
                .expect("block_processed failed");

            let monitor_data2 = MonitorData::new(
                account.clone(),
                30, // first_subaddress
                20, // num_subaddresses
                0,  // first_block
                "", // name
            )
            .expect("failed to create data");

            let monitor_id2 = MonitorId::from(&monitor_data2);

            store
                .block_processed(&mut db_txn, &monitor_id2, 0, &utxos[0..1], &utxos[1..2])
                .expect("block_processed failed");

            // First block - original monitor id
            let processed_tx_outs = store
                .get_processed_block(&db_txn, &monitor_id, 0)
                .expect("get_processed_block failed");
            assert_eq!(processed_tx_outs.len(), 4);

            let expected_processed_tx_outs: HashSet<_> = utxos
                .iter()
                .skip(1)
                .take(4)
                .map(ProcessedTxOut::from_received_utxo)
                .collect();
            assert_eq!(
                expected_processed_tx_outs,
                HashSet::from_iter(processed_tx_outs)
            );

            // First block - second monitor id
            let processed_tx_outs = store
                .get_processed_block(&db_txn, &monitor_id2, 0)
                .expect("get_processed_block failed");
            assert_eq!(processed_tx_outs.len(), 2);

            assert_eq!(
                HashSet::from_iter(vec![
                    ProcessedTxOut::from_received_utxo(&utxos[0]),
                    ProcessedTxOut::from_spent_utxo(&utxos[1])
                ]),
                HashSet::from_iter(processed_tx_outs),
            );

            // Second block - original monitor id
            let processed_tx_outs = store
                .get_processed_block(&db_txn, &monitor_id, 1)
                .expect("get_processed_block failed");
            assert_eq!(processed_tx_outs.len(), utxos.len() - 5);

            let expected_processed_tx_outs: HashSet<_> = utxos
                .iter()
                .skip(5)
                .map(ProcessedTxOut::from_received_utxo)
                .collect();
            assert_eq!(
                expected_processed_tx_outs,
                HashSet::from_iter(processed_tx_outs)
            );

            // Second block - second monitor id
            let processed_tx_outs = store
                .get_processed_block(&db_txn, &monitor_id2, 1)
                .expect("get_processed_block failed");
            assert!(processed_tx_outs.is_empty());

            db_txn.commit().unwrap();
        }
    }
}
