// Copyright (c) 2018-2021 The MobileCoin Foundation

//! Database storage for discovered outputs.
//! * Manages the mapping of (monitor id, subaddress index) -> [UnspentTxOut]s.

use crate::{
    database_key::DatabaseByteArrayKey, error::Error, monitor_store::MonitorId,
    subaddress_store::SubaddressId,
};

use lmdb::{Cursor, Database, DatabaseFlags, Environment, RwTransaction, Transaction, WriteFlags};
use mc_common::{logger::Logger, HashMap};
use mc_transaction_core::{ring_signature::KeyImage, tx::TxOut};
use mc_util_serial::Message;
use std::{convert::TryFrom, sync::Arc};

// LMDB Database Names
pub const SUBADDRESS_ID_TO_UTXO_ID_DB_NAME: &str =
    "mobilecoind_db:utxo_store:subaddress_id_to_utxo_id";

pub const KEY_IMAGE_TO_SUBADDRESS_ID_DB_NAME: &str =
    "mobilecoind_db:utxo_store:key_image_to_subaddress_id";

pub const UTXO_ID_TO_UTXO_DATA_DB_NAME: &str = "mobilecoind_db:utxo_store:utxo_id_to_utxo";

/// An unspent (when discovered) transaction output with some annotations.
#[derive(Clone, Eq, Hash, PartialEq, Message)]
pub struct UnspentTxOut {
    /// The actual transaction output.
    #[prost(message, required, tag = "1")]
    pub tx_out: TxOut,

    /// Index of the subaddress to which this output was sent.
    #[prost(uint64, tag = "2")]
    pub subaddress_index: u64,

    /// Key image of this TxOut.
    #[prost(message, required, tag = "3")]
    pub key_image: KeyImage,

    /// Value of this TxOut.
    #[prost(uint64, tag = "4")]
    pub value: u64,

    /// The block height at which the transaction manager last attempted to
    /// spend this UnspentTxOut An output can only be considered as spent if
    /// its KeyImage appears in the ledger, but this flag can provide a
    /// useful hint to the TransactionManager that the UnspentTxOut may have
    /// been used in a recent transaction that is still pending.
    #[prost(uint64, tag = "5")]
    pub attempted_spend_height: u64,

    /// The tombstone block used when we attempted to spend the UTXO.
    #[prost(uint64, tag = "6")]
    pub attempted_spend_tombstone: u64,
}

/// Type used as the key in the utxo_id_to_utxo  database.
pub type UtxoId = DatabaseByteArrayKey;

impl From<&UnspentTxOut> for UtxoId {
    fn from(src: &UnspentTxOut) -> Self {
        // The key image uniquely identifies a TxOut, which uniquely identifies an
        // UnspentTxOut.
        Self::from(&src.key_image)
    }
}

impl From<&KeyImage> for UtxoId {
    fn from(src: &KeyImage) -> Self {
        Self::from(src.as_bytes())
    }
}

/// The outputs database.
#[derive(Clone)]
pub struct UtxoStore {
    env: Arc<Environment>,

    /// Mapping of SubaddressId -> [UtxoId].
    /// This holds the list of UtxoIds associated with a (monitor id, subaddress
    /// index tuple) and is used to lookup utxos for a specific index.
    subaddress_id_to_utxo_id: Database,

    /// Mapping of KeyImage -> SubaddressId.
    /// This is needed for more efficient removal of an UnspentTxOut based on a
    /// key image, as well as to allow checking of which monitor a given
    /// UnspentTxOut belongs to.
    key_image_to_subaddress_id: Database,

    /// Mapping of UtxoId -> UnspentTxOut.
    utxo_id_to_utxo: Database,

    /// Logger.
    logger: Logger,
}

impl UtxoStore {
    pub fn new(env: Arc<Environment>, logger: Logger) -> Result<Self, Error> {
        let subaddress_id_to_utxo_id = env.create_db(
            Some(SUBADDRESS_ID_TO_UTXO_ID_DB_NAME),
            // DUP_SORT is needed here since we are storing multiple UtxoIds per SubaddressId.
            // Note that values in a DUP_SORT db must be < 511 bytes!
            DatabaseFlags::DUP_SORT | DatabaseFlags::DUP_FIXED,
        )?;

        let key_image_to_subaddress_id = env.create_db(
            Some(KEY_IMAGE_TO_SUBADDRESS_ID_DB_NAME),
            DatabaseFlags::empty(),
        )?;

        let utxo_id_to_utxo = env.create_db(
            Some(UTXO_ID_TO_UTXO_DATA_DB_NAME),
            DatabaseFlags::empty(), // here we can store larger values
        )?;

        Ok(Self {
            env,
            subaddress_id_to_utxo_id,
            key_image_to_subaddress_id,
            utxo_id_to_utxo,
            logger,
        })
    }

    /// Append a discovered transaction to the list stored for a given
    /// subaddress.
    pub fn append_utxo<'env>(
        &self,
        db_txn: &mut RwTransaction<'env>,
        monitor_id: &MonitorId,
        index: u64,
        utxo: &UnspentTxOut,
    ) -> Result<(), Error> {
        let subaddress_id = SubaddressId::new(monitor_id, index);
        let subaddress_id_bytes = subaddress_id.to_vec();
        let utxo_id = UtxoId::from(utxo);

        // Sanity test
        if index != utxo.subaddress_index {
            return Err(Error::InvalidArgument(
                "index".to_string(),
                "must be equal to utxo.subaddress_index".to_string(),
            ));
        }

        // Store the utxo_id -> UnspentTxOut if it is not already in the database.
        let utxo_bytes = mc_util_serial::encode(utxo);
        match db_txn.put(
            self.utxo_id_to_utxo,
            &utxo_id,
            &utxo_bytes,
            WriteFlags::NO_OVERWRITE,
        ) {
            Ok(_) => Ok(()),
            Err(lmdb::Error::KeyExist) => Err(Error::DuplicateUnspentTxOut),
            Err(err) => Err(err.into()),
        }?;

        // Store the key image -> subaddress id.
        db_txn.put(
            self.key_image_to_subaddress_id,
            utxo.key_image.as_bytes(),
            &subaddress_id_bytes,
            // Since the `put` operation above guarantees utxo uniqueness in the database, we are
            // not expecting to fail here. NO_OVERWRITE would result in KeyExist being returned
            // from this method, which indicates a bug.
            WriteFlags::NO_OVERWRITE,
        )?;

        // Add the utxo id to the list indexed by subaddress_id.
        db_txn.put(
            self.subaddress_id_to_utxo_id,
            &subaddress_id_bytes,
            &utxo_id,
            WriteFlags::NO_DUP_DATA,
        )?;

        Ok(())
    }

    /// Removes all utxos associated with a given address.
    pub fn remove_utxos<'env>(
        &self,
        db_txn: &mut RwTransaction<'env>,
        monitor_id: &MonitorId,
        index: u64,
    ) -> Result<(), Error> {
        let subaddress_id = SubaddressId::new(monitor_id, index);
        let subaddress_id_bytes = subaddress_id.to_vec();

        // Go over the list of all UtxoIds associated with this subaddress and remove
        // them.
        let mut deleted_something = false;
        for utxo_id in self.get_utxo_ids(db_txn, &subaddress_id)? {
            db_txn.del(self.utxo_id_to_utxo, &utxo_id, None)?;

            // Conveniently, utxo_id == key image.
            db_txn.del(self.key_image_to_subaddress_id, &utxo_id, None)?;

            deleted_something = true;
        }

        // Delete the actual list.
        match db_txn.del(self.subaddress_id_to_utxo_id, &subaddress_id_bytes, None) {
            Ok(_) => Ok(()),
            Err(lmdb::Error::NotFound) => {
                if deleted_something {
                    // If we deleted something and the actual list didn't exist, something is
                    // weird. Return the lmdb error.
                    Err(lmdb::Error::NotFound)
                } else {
                    Ok(())
                }
            }
            Err(err) => Err(err),
        }?;

        // Success.
        Ok(())
    }

    /// Removes utxos based on a list of key images.
    /// This method silently ignores key images that were not found in the
    /// database. It returns the list of utxos that were removed.
    pub fn remove_utxos_by_key_images<'env>(
        &self,
        db_txn: &mut RwTransaction<'env>,
        monitor_id: &MonitorId,
        key_images: &[KeyImage],
    ) -> Result<Vec<UnspentTxOut>, Error> {
        // Break down the key images by SubaddressId. We need key images bytes, so the
        // mapping as to the actual byte array.
        let mut subaddress_id_to_key_images = HashMap::<SubaddressId, Vec<&[u8]>>::default();
        for key_image in key_images.iter() {
            match db_txn.get(self.key_image_to_subaddress_id, key_image.as_bytes()) {
                Ok(subaddress_id_bytes) => {
                    let subaddress_id = SubaddressId::try_from(subaddress_id_bytes)?;

                    // We only care about subaddresses belonging to the monitor id that was handed
                    // to us.
                    if subaddress_id.monitor_id == *monitor_id {
                        subaddress_id_to_key_images
                            .entry(subaddress_id)
                            .or_insert_with(Vec::new)
                            .push(key_image.as_bytes());
                    }

                    Ok(())
                }
                Err(lmdb::Error::NotFound) => Ok(()),
                Err(err) => Err(Error::Lmdb(err)),
            }?;
        }

        // Keep track of key images we have successfully removed.
        let mut removed_key_images = Vec::<KeyImage>::new();

        // Go over the key images by subaddress id.
        for (subaddress_id, key_images) in subaddress_id_to_key_images.iter() {
            // Go over the list of utxo ids associated with the subaddress_id, and remove
            // the ones that match the list of key images. Keep track of which
            // ones were successfully removed so that we could clear their utxo
            // data and return them to the caller.
            let mut cursor = db_txn.open_rw_cursor(self.subaddress_id_to_utxo_id)?;
            let _ = cursor
                .iter_dup_of(&subaddress_id.to_vec())
                .map(|result| {
                    result
                        .map_err(Error::from)
                        .and_then(|(subaddress_id_bytes, utxo_id_bytes)| {
                            // Sanity check.
                            assert_eq!(subaddress_id_bytes, &subaddress_id.to_vec()[..]);

                            // Remember: The utxo id bytes are equal to the KeyImage
                            if key_images.contains(&utxo_id_bytes) {
                                // utxo ids and key images are interchangeable so this is not
                                // expected to fail.
                                // Note that it is critical to read `utxo_id_bytes` BEFORE deleting
                                // due to this bug: https://github.com/danburkert/lmdb-rs/issues/57
                                removed_key_images.push(KeyImage::try_from(utxo_id_bytes).unwrap());

                                cursor.del(WriteFlags::empty())?;
                            }

                            Ok(())
                        })
                })
                .collect::<Result<Vec<()>, Error>>()?;
        }

        // Collect and remove the actual UnspentTxOut data for every key image we
        // successfully removed, as well as the key image -> subaddress
        // association as that is no longer going to be needed.
        let mut removed_utxos = Vec::new();

        for key_image in removed_key_images.iter() {
            let utxo_id = UtxoId::from(key_image);

            removed_utxos.push(self.get_utxo_by_id(db_txn, &utxo_id)?);

            db_txn.del(self.utxo_id_to_utxo, &utxo_id, None)?;
            db_txn.del(self.key_image_to_subaddress_id, &key_image, None)?;
        }

        // Success.
        Ok(removed_utxos)
    }

    /// Get all UnspentTxOuts for a given address.
    pub fn get_utxos(
        &self,
        db_txn: &impl Transaction,
        monitor_id: &MonitorId,
        index: u64,
    ) -> Result<Vec<UnspentTxOut>, Error> {
        let subaddress_id = SubaddressId::new(monitor_id, index);

        let utxo_ids = self.get_utxo_ids(db_txn, &subaddress_id)?;
        utxo_ids
            .iter()
            .map(|utxo_id| self.get_utxo_by_id(db_txn, utxo_id))
            .collect()
    }

    /// Get subaddress id by utxo id.
    pub fn get_subaddress_id_by_utxo_id(
        &self,
        db_txn: &impl Transaction,
        utxo_id: &UtxoId,
    ) -> Result<SubaddressId, Error> {
        // Remember: key image and utxo_id byte representations are identical by design.
        match db_txn.get(self.key_image_to_subaddress_id, &utxo_id) {
            Ok(value_bytes) => Ok(SubaddressId::try_from(value_bytes)?),
            Err(lmdb::Error::NotFound) => Err(Error::UtxoIdNotFound),
            Err(err) => Err(err.into()),
        }
    }

    /// Update a list of UnspentTxOuts attempted_spend_height and
    /// attempted_spend_tombstone.
    pub fn update_attempted_spend<'env>(
        &self,
        db_txn: &mut RwTransaction<'env>,
        utxo_ids: &[UtxoId],
        attempted_spend_height: u64,
        attempted_spend_tombstone: u64,
    ) -> Result<(), Error> {
        for utxo_id in utxo_ids.iter() {
            let mut utxo = match self.get_utxo_by_id(db_txn, utxo_id) {
                Ok(utxo) => utxo,
                Err(Error::UtxoIdNotFound) => {
                    continue;
                }
                Err(err) => {
                    return Err(err);
                }
            };

            // We shouldn't be moving backwards in time.
            assert!(attempted_spend_height >= utxo.attempted_spend_height);
            assert!(attempted_spend_tombstone >= attempted_spend_height);

            utxo.attempted_spend_height = attempted_spend_height;
            utxo.attempted_spend_tombstone = attempted_spend_tombstone;

            let utxo_bytes = mc_util_serial::encode(&utxo);
            db_txn.put(
                self.utxo_id_to_utxo,
                utxo_id,
                &utxo_bytes,
                WriteFlags::empty(),
            )?;
        }

        Ok(())
    }

    /// Get all UtxoIds associated with a given subaddress.
    fn get_utxo_ids(
        &self,
        db_txn: &impl Transaction,
        subaddress_id: &SubaddressId,
    ) -> Result<Vec<UtxoId>, Error> {
        let mut cursor = db_txn.open_ro_cursor(self.subaddress_id_to_utxo_id)?;
        cursor
            .iter_dup_of(&subaddress_id.to_vec())
            .map(|result| {
                result
                    .map_err(Error::from)
                    .and_then(|(subaddress_id_bytes, utxo_id_bytes)| {
                        // Sanity check.
                        assert_eq!(subaddress_id.to_vec(), subaddress_id_bytes);

                        UtxoId::try_from(utxo_id_bytes)
                    })
            })
            .collect::<Result<Vec<_>, Error>>()
    }

    /// Get a single UnspentTxOut by its id.
    fn get_utxo_by_id(
        &self,
        db_txn: &impl Transaction,
        utxo_id: &UtxoId,
    ) -> Result<UnspentTxOut, Error> {
        match db_txn.get(self.utxo_id_to_utxo, &utxo_id) {
            Ok(value_bytes) => Ok(mc_util_serial::decode(value_bytes)?),
            Err(lmdb::Error::NotFound) => Err(Error::UtxoIdNotFound),
            Err(err) => Err(err.into()),
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::test_utils::{get_test_databases, get_test_monitor_data_and_id};
    use mc_common::{
        logger::{test_with_logger, Logger},
        HashSet,
    };
    use mc_crypto_rand::{CryptoRng, RngCore};
    use mc_ledger_db::{Ledger, LedgerDB};
    use rand::{rngs::StdRng, SeedableRng};
    use std::iter::FromIterator;
    use tempdir::TempDir;

    fn setup_test_utxo_store(
        mut rng: &mut (impl CryptoRng + RngCore),
        logger: &Logger,
    ) -> (LedgerDB, UtxoStore, Vec<UnspentTxOut>) {
        // Set up a db with 3 random recipients and 10 blocks.
        let (ledger_db, _mobilecoind_db) =
            get_test_databases(3, &vec![], 10, logger.clone(), &mut rng);

        // Get a few TxOuts to play with, and use them to construct UnspentTxOuts.
        let utxos: Vec<UnspentTxOut> = (0..5)
            .map(|idx| {
                let tx_out = ledger_db.get_tx_out_by_index(idx).unwrap();
                UnspentTxOut {
                    tx_out,
                    subaddress_index: 0,
                    key_image: KeyImage::from(idx),
                    value: idx,
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

        let utxo_store = UtxoStore::new(env, logger.clone()).unwrap();

        // Return
        (ledger_db, utxo_store, utxos)
    }

    // UtxoStore basic functionality tests
    #[test_with_logger]
    fn test_utxo_store(logger: Logger) {
        let mut rng: StdRng = SeedableRng::from_seed([123u8; 32]);
        let (_ledger_db, utxo_store, utxos) = setup_test_utxo_store(&mut rng, &logger);
        let utxo_ids: Vec<UtxoId> = utxos.iter().map(UtxoId::from).collect();

        // Some random monitor ids to play with
        let (_monitor_data, monitor_id0) = get_test_monitor_data_and_id(&mut rng);
        let (_monitor_data, monitor_id1) = get_test_monitor_data_and_id(&mut rng);

        // Two subaddresses for each monitor.
        let subaddress0_0 = SubaddressId::new(&monitor_id0, 0);
        let subaddress0_1 = SubaddressId::new(&monitor_id0, 1);

        let subaddress1_0 = SubaddressId::new(&monitor_id1, 0);
        let subaddress1_1 = SubaddressId::new(&monitor_id1, 1);

        // We run the test a few times to ensure its idempotent.
        for _ in 0..3 {
            // Initially we should have no utxo ids in our database.
            {
                let db_txn = utxo_store.env.begin_ro_txn().unwrap();

                for subaddress in &[
                    &subaddress0_0,
                    &subaddress0_1,
                    &subaddress1_0,
                    &subaddress1_1,
                ] {
                    assert_eq!(
                        utxo_store.get_utxo_ids(&db_txn, subaddress).unwrap(),
                        vec![],
                    );
                }
            }

            // Append two outputs to the subaddress0_0
            {
                let mut db_txn = utxo_store.env.begin_rw_txn().unwrap();

                utxo_store
                    .append_utxo(&mut db_txn, &monitor_id0, 0, &utxos[0])
                    .unwrap();
                utxo_store
                    .append_utxo(&mut db_txn, &monitor_id0, 0, &utxos[1])
                    .unwrap();

                // The utxo ids should be available for subaddress0_0.
                assert_eq!(
                    HashSet::from_iter(vec![utxo_ids[0], utxo_ids[1]]),
                    HashSet::from_iter(utxo_store.get_utxo_ids(&db_txn, &subaddress0_0).unwrap()),
                );

                // The utxos should be identical to the ones we inserted.
                assert_eq!(
                    HashSet::from_iter(vec![utxos[0].clone(), utxos[1].clone()]),
                    HashSet::from_iter(
                        utxo_store
                            .get_utxos(&db_txn, &subaddress0_0.monitor_id, subaddress0_0.index)
                            .unwrap()
                    ),
                );

                // Other monitors/subaddresses should still have no data.
                for subaddress in &[&subaddress0_1, &subaddress1_0, &subaddress1_1] {
                    assert_eq!(
                        utxo_store.get_utxo_ids(&db_txn, subaddress).unwrap(),
                        vec![],
                    );

                    assert_eq!(
                        utxo_store
                            .get_utxos(&db_txn, &subaddress.monitor_id, subaddress.index)
                            .unwrap(),
                        vec![],
                    );
                }

                // Commit so the next part of the test could read those utxos.
                db_txn.commit().unwrap();
            }

            // Appending an output that is already in the database should fail, regardless
            // of the monitor/subaddress it is being appended to.
            {
                let mut db_txn = utxo_store.env.begin_rw_txn().unwrap();

                for subaddress in &[
                    &subaddress0_0,
                    &subaddress0_1,
                    &subaddress1_0,
                    &subaddress1_1,
                ] {
                    let mut utxo = utxos[0].clone();
                    utxo.subaddress_index = subaddress.index;

                    match utxo_store.append_utxo(
                        &mut db_txn,
                        &subaddress.monitor_id,
                        subaddress.index,
                        &utxo,
                    ) {
                        Ok(_) => panic!("unexpected success"),
                        Err(Error::DuplicateUnspentTxOut) => {}
                        Err(err) => panic!("unexpected error {:?}", err),
                    }
                }
            }

            // Appending new utxos to a different monitor/index should succeed, and not get
            // mixed with the previously addded ones.
            {
                let mut db_txn = utxo_store.env.begin_rw_txn().unwrap();

                let mut utxo = utxos[2].clone();
                utxo.subaddress_index = subaddress1_1.index;

                utxo_store
                    .append_utxo(
                        &mut db_txn,
                        &subaddress1_1.monitor_id,
                        subaddress1_1.index,
                        &utxo,
                    )
                    .unwrap();

                // Verify we can read the expected ids for each of our four subaddresses.
                assert_eq!(
                    HashSet::from_iter(vec![utxo_ids[0], utxo_ids[1]]),
                    HashSet::from_iter(utxo_store.get_utxo_ids(&db_txn, &subaddress0_0).unwrap()),
                );

                assert_eq!(
                    utxo_store.get_utxo_ids(&db_txn, &subaddress0_1).unwrap(),
                    vec![],
                );

                assert_eq!(
                    utxo_store.get_utxo_ids(&db_txn, &subaddress1_0).unwrap(),
                    vec![],
                );

                assert_eq!(
                    utxo_store.get_utxo_ids(&db_txn, &subaddress1_1).unwrap(),
                    vec![utxo_ids[2]],
                );

                // Commit so the next part of the test could read those utxos.
                db_txn.commit().unwrap();
            }

            // Remove all utxos for subaddress0_0 and check only it got affected.
            {
                let mut db_txn = utxo_store.env.begin_rw_txn().unwrap();

                utxo_store
                    .remove_utxos(&mut db_txn, &subaddress0_0.monitor_id, subaddress0_0.index)
                    .unwrap();

                // Verify we can read the expected ids for each of our four subaddresses.
                assert_eq!(
                    utxo_store.get_utxo_ids(&db_txn, &subaddress0_0).unwrap(),
                    vec![],
                );

                assert_eq!(
                    utxo_store.get_utxo_ids(&db_txn, &subaddress0_1).unwrap(),
                    vec![],
                );

                assert_eq!(
                    utxo_store.get_utxo_ids(&db_txn, &subaddress1_0).unwrap(),
                    vec![],
                );

                assert_eq!(
                    utxo_store.get_utxo_ids(&db_txn, &subaddress1_1).unwrap(),
                    vec![utxo_ids[2]],
                );

                // Commit so the next part of the test could read those utxos.
                db_txn.commit().unwrap();
            }

            // Remove the remaining utxo, and by that restore the database into its empty
            // state.
            {
                let mut db_txn = utxo_store.env.begin_rw_txn().unwrap();

                utxo_store
                    .remove_utxos(&mut db_txn, &subaddress1_1.monitor_id, subaddress1_1.index)
                    .unwrap();

                for subaddress in &[
                    &subaddress0_0,
                    &subaddress0_1,
                    &subaddress1_0,
                    &subaddress1_1,
                ] {
                    assert_eq!(
                        utxo_store.get_utxo_ids(&db_txn, subaddress).unwrap(),
                        vec![],
                    );
                }

                // Commit so the next part of the test could read those utxos.
                db_txn.commit().unwrap();
            }

            // Removing utxos when none exist should not error.
            {
                let mut db_txn = utxo_store.env.begin_rw_txn().unwrap();

                utxo_store
                    .remove_utxos(&mut db_txn, &subaddress1_1.monitor_id, subaddress0_0.index)
                    .unwrap();
            }
        }
    }

    /// remove_utxos_by_key_images behaves as expected.
    #[test_with_logger]
    fn test_remove_utxos_by_key_images(logger: Logger) {
        let mut rng: StdRng = SeedableRng::from_seed([123u8; 32]);
        let (_ledger_db, utxo_store, mut utxos) = setup_test_utxo_store(&mut rng, &logger);
        let key_images: Vec<KeyImage> = utxos.iter().map(|utxo| utxo.key_image.clone()).collect();

        // Some random monitor ids to play with
        let (_monitor_data, monitor_id0) = get_test_monitor_data_and_id(&mut rng);
        let (_monitor_data, monitor_id1) = get_test_monitor_data_and_id(&mut rng);

        // Removing nonexistent key images should return success and remove nothing.
        {
            let mut db_txn = utxo_store.env.begin_rw_txn().unwrap();

            let removed_utxos = utxo_store
                .remove_utxos_by_key_images(&mut db_txn, &monitor_id0, &[])
                .unwrap();
            assert_eq!(removed_utxos, vec![]);

            let removed_utxos = utxo_store
                .remove_utxos_by_key_images(&mut db_txn, &monitor_id0, &key_images)
                .unwrap();
            assert_eq!(removed_utxos, vec![]);
        }

        // Add a few utxos to monitor_id0.
        {
            let mut db_txn = utxo_store.env.begin_rw_txn().unwrap();

            // Three for monitor_id0
            utxos[0].subaddress_index = 123;
            utxo_store
                .append_utxo(
                    &mut db_txn,
                    &monitor_id0,
                    utxos[0].subaddress_index,
                    &utxos[0],
                )
                .unwrap();

            utxos[1].subaddress_index = 123;
            utxo_store
                .append_utxo(
                    &mut db_txn,
                    &monitor_id0,
                    utxos[1].subaddress_index,
                    &utxos[1],
                )
                .unwrap();

            utxos[2].subaddress_index = 0;
            utxo_store
                .append_utxo(
                    &mut db_txn,
                    &monitor_id0,
                    utxos[2].subaddress_index,
                    &utxos[2],
                )
                .unwrap();

            // And wwo for monitor_id1
            utxos[3].subaddress_index = 123;
            utxo_store
                .append_utxo(
                    &mut db_txn,
                    &monitor_id1,
                    utxos[3].subaddress_index,
                    &utxos[3],
                )
                .unwrap();

            utxos[4].subaddress_index = 666;
            utxo_store
                .append_utxo(
                    &mut db_txn,
                    &monitor_id1,
                    utxos[4].subaddress_index,
                    &utxos[4],
                )
                .unwrap();

            db_txn.commit().unwrap();
        }

        // Attempting to remove the utxos from a different monitor should not remove
        // them.
        {
            let mut db_txn = utxo_store.env.begin_rw_txn().unwrap();

            // The first key images are associated with monitor_id0.
            let removed_utxos = utxo_store
                .remove_utxos_by_key_images(&mut db_txn, &monitor_id1, &key_images[0..2])
                .unwrap();
            assert_eq!(removed_utxos, vec![]);

            db_txn.commit().unwrap();
        }

        // Nothing should've been removed
        {
            let db_txn = utxo_store.env.begin_ro_txn().unwrap();

            assert_eq!(
                HashSet::from_iter(utxo_store.get_utxos(&db_txn, &monitor_id0, 123).unwrap()),
                HashSet::from_iter(vec![utxos[0].clone(), utxos[1].clone()])
            );

            assert_eq!(
                utxo_store.get_utxos(&db_txn, &monitor_id0, 0).unwrap(),
                vec![utxos[2].clone()]
            );

            assert_eq!(
                utxo_store.get_utxos(&db_txn, &monitor_id1, 123).unwrap(),
                vec![utxos[3].clone()]
            );

            assert_eq!(
                utxo_store.get_utxos(&db_txn, &monitor_id1, 666).unwrap(),
                vec![utxos[4].clone()]
            );
        }

        // Remove with the correct parameters.
        {
            let mut db_txn = utxo_store.env.begin_rw_txn().unwrap();

            let removed_utxos = utxo_store
                .remove_utxos_by_key_images(&mut db_txn, &monitor_id0, &key_images)
                .unwrap();
            assert_eq!(
                HashSet::from_iter(removed_utxos.iter().map(|utxo| utxo.key_image.clone())),
                HashSet::from_iter(vec![
                    key_images[0].clone(),
                    key_images[1].clone(),
                    key_images[2].clone()
                ])
            );

            assert_eq!(
                HashSet::from_iter(removed_utxos),
                HashSet::from_iter(vec![utxos[0].clone(), utxos[1].clone(), utxos[2].clone()])
            );

            assert_eq!(
                utxo_store.get_utxos(&db_txn, &monitor_id0, 123).unwrap(),
                vec![]
            );

            assert_eq!(
                utxo_store.get_utxos(&db_txn, &monitor_id0, 0).unwrap(),
                vec![]
            );

            assert_eq!(
                utxo_store.get_utxos(&db_txn, &monitor_id1, 123).unwrap(),
                vec![utxos[3].clone()]
            );

            assert_eq!(
                utxo_store.get_utxos(&db_txn, &monitor_id1, 666).unwrap(),
                vec![utxos[4].clone()]
            );

            db_txn.commit().unwrap();
        }

        // Removing again should do nothing.
        {
            let mut db_txn = utxo_store.env.begin_rw_txn().unwrap();

            let removed_utxos = utxo_store
                .remove_utxos_by_key_images(&mut db_txn, &monitor_id0, &key_images)
                .unwrap();
            assert_eq!(removed_utxos, vec![]);

            assert_eq!(
                utxo_store.get_utxos(&db_txn, &monitor_id0, 123).unwrap(),
                vec![]
            );

            assert_eq!(
                utxo_store.get_utxos(&db_txn, &monitor_id0, 0).unwrap(),
                vec![]
            );

            assert_eq!(
                utxo_store.get_utxos(&db_txn, &monitor_id1, 123).unwrap(),
                vec![utxos[3].clone()]
            );

            assert_eq!(
                utxo_store.get_utxos(&db_txn, &monitor_id1, 666).unwrap(),
                vec![utxos[4].clone()]
            );

            db_txn.commit().unwrap();
        }
    }

    #[test_with_logger]
    fn test_update_attempted_spend(logger: Logger) {
        let mut rng: StdRng = SeedableRng::from_seed([123u8; 32]);
        let (_ledger_db, utxo_store, utxos) = setup_test_utxo_store(&mut rng, &logger);
        let (_monitor_data, monitor_id) = get_test_monitor_data_and_id(&mut rng);

        // Append utxos to database
        {
            let mut db_txn = utxo_store.env.begin_rw_txn().unwrap();

            assert!(!utxos.is_empty());
            for utxo in utxos.iter() {
                utxo_store
                    .append_utxo(&mut db_txn, &monitor_id, utxo.subaddress_index, utxo)
                    .unwrap();
            }

            db_txn.commit().unwrap();
        }

        // We should have the original attempted_spend_height/attempted_spend_tombstone
        // in the database.
        {
            let db_txn = utxo_store.env.begin_ro_txn().unwrap();

            for utxo in utxos.iter() {
                let utxo2 = utxo_store
                    .get_utxo_by_id(&db_txn, &UtxoId::from(utxo))
                    .unwrap();
                assert_eq!(utxo.attempted_spend_height, utxo2.attempted_spend_height);
                assert_eq!(
                    utxo.attempted_spend_tombstone,
                    utxo2.attempted_spend_tombstone
                );
            }
        }

        // Update some of our utxos and one that doesn't exist.
        {
            let mut db_txn = utxo_store.env.begin_rw_txn().unwrap();
            utxo_store
                .update_attempted_spend(
                    &mut db_txn,
                    &[
                        UtxoId::from(&utxos[0]),
                        UtxoId::from(&utxos[1]),
                        UtxoId::from(&KeyImage::from(1234567)),
                    ],
                    12345,
                    67890,
                )
                .unwrap();
            db_txn.commit().unwrap();
        }

        // Verify that utxos 0 and 1 got updated as expected.
        {
            let db_txn = utxo_store.env.begin_ro_txn().unwrap();

            for (i, orig_utxo) in utxos.iter().enumerate() {
                let utxo = utxo_store
                    .get_utxo_by_id(&db_txn, &UtxoId::from(orig_utxo))
                    .unwrap();

                let (expected_height, expected_tombstone) = if i < 2 {
                    (12345, 67890)
                } else {
                    (
                        orig_utxo.attempted_spend_height,
                        orig_utxo.attempted_spend_tombstone,
                    )
                };

                assert_eq!(utxo.attempted_spend_height, expected_height);
                assert_eq!(utxo.attempted_spend_tombstone, expected_tombstone);
            }
        }
    }
}
