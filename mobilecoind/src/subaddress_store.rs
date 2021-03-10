// Copyright (c) 2018-2021 The MobileCoin Foundation

//! Database storage for subaddress indices
//! * A lookup table, mapping subaddress_spend_public_key to monitor_id and
//!   subaddress index. This is used by the ledger sync code, allowing it to
//!   match TxOuts into specific monitor_ids.

use crate::{
    database_key::DatabaseByteArrayKey,
    error::Error,
    monitor_store::{MonitorData, MonitorId},
};

use lmdb::{Database, DatabaseFlags, Environment, RwTransaction, Transaction, WriteFlags};
use mc_common::logger::{log, Logger};
use mc_crypto_keys::RistrettoPublic;
use prost::Message;
use std::{convert::TryFrom, sync::Arc};

// LMDB Database Names
pub const SUBADDRESS_PUBLIC_SPEND_KEY_TO_INDEX_DATA_DB_NAME: &str =
    "mobilecoind_db:subaddress_store:spk_to_index_data";

/// Type used to associate a monitor id and subaddress index.
/// It is used as the stored data in the spk_to_index_data database,
/// as well as by the output store.
#[derive(Message, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct SubaddressId {
    /// The monitor_id that created this entry.
    #[prost(message, required, tag = "1")]
    pub monitor_id: MonitorId,

    /// The subaddress index corresponding to this Subaddress Spend Public Key.
    #[prost(uint64, tag = "2")]
    pub index: u64,
}
impl SubaddressId {
    pub fn new(monitor_id: &MonitorId, index: u64) -> Self {
        Self {
            monitor_id: *monitor_id,
            index,
        }
    }

    // 40 bytes: 32 for MonitorId, 8 for index.
    pub fn to_bytes(&self) -> [u8; 40] {
        let mut buf = [0u8; 40];
        buf[0..32].copy_from_slice(self.monitor_id.as_bytes());
        buf[32..40].copy_from_slice(&self.index.to_be_bytes());
        buf
    }

    pub fn to_vec(&self) -> Vec<u8> {
        self.to_bytes().to_vec()
    }
}

impl TryFrom<&[u8]> for SubaddressId {
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
        let index = u64::from_be_bytes(index_bytes);

        Ok(Self { monitor_id, index })
    }
}

/// Type used as the key in the spk_to_index_data database
pub type SubaddressSPKId = DatabaseByteArrayKey;

impl From<&RistrettoPublic> for SubaddressSPKId {
    fn from(src: &RistrettoPublic) -> Self {
        Self::from(src.to_bytes())
    }
}

#[derive(Clone)]
pub struct SubaddressStore {
    env: Arc<Environment>,

    /// Mapping of Subaddress Spend Public Key -> SubaddressId
    spk_to_index_data: Database,

    /// Logger.
    logger: Logger,
}

impl SubaddressStore {
    pub fn new(env: Arc<Environment>, logger: Logger) -> Result<Self, Error> {
        let spk_to_index_data = env.create_db(
            Some(SUBADDRESS_PUBLIC_SPEND_KEY_TO_INDEX_DATA_DB_NAME),
            DatabaseFlags::empty(),
        )?;
        Ok(Self {
            env,
            spk_to_index_data,
            logger,
        })
    }

    /// Insert a new subaddress spend public key into the database.
    pub fn insert<'env>(
        &self,
        db_txn: &mut RwTransaction<'env>,
        monitor_id: &MonitorId,
        data: &MonitorData,
        index: u64,
    ) -> Result<(), Error> {
        let subaddress_spk =
            SubaddressSPKId::from(data.account_key.subaddress(index).spend_public_key());
        let subaddress_id: SubaddressId = SubaddressId::new(monitor_id, index);

        let value_bytes = mc_util_serial::encode(&subaddress_id);
        match db_txn.put(
            self.spk_to_index_data,
            &subaddress_spk,
            &value_bytes,
            WriteFlags::NO_OVERWRITE,
        ) {
            Ok(_) => Ok(()),
            Err(lmdb::Error::KeyExist) => Err(Error::SubaddressSPKIdExists),
            Err(err) => Err(err.into()),
        }?;

        log::trace!(
            self.logger,
            "Inserting {} ({}@{}) to subaddress store",
            subaddress_spk,
            monitor_id,
            index,
        );

        Ok(())
    }

    /// Returns the SubaddressId associated with a given spk
    pub fn get_index_data(
        &self,
        db_txn: &impl Transaction,
        subaddress_spk: &SubaddressSPKId,
    ) -> Result<SubaddressId, Error> {
        match db_txn.get(self.spk_to_index_data, &subaddress_spk) {
            Ok(value_bytes) => Ok(mc_util_serial::decode(value_bytes)?),
            Err(lmdb::Error::NotFound) => Err(Error::SubaddressSPKNotFound),
            Err(err) => Err(err.into()),
        }
    }

    /// deletes the SubaddressId stored for a subaddress spend public key
    pub fn delete<'env>(
        &self,
        db_txn: &mut RwTransaction<'env>,
        data: &MonitorData,
        index: u64,
    ) -> Result<(), Error> {
        let subaddress_spk =
            SubaddressSPKId::from(data.account_key.subaddress(index).spend_public_key());

        db_txn.del(self.spk_to_index_data, &subaddress_spk, None)?;

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::test_utils::get_test_monitor_data_and_id;
    use rand::{rngs::StdRng, SeedableRng};

    #[test]
    fn test_subaddress_id_to_and_from_bytes() {
        let mut rng: StdRng = SeedableRng::from_seed([123u8; 32]);
        let (_, monitor_id0) = get_test_monitor_data_and_id(&mut rng);
        let (_, monitor_id1) = get_test_monitor_data_and_id(&mut rng);

        let sid0 = SubaddressId::new(&monitor_id0, 0);
        let sid1 = SubaddressId::new(&monitor_id0, 1);
        let sid2 = SubaddressId::new(&monitor_id1, 0);

        let bytes0 = sid0.to_bytes().to_vec();
        let bytes1 = sid1.to_bytes().to_vec();
        let bytes2 = sid2.to_bytes().to_vec();

        // Byte representation should be unique for our test cases.
        assert_ne!(bytes0, bytes1);
        assert_ne!(bytes0, bytes2);

        // Byte representation should successfully convert back.
        assert_eq!(sid0, SubaddressId::try_from(&bytes0[..]).unwrap());
        assert_eq!(sid1, SubaddressId::try_from(&bytes1[..]).unwrap());
        assert_eq!(sid2, SubaddressId::try_from(&bytes2[..]).unwrap());

        // Not enough or too many bytes should fail.
        assert!(SubaddressId::try_from(&vec![0u8; 39][..]).is_err());
        assert!(SubaddressId::try_from(&vec![0u8; 40][..]).is_ok());
        assert!(SubaddressId::try_from(&vec![0u8; 41][..]).is_err());
    }
}
