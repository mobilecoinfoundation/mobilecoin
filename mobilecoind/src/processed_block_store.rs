// Copyright (c) 2018-2020 MobileCoin Inc.

//! Database storage for data obtained by processing blocks.
//! * Stores a map of (monitor id, block number) -> list of transactions that
//!   appeared in the given block number and belong to a given monitor id.

use crate::{error::Error, monitor_store::MonitorId, utxo_store::UnspentTxOut};
use lmdb::{Database, DatabaseFlags, Environment, RwTransaction, WriteFlags};
use mc_common::logger::Logger;
use mc_crypto_keys::CompressedRistrettoPublic;
use mc_transaction_core::ring_signature::KeyImage;
use prost::Message;
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

/// Type used as the stored data in the processed_block_id_to_processed_tx_outs database.
/// Note that this is different than `mobilecoind_api::ProcessedTxOut`, as that one contains some
/// extra data that can be derived upon construction.
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
}

impl From<&UnspentTxOut> for ProcessedTxOut {
    fn from(src: &UnspentTxOut) -> Self {
        Self {
            subaddress_index: src.subaddress_index,
            public_key: src.tx_out.public_key,
            key_image: src.key_image,
            value: src.value,
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

    /// Feed data processed from a given block.
    pub fn block_processed<'env>(
        &self,
        db_txn: &mut RwTransaction<'env>,
        monitor_id: &MonitorId,
        block_index: u64,
        discovered_utxos: &[UnspentTxOut],
    ) -> Result<(), Error> {
        let key = ProcessedBlockKey::new(monitor_id, block_index);
        let key_bytes = key.to_vec();

        for utxo in discovered_utxos.iter() {
            let processed_tx_out = ProcessedTxOut::from(utxo);
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
