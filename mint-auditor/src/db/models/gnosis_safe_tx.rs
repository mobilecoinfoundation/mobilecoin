// Copyright (c) 2018-2022 The MobileCoin Foundation

use crate::{
    db::{schema::gnosis_safe_txs, Conn},
    error::Error,
    gnosis::api_data_types::RawGnosisTransaction,
};
use diesel::prelude::*;
use serde::{Deserialize, Serialize};

/// Diesel model for the `gnosis_safe_txs` table.
/// This table stores txs into the monitored gnosis safe.
#[derive(
    Clone, Debug, Default, Deserialize, Eq, Hash, Insertable, PartialEq, Queryable, Serialize,
)]
pub struct GnosisSafeTx {
    /// Ethereum transaction hash.
    pub eth_tx_hash: String,

    /// The JSON representation of the transaction, as served from the gnosis
    /// API.
    pub raw_tx_json: String,
}

impl GnosisSafeTx {
    /// Insert a raw Gnosis Safe transaction into the database.
    pub fn insert(raw_tx: &RawGnosisTransaction, conn: &Conn) -> Result<(), Error> {
        let obj = Self {
            eth_tx_hash: raw_tx.tx_hash()?.to_string(),
            raw_tx_json: raw_tx.to_json_string(),
        };

        diesel::insert_into(gnosis_safe_txs::table)
            .values(obj)
            .execute(conn)?;

        Ok(())
    }

    /// Decode a Gnosis Safe transaction.
    pub fn decode(&self) -> Result<RawGnosisTransaction, Error> {
        Ok(RawGnosisTransaction::from_json_bytes(
            self.raw_tx_json.as_bytes(),
        )?)
    }
}
