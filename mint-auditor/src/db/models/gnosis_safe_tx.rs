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
#[derive(Debug, Deserialize, Eq, Insertable, PartialEq, Queryable, Serialize)]
pub struct GnosisSafeTx {
    /// Ethereum transaction hash.
    pub eth_tx_hash: String,

    /// The JSON representation of the transaction, as served from the gnosis
    /// API.
    pub raw_tx_json: String,
}

impl GnosisSafeTx {
    /// Insert a raw Gnosis Safe transaction into the database.
    pub fn insert(api_obj: &RawGnosisTransaction, conn: &Conn) -> Result<(), Error> {
        let obj = Self {
            eth_tx_hash: api_obj.tx_hash()?.to_string(),
            raw_tx_json: api_obj.to_json_string(),
        };

        diesel::insert_into(gnosis_safe_txs::table)
            .values(obj)
            .execute(conn)?;

        Ok(())
    }
}
