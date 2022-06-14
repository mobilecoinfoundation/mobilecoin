// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Model file for the mint_txs table.

use crate::{
    db::{
        schema::mint_txs::{self},
        Conn,
    },
    Error,
};
use diesel::prelude::*;
use mc_account_keys::PublicAddress;
use mc_api::printable::PrintableWrapper;
use mc_blockchain_types::BlockIndex;
use mc_transaction_core::TokenId;
use mc_util_serial::{decode, encode};
use serde::{Deserialize, Serialize};

/// Diesel model for the `mint_txs` table.
/// This stores audit data for a specific block index.
#[derive(Debug, Deserialize, Eq, Insertable, PartialEq, Queryable, Serialize)]
pub struct MintTx {
    /// Auto incrementing primary key.
    pub id: Option<i32>,

    /// The block index at which this mint tx appreared.
    pub block_index: i64,

    /// The token id this mint tx is for.
    pub token_id: i64,

    /// The amount being minted.
    pub amount: i64,

    /// The nonce, as hex-encoded bytes.
    pub nonce: String,

    /// The recipient of the mint.
    pub recipient_b58_address: String,

    /// Tombstone block.
    pub tombstone_block: i64,

    /// The protobuf-serialized MintTx.
    pub protobuf: Vec<u8>,

    /// The mint config id, when we are able to match it with one.
    pub mint_config_id: Option<i32>,
}

impl MintTx {
    /// Get block index.
    pub fn block_index(&self) -> u64 {
        self.block_index as u64
    }

    /// Get token id.
    pub fn token_id(&self) -> TokenId {
        TokenId::from(self.token_id as u64)
    }

    /// Get amount.
    pub fn amount(&self) -> u64 {
        self.amount as u64
    }

    /// Get tombstone block.
    pub fn tombstone_block(&self) -> u64 {
        self.tombstone_block as u64
    }

    /// Get the original MintTx
    pub fn decode(&self) -> Result<mc_transaction_core::mint::MintTx, Error> {
        Ok(decode(&self.protobuf)?)
    }

    /// Insert a new MintTx into the database.
    pub fn insert(
        block_index: BlockIndex,
        mint_config_id: Option<i32>,
        tx: &mc_transaction_core::mint::MintTx,
        conn: &Conn,
    ) -> Result<(), Error> {
        let recipient = PublicAddress::new(&tx.prefix.spend_public_key, &tx.prefix.view_public_key);
        let mut wrapper = PrintableWrapper::new();
        wrapper.set_public_address((&recipient).into());
        let recipient_b58_address = wrapper.b58_encode()?;

        let obj = Self {
            id: None,
            block_index: block_index as i64,
            token_id: tx.prefix.token_id as i64,
            amount: tx.prefix.amount as i64,
            nonce: hex::encode(&tx.prefix.nonce),
            recipient_b58_address,
            tombstone_block: tx.prefix.tombstone_block as i64,
            protobuf: encode(tx),
            mint_config_id,
        };

        diesel::insert_into(mint_txs::table)
            .values(&obj)
            .execute(conn)?;

        Ok(())
    }
}
