// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Model file for the mint_txs table.

use crate::{
    db::{schema::mint_txs, Conn},
    Error,
};
use diesel::prelude::*;
use hex::ToHex;
use mc_account_keys::PublicAddress;
use mc_api::printable::PrintableWrapper;
use mc_blockchain_types::BlockIndex;
use mc_transaction_core::{mint::MintTx as CoreMintTx, TokenId};
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
    pub fn decode(&self) -> Result<CoreMintTx, Error> {
        Ok(decode(&self.protobuf)?)
    }

    /// Insert a new MintTx into the database.
    pub fn insert(
        block_index: BlockIndex,
        mint_config_id: Option<i32>,
        tx: &CoreMintTx,
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
            nonce: tx.prefix.nonce.encode_hex(),
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

#[cfg(test)]
mod tests {
    use super::super::MintTx;
    use crate::db::test_utils::TestDbContext;
    use mc_common::logger::{test_with_logger, Logger};
    use mc_transaction_core::TokenId;
    use mc_transaction_core_test_utils::{create_mint_config_tx_and_signers, create_mint_tx};

    #[test_with_logger]
    fn insert_enforces_uniqueness(logger: Logger) {
        let mut rng = mc_util_test_helper::get_seeded_rng();
        let test_db_context = TestDbContext::default();
        let mint_auditor_db = test_db_context.get_db_instance(logger.clone());
        let token_id1 = TokenId::from(1);

        let conn = mint_auditor_db.get_conn().unwrap();

        let (_mint_config_tx1, signers1) = create_mint_config_tx_and_signers(token_id1, &mut rng);
        let mint_tx1 = create_mint_tx(token_id1, &signers1, 100, &mut rng);

        // Store a MintTx for the first time.
        MintTx::insert(5, None, &mint_tx1, &conn).unwrap();

        // Trying again should fail.
        assert!(MintTx::insert(5, None, &mint_tx1, &conn).is_err());
    }
}
