// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Model file for the mint_txs table.

use crate::{
    db::{
        last_insert_rowid,
        schema::{audited_mints, mint_txs},
        Conn,
    },
    Error,
};
use diesel::{
    dsl::{exists, not},
    prelude::*,
};
use hex::ToHex;
use mc_account_keys::PublicAddress;
use mc_api::printable::PrintableWrapper;
use mc_blockchain_types::BlockIndex;
use mc_transaction_core::{mint::MintTx as CoreMintTx, TokenId};
use mc_util_serial::{decode, encode};
use serde::{Deserialize, Serialize};

/// Diesel model for the `mint_txs` table.
/// This stores data about a single MintTx.
#[derive(
    Clone, Debug, Default, Deserialize, Eq, Hash, Insertable, PartialEq, Queryable, Serialize,
)]
pub struct MintTx {
    /// Auto incrementing primary key.
    id: Option<i32>,

    /// The block index at which this mint tx appreared.
    block_index: i64,

    /// The token id this mint tx is for.
    token_id: i64,

    /// The amount being minted.
    amount: i64,

    /// The nonce, as hex-encoded bytes.
    nonce_hex: String,

    /// The recipient of the mint.
    recipient_b58_addr: String,

    /// Tombstone block.
    tombstone_block: i64,

    /// The protobuf-serialized MintTx.
    protobuf: Vec<u8>,

    /// The mint config id, when we are able to match it with one.
    mint_config_id: Option<i32>,
}

impl MintTx {
    /// Get id.
    pub fn id(&self) -> Option<i32> {
        self.id
    }

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

    /// Get nonce.
    pub fn nonce_hex(&self) -> &str {
        &self.nonce_hex
    }

    /// Get recipient b58 address.
    pub fn recipient_b58_addr(&self) -> &str {
        &self.recipient_b58_addr
    }

    /// Get tombstone block.
    pub fn tombstone_block(&self) -> u64 {
        self.tombstone_block as u64
    }

    /// Get mint config id, when we are able to match it with one.
    pub fn mint_config_id(&self) -> Option<i32> {
        self.mint_config_id
    }

    /// Get the original MintTx
    pub fn decode(&self) -> Result<CoreMintTx, Error> {
        Ok(decode(&self.protobuf)?)
    }

    /// Create an instance of this object from a
    /// [mc_transaction_core::mint::MintTx] and some extra information.
    pub fn from_core_mint_tx(
        block_index: BlockIndex,
        mint_config_id: Option<i32>,
        tx: &CoreMintTx,
    ) -> Result<Self, Error> {
        let recipient = PublicAddress::new(&tx.prefix.spend_public_key, &tx.prefix.view_public_key);
        let mut wrapper = PrintableWrapper::new();
        wrapper.set_public_address((&recipient).into());
        let recipient_b58_addr = wrapper.b58_encode()?;

        Ok(Self {
            id: None,
            block_index: block_index as i64,
            token_id: tx.prefix.token_id as i64,
            amount: tx.prefix.amount as i64,
            nonce_hex: tx.prefix.nonce.encode_hex(),
            recipient_b58_addr,
            tombstone_block: tx.prefix.tombstone_block as i64,
            protobuf: encode(tx),
            mint_config_id,
        })
    }

    /// Insert a new MintTx into the database.
    pub fn insert(&mut self, conn: &Conn) -> Result<(), Error> {
        if let Some(id) = self.id {
            return Err(Error::AlreadyExists(format!(
                "MintTx already has an id ({})",
                id
            )));
        }
        diesel::insert_into(mint_txs::table)
            .values(self.clone())
            .execute(conn)?;

        self.id = Some(diesel::select(last_insert_rowid).get_result::<i32>(conn)?);

        Ok(())
    }

    /// Helper for inserting from a [mc_transaction_core::mint::MintTx] and some
    /// extra information.
    pub fn insert_from_core_mint_tx(
        block_index: BlockIndex,
        mint_config_id: Option<i32>,
        tx: &CoreMintTx,
        conn: &Conn,
    ) -> Result<Self, Error> {
        let mut mint_tx = Self::from_core_mint_tx(block_index, mint_config_id, tx)?;
        mint_tx.insert(conn)?;
        Ok(mint_tx)
    }

    /// Attempt to find all [MintTx]s that do not have a matching entry in the
    /// `audited_mints` table.
    pub fn find_unaudited_mint_txs(conn: &Conn) -> Result<Vec<Self>, Error> {
        Ok(mint_txs::table
            .filter(not(exists(
                audited_mints::table
                    .select(audited_mints::mint_tx_id)
                    .filter(audited_mints::mint_tx_id.nullable().eq(mint_txs::id)),
            )))
            .load(conn)?)
    }

    /// Attempt to find a [MintTx] that has a given nonce and no matching entry
    /// in the `audited_mints` table.
    pub fn find_unaudited_mint_tx_by_nonce_and_token_id(
        token_id: TokenId,
        nonce_hex: &str,
        conn: &Conn,
    ) -> Result<Option<Self>, Error> {
        Ok(mint_txs::table
            .filter(mint_txs::token_id.eq(*token_id as i64))
            .filter(mint_txs::nonce_hex.eq(nonce_hex))
            .filter(not(exists(
                audited_mints::table
                    .select(audited_mints::mint_tx_id)
                    .filter(audited_mints::mint_tx_id.nullable().eq(mint_txs::id)),
            )))
            .first(conn)
            .optional()?)
    }

    /// Get [MintTx]s for a given block index.
    pub fn get_mint_txs_by_block_index(
        block_index: BlockIndex,
        conn: &Conn,
    ) -> Result<Vec<Self>, Error> {
        Ok(mint_txs::table
            .filter(mint_txs::block_index.eq(block_index as i64))
            .order_by(mint_txs::id)
            .load(conn)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::{
        models::AuditedMint,
        test_utils::{create_gnosis_safe_deposit, insert_gnosis_deposit, TestDbContext},
    };
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
        MintTx::insert_from_core_mint_tx(5, None, &mint_tx1, &conn).unwrap();

        // Trying again should fail.
        assert!(MintTx::insert_from_core_mint_tx(5, None, &mint_tx1, &conn).is_err());
    }

    #[test_with_logger]
    fn test_find_unaudited_mint_tx_by_nonce(logger: Logger) {
        let test_db_context = TestDbContext::default();
        let mint_auditor_db = test_db_context.get_db_instance(logger.clone());
        let token_id1 = TokenId::from(1);
        let token_id2 = TokenId::from(2);

        let conn = mint_auditor_db.get_conn().unwrap();

        let mut rng = mc_util_test_helper::get_seeded_rng();
        let mut rng2 = mc_util_test_helper::get_seeded_rng();

        // Create gnosis deposits.
        let mut deposit1 = create_gnosis_safe_deposit(100, &mut rng);
        let mut deposit2 = create_gnosis_safe_deposit(200, &mut rng);
        let deposit3 = create_gnosis_safe_deposit(300, &mut rng2);
        let deposit4 = create_gnosis_safe_deposit(400, &mut rng2);

        // Create two MintTxs.
        let (_mint_config_tx1, signers1) = create_mint_config_tx_and_signers(token_id1, &mut rng);
        let (_mint_config_tx2, signers2) = create_mint_config_tx_and_signers(token_id2, &mut rng2);

        let mut mint_tx1 = create_mint_tx(token_id1, &signers1, 100, &mut rng);
        let mut mint_tx2 = create_mint_tx(token_id1, &signers1, 100, &mut rng);
        let mut mint_tx1_tkn2 = create_mint_tx(token_id2, &signers2, 100, &mut rng2);
        let mut mint_tx2_tkn2 = create_mint_tx(token_id2, &signers2, 100, &mut rng2);

        mint_tx1.prefix.nonce = hex::decode(&deposit1.expected_mc_mint_tx_nonce_hex()).unwrap();
        mint_tx2.prefix.nonce = hex::decode(&deposit2.expected_mc_mint_tx_nonce_hex()).unwrap();
        mint_tx1_tkn2.prefix.nonce =
            hex::decode(&deposit3.expected_mc_mint_tx_nonce_hex()).unwrap();
        mint_tx2_tkn2.prefix.nonce =
            hex::decode(&deposit4.expected_mc_mint_tx_nonce_hex()).unwrap();

        // The nonces should be the same.
        assert_eq!(mint_tx1.prefix.nonce, mint_tx1_tkn2.prefix.nonce);
        assert_eq!(mint_tx2.prefix.nonce, mint_tx2_tkn2.prefix.nonce);

        // Since they haven't been inserted yet, they should not be found.
        assert!(MintTx::find_unaudited_mint_tx_by_nonce_and_token_id(
            token_id1,
            &hex::encode(&mint_tx1.prefix.nonce),
            &conn
        )
        .unwrap()
        .is_none());

        assert!(MintTx::find_unaudited_mint_tx_by_nonce_and_token_id(
            token_id1,
            &hex::encode(&mint_tx2.prefix.nonce),
            &conn
        )
        .unwrap()
        .is_none());

        assert!(MintTx::find_unaudited_mint_tx_by_nonce_and_token_id(
            token_id2,
            &hex::encode(&mint_tx1_tkn2.prefix.nonce),
            &conn
        )
        .unwrap()
        .is_none());

        assert!(MintTx::find_unaudited_mint_tx_by_nonce_and_token_id(
            token_id2,
            &hex::encode(&mint_tx2_tkn2.prefix.nonce),
            &conn
        )
        .unwrap()
        .is_none());

        // Insert the first MintTx, it should now be found.
        let sql_mint_tx1 = MintTx::insert_from_core_mint_tx(5, None, &mint_tx1, &conn).unwrap();

        assert_eq!(
            MintTx::find_unaudited_mint_tx_by_nonce_and_token_id(
                token_id1,
                &hex::encode(&mint_tx1.prefix.nonce),
                &conn
            )
            .unwrap()
            .unwrap(),
            sql_mint_tx1
        );
        // This has not been inserted, and should not be found.
        assert!(MintTx::find_unaudited_mint_tx_by_nonce_and_token_id(
            token_id1,
            &hex::encode(&mint_tx2.prefix.nonce),
            &conn
        )
        .unwrap()
        .is_none());
        // This is for a different token_id, so should not be found even though it
        // shares a nonce.
        assert!(MintTx::find_unaudited_mint_tx_by_nonce_and_token_id(
            token_id2,
            &hex::encode(&mint_tx1_tkn2.prefix.nonce),
            &conn
        )
        .unwrap()
        .is_none());
        // This is for a different token_id, so should not be found even though it
        // shares a nonce.
        assert!(MintTx::find_unaudited_mint_tx_by_nonce_and_token_id(
            token_id2,
            &hex::encode(&mint_tx2_tkn2.prefix.nonce),
            &conn
        )
        .unwrap()
        .is_none());

        // Insert the second MintTx, they should both be found.
        let sql_mint_tx2 = MintTx::insert_from_core_mint_tx(5, None, &mint_tx2, &conn).unwrap();

        assert_eq!(
            MintTx::find_unaudited_mint_tx_by_nonce_and_token_id(
                token_id1,
                &hex::encode(&mint_tx1.prefix.nonce),
                &conn
            )
            .unwrap()
            .unwrap(),
            sql_mint_tx1
        );

        assert_eq!(
            MintTx::find_unaudited_mint_tx_by_nonce_and_token_id(
                token_id1,
                &hex::encode(&mint_tx2.prefix.nonce),
                &conn
            )
            .unwrap()
            .unwrap(),
            sql_mint_tx2
        );
        // This is for a different token_id, so should not be found even though it
        // shares a nonce.
        assert!(MintTx::find_unaudited_mint_tx_by_nonce_and_token_id(
            token_id2,
            &hex::encode(&mint_tx1_tkn2.prefix.nonce),
            &conn
        )
        .unwrap()
        .is_none());
        // This is for a different token_id, so should not be found even though it
        // shares a nonce.
        assert!(MintTx::find_unaudited_mint_tx_by_nonce_and_token_id(
            token_id2,
            &hex::encode(&mint_tx2_tkn2.prefix.nonce),
            &conn
        )
        .unwrap()
        .is_none());

        // Insert the third MintTx and fourth MintTx, they should all be found.
        let sql_mint_tx3 =
            MintTx::insert_from_core_mint_tx(5, None, &mint_tx1_tkn2, &conn).unwrap();
        let sql_mint_tx4 =
            MintTx::insert_from_core_mint_tx(5, None, &mint_tx2_tkn2, &conn).unwrap();
        assert_eq!(
            MintTx::find_unaudited_mint_tx_by_nonce_and_token_id(
                token_id2,
                &hex::encode(&mint_tx1.prefix.nonce),
                &conn
            )
            .unwrap()
            .unwrap(),
            sql_mint_tx3
        );

        assert_eq!(
            MintTx::find_unaudited_mint_tx_by_nonce_and_token_id(
                token_id2,
                &hex::encode(&mint_tx2.prefix.nonce),
                &conn
            )
            .unwrap()
            .unwrap(),
            sql_mint_tx4
        );

        // Insert a row to the `audited_mints` table marking the first MintTx as
        // audited. We should no longer be able to find it.
        insert_gnosis_deposit(&mut deposit1, &conn);
        AuditedMint::associate_deposit_with_mint(
            deposit1.id().unwrap(),
            sql_mint_tx1.id().unwrap(),
            &conn,
        )
        .unwrap();

        assert!(MintTx::find_unaudited_mint_tx_by_nonce_and_token_id(
            token_id1,
            &hex::encode(&mint_tx1.prefix.nonce),
            &conn
        )
        .unwrap()
        .is_none());

        assert_eq!(
            MintTx::find_unaudited_mint_tx_by_nonce_and_token_id(
                token_id1,
                &hex::encode(&mint_tx2.prefix.nonce),
                &conn
            )
            .unwrap()
            .unwrap(),
            sql_mint_tx2
        );
        assert_eq!(
            MintTx::find_unaudited_mint_tx_by_nonce_and_token_id(
                token_id2,
                &hex::encode(&mint_tx1.prefix.nonce),
                &conn
            )
            .unwrap()
            .unwrap(),
            sql_mint_tx3
        );
        assert_eq!(
            MintTx::find_unaudited_mint_tx_by_nonce_and_token_id(
                token_id2,
                &hex::encode(&mint_tx2.prefix.nonce),
                &conn
            )
            .unwrap()
            .unwrap(),
            sql_mint_tx4
        );

        // Mark the second mint as audited. We should no longer be able to find it.
        insert_gnosis_deposit(&mut deposit2, &conn);
        AuditedMint::associate_deposit_with_mint(
            deposit2.id().unwrap(),
            sql_mint_tx2.id().unwrap(),
            &conn,
        )
        .unwrap();

        assert!(MintTx::find_unaudited_mint_tx_by_nonce_and_token_id(
            token_id1,
            &hex::encode(&mint_tx1.prefix.nonce),
            &conn
        )
        .unwrap()
        .is_none());

        assert!(MintTx::find_unaudited_mint_tx_by_nonce_and_token_id(
            token_id1,
            &hex::encode(&mint_tx2.prefix.nonce),
            &conn
        )
        .unwrap()
        .is_none());
        assert_eq!(
            MintTx::find_unaudited_mint_tx_by_nonce_and_token_id(
                token_id2,
                &hex::encode(&mint_tx1.prefix.nonce),
                &conn
            )
            .unwrap()
            .unwrap(),
            sql_mint_tx3
        );
        assert_eq!(
            MintTx::find_unaudited_mint_tx_by_nonce_and_token_id(
                token_id2,
                &hex::encode(&mint_tx2.prefix.nonce),
                &conn
            )
            .unwrap()
            .unwrap(),
            sql_mint_tx4
        );
    }
}
