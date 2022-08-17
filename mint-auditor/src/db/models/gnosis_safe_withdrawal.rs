// Copyright (c) 2018-2022 The MobileCoin FoundationD
//

use crate::{
    db::{
        last_insert_rowid,
        models::{SqlEthAddr, SqlEthTxHash},
        schema::{audited_burns, gnosis_safe_withdrawals},
        Conn,
    },
    error::Error,
    gnosis::{EthAddr, EthTxHash},
};
use diesel::{
    dsl::{exists, not},
    prelude::*,
};
use mc_crypto_keys::CompressedRistrettoPublic;
use serde::{Deserialize, Serialize};

/// Diesel model for the `gnosis_safe_withdrawals` table.
/// This table stores withdrawals into the monitored gnosis safe.
#[derive(
    Clone, Debug, Default, Deserialize, Eq, Hash, Insertable, PartialEq, Queryable, Serialize,
)]
pub struct GnosisSafeWithdrawal {
    /// Id (required to keep Diesel happy).
    id: Option<i32>,

    /// Ethereum transaction hash.
    eth_tx_hash: SqlEthTxHash,

    /// Ethereum block number.
    eth_block_number: i64,

    /// Gnosis safe address being withdrawn from.
    safe_addr: SqlEthAddr,

    /// Token contract address that is being withdrawn.
    token_addr: SqlEthAddr,

    /// Amount withdrawan.
    amount: i64,

    /// Associated mobilecoin transaction public key (hex-encoded).
    mc_tx_out_public_key_hex: String,
}

impl GnosisSafeWithdrawal {
    /// Construct a new [GnosisSafeWithdrawal] object.
    pub fn new(
        id: Option<i32>,
        eth_tx_hash: EthTxHash,
        eth_block_number: u64,
        safe_addr: EthAddr,
        token_addr: EthAddr,
        amount: u64,
        mc_tx_out_public_key_hex: String,
    ) -> Self {
        Self {
            id,
            eth_tx_hash: eth_tx_hash.into(),
            eth_block_number: eth_block_number as i64,
            safe_addr: safe_addr.into(),
            token_addr: token_addr.into(),
            amount: amount as i64,
            mc_tx_out_public_key_hex,
        }
    }

    /// Get id.
    pub fn id(&self) -> Option<i32> {
        self.id
    }

    /// Get ethereum transaction hash.
    pub fn eth_tx_hash(&self) -> &EthTxHash {
        &self.eth_tx_hash
    }

    /// Get ethereum block number.
    pub fn eth_block_number(&self) -> u64 {
        self.eth_block_number as u64
    }

    /// Get safe address.
    pub fn safe_addr(&self) -> &EthAddr {
        &self.safe_addr
    }

    /// Get token address.
    pub fn token_addr(&self) -> &EthAddr {
        &self.token_addr
    }

    /// Get amount withdrawan.
    pub fn amount(&self) -> u64 {
        self.amount as u64
    }

    /// Get associated mobilecoin transaction public key (hex-encoded).
    pub fn mc_tx_out_public_key_hex(&self) -> &str {
        &self.mc_tx_out_public_key_hex
    }

    /// Get the associated mobilecoin transaction public key
    pub fn mc_tx_out_public_key(&self) -> Result<CompressedRistrettoPublic, Error> {
        let key_bytes = hex::decode(&self.mc_tx_out_public_key_hex)?;
        Ok(CompressedRistrettoPublic::try_from(&key_bytes[..])?)
    }

    /// Insert a withdrawal into the database.
    pub fn insert(&mut self, conn: &Conn) -> Result<(), Error> {
        if let Some(id) = self.id {
            return Err(Error::AlreadyExists(format!(
                "GnosisSafeWithdrawal already has an id ({})",
                id
            )));
        }

        diesel::insert_into(gnosis_safe_withdrawals::table)
            .values(self.clone())
            .execute(conn)?;

        self.id = Some(diesel::select(last_insert_rowid).get_result::<i32>(conn)?);

        Ok(())
    }

    /// Attempt to find a [GnosisSafeWithdrawal] that has a given nonce and no
    /// matching entry in the `audited_burns` table.
    pub fn find_unaudited_withdrawal_by_public_key(
        public_key_hex: &str,
        conn: &Conn,
    ) -> Result<Option<Self>, Error> {
        Ok(gnosis_safe_withdrawals::table
            .filter(gnosis_safe_withdrawals::mc_tx_out_public_key_hex.eq(public_key_hex))
            .filter(not(exists(
                audited_burns::table
                    .select(audited_burns::gnosis_safe_withdrawal_id)
                    .filter(
                        audited_burns::gnosis_safe_withdrawal_id
                            .nullable()
                            .eq(gnosis_safe_withdrawals::id),
                    ),
            )))
            .first(conn)
            .optional()?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::{
        models::AuditedBurn,
        test_utils::{
            create_and_insert_burn_tx_out, create_gnosis_safe_withdrawal_from_burn_tx_out,
            insert_gnosis_withdrawal, TestDbContext,
        },
    };
    use mc_common::logger::{test_with_logger, Logger};
    use mc_transaction_core::TokenId;

    #[test_with_logger]
    fn test_find_unaudited_withdrawal_by_public_key(logger: Logger) {
        let mut rng = mc_util_test_helper::get_seeded_rng();
        let test_db_context = TestDbContext::default();
        let mint_auditor_db = test_db_context.get_db_instance(logger.clone());
        let token_id = TokenId::from(1);
        let conn = mint_auditor_db.get_conn().unwrap();

        // Create two BurnTxOuts.
        let burn_tx_out1 = create_and_insert_burn_tx_out(token_id, 100, &conn, &mut rng);
        let burn_tx_out2 = create_and_insert_burn_tx_out(token_id, 100, &conn, &mut rng);

        // Create two Gnosis withdrawals.
        let mut withdrawal1 =
            create_gnosis_safe_withdrawal_from_burn_tx_out(&burn_tx_out1, &mut rng);
        let mut withdrawal2 =
            create_gnosis_safe_withdrawal_from_burn_tx_out(&burn_tx_out2, &mut rng);

        // Since they haven't been inserted yet, they should not be found.
        assert!(
            GnosisSafeWithdrawal::find_unaudited_withdrawal_by_public_key(
                burn_tx_out1.public_key_hex(),
                &conn
            )
            .unwrap()
            .is_none()
        );

        assert!(
            GnosisSafeWithdrawal::find_unaudited_withdrawal_by_public_key(
                burn_tx_out2.public_key_hex(),
                &conn
            )
            .unwrap()
            .is_none()
        );

        // Insert the first withdrawal, it should now be found.
        insert_gnosis_withdrawal(&mut withdrawal1, &conn);

        assert_eq!(
            GnosisSafeWithdrawal::find_unaudited_withdrawal_by_public_key(
                burn_tx_out1.public_key_hex(),
                &conn
            )
            .unwrap()
            .unwrap(),
            withdrawal1
        );
        assert!(
            GnosisSafeWithdrawal::find_unaudited_withdrawal_by_public_key(
                burn_tx_out2.public_key_hex(),
                &conn
            )
            .unwrap()
            .is_none()
        );

        // Insert the second withdrawal, they should both be found.
        insert_gnosis_withdrawal(&mut withdrawal2, &conn);

        assert_eq!(
            GnosisSafeWithdrawal::find_unaudited_withdrawal_by_public_key(
                burn_tx_out1.public_key_hex(),
                &conn
            )
            .unwrap()
            .unwrap(),
            withdrawal1,
        );

        assert_eq!(
            GnosisSafeWithdrawal::find_unaudited_withdrawal_by_public_key(
                burn_tx_out2.public_key_hex(),
                &conn
            )
            .unwrap()
            .unwrap(),
            withdrawal2,
        );

        // Insert a row to the `audited_burns` table marking the first withdrawal as
        // audited. We should no longer be able to find it.
        AuditedBurn::associate_withdrawal_with_burn(
            withdrawal1.id().unwrap(),
            burn_tx_out1.id().unwrap(),
            &conn,
        )
        .unwrap();

        assert!(
            GnosisSafeWithdrawal::find_unaudited_withdrawal_by_public_key(
                burn_tx_out1.public_key_hex(),
                &conn
            )
            .unwrap()
            .is_none()
        );

        assert_eq!(
            GnosisSafeWithdrawal::find_unaudited_withdrawal_by_public_key(
                burn_tx_out2.public_key_hex(),
                &conn
            )
            .unwrap()
            .unwrap(),
            withdrawal2,
        );

        // Mark the second withdrawal as audited. We should no longer be able to find
        // it.
        AuditedBurn::associate_withdrawal_with_burn(
            withdrawal2.id().unwrap(),
            burn_tx_out2.id().unwrap(),
            &conn,
        )
        .unwrap();

        assert!(
            GnosisSafeWithdrawal::find_unaudited_withdrawal_by_public_key(
                burn_tx_out1.public_key_hex(),
                &conn
            )
            .unwrap()
            .is_none()
        );

        assert!(
            GnosisSafeWithdrawal::find_unaudited_withdrawal_by_public_key(
                burn_tx_out2.public_key_hex(),
                &conn
            )
            .unwrap()
            .is_none()
        );
    }
}
