// Copyright (c) 2018-2022 The MobileCoin Foundation

use crate::{
    db::{
        last_insert_rowid,
        models::{SqlEthAddr, SqlEthTxHash},
        schema::{audited_mints, gnosis_safe_deposits},
        Conn,
    },
    error::Error,
    gnosis::{EthAddr, EthTxHash},
    MintTxNonce,
};
use diesel::{
    dsl::{exists, not},
    prelude::*,
};
use serde::{Deserialize, Serialize};

/// Diesel model for the `gnosis_safe_deposits` table.
/// This table stores deposits into the monitored gnosis safe.
#[derive(
    Clone, Debug, Default, Deserialize, Eq, Hash, Insertable, PartialEq, Queryable, Serialize,
)]
pub struct GnosisSafeDeposit {
    /// Auto incrementing primary key.
    id: Option<i32>,

    /// Ethereum transaction hash.
    eth_tx_hash: SqlEthTxHash,

    /// Ethereum block number.
    eth_block_number: i64,

    /// Gnosis safe address receiving the deposit.
    safe_addr: SqlEthAddr,

    /// Token contract address that is being deposited.
    token_addr: SqlEthAddr,

    /// Amount deposited.
    amount: i64,

    /// The hex-encoded MintTx nonce we expect to see on the MobileCoin
    /// blockchain
    expected_mc_mint_tx_nonce_hex: String,
}

impl GnosisSafeDeposit {
    /// Construct a new [GnosisSafeDeposit] object.
    pub fn new(
        id: Option<i32>,
        eth_tx_hash: EthTxHash,
        eth_block_number: u64,
        safe_addr: EthAddr,
        token_addr: EthAddr,
        amount: u64,
    ) -> Self {
        let expected_mc_mint_tx_nonce = MintTxNonce::EthereumGnosisDeposit(eth_tx_hash);
        let expected_mc_mint_tx_nonce_hex = hex::encode(expected_mc_mint_tx_nonce.to_bytes());
        Self {
            id,
            eth_tx_hash: eth_tx_hash.into(),
            eth_block_number: eth_block_number as i64,
            safe_addr: safe_addr.into(),
            token_addr: token_addr.into(),
            amount: amount as i64,
            expected_mc_mint_tx_nonce_hex,
        }
    }

    /// Get id.
    pub fn id(&self) -> Option<i32> {
        self.id
    }

    /// Get Ethereum transaction hash.
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

    /// Get amount deposited.
    pub fn amount(&self) -> u64 {
        self.amount as u64
    }

    /// Get the hex-encoded MintTx nonce we expect to see on the MobileCoin
    /// blockchain.
    pub fn expected_mc_mint_tx_nonce_hex(&self) -> &str {
        &self.expected_mc_mint_tx_nonce_hex
    }

    /// Insert a deposit into the database.
    pub fn insert(&mut self, conn: &Conn) -> Result<(), Error> {
        if let Some(id) = self.id {
            return Err(Error::AlreadyExists(format!(
                "GnosisSafeDeposit already has an id ({})",
                id
            )));
        }

        diesel::insert_into(gnosis_safe_deposits::table)
            .values(self.clone())
            .execute(conn)?;

        self.id = Some(diesel::select(last_insert_rowid).get_result::<i32>(conn)?);

        Ok(())
    }

    /// Attempt to find all [GnosisSafeDeposit]s that do not have a matching
    /// entry in the `audited_mints` table.
    pub fn find_unaudited_deposits(conn: &Conn) -> Result<Vec<Self>, Error> {
        Ok(gnosis_safe_deposits::table
            .filter(not(exists(
                audited_mints::table
                    .select(audited_mints::gnosis_safe_deposit_id)
                    .filter(
                        audited_mints::gnosis_safe_deposit_id
                            .nullable()
                            .eq(gnosis_safe_deposits::id),
                    ),
            )))
            .load(conn)?)
    }

    /// Attempt to find a [GnosisSafeDeposit] that has a given nonce and no
    /// matching entry in the `audited_mints` table.
    pub fn find_unaudited_deposit_by_nonce_and_token_address(
        token_address: &EthAddr,
        nonce_hex: &str,
        conn: &Conn,
    ) -> Result<Option<Self>, Error> {
        Ok(gnosis_safe_deposits::table
            .filter(gnosis_safe_deposits::token_addr.eq(token_address.clone().0))
            .filter(gnosis_safe_deposits::expected_mc_mint_tx_nonce_hex.eq(nonce_hex))
            .filter(not(exists(
                audited_mints::table
                    .select(audited_mints::gnosis_safe_deposit_id)
                    .filter(
                        audited_mints::gnosis_safe_deposit_id
                            .nullable()
                            .eq(gnosis_safe_deposits::id),
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
        models::{AuditedMint, MintTx},
        test_utils::{
            create_gnosis_safe_deposit, create_gnosis_safe_deposit_alternative_address,
            insert_gnosis_deposit, TestDbContext,
        },
    };
    use mc_common::logger::{test_with_logger, Logger};
    use mc_transaction_core::TokenId;
    use mc_transaction_core_test_utils::{create_mint_config_tx_and_signers, create_mint_tx};

    #[test_with_logger]
    fn test_find_unaudited_deposits_by_nonce(logger: Logger) {
        let test_db_context = TestDbContext::default();
        let mint_auditor_db = test_db_context.get_db_instance(logger.clone());
        let token_id1 = TokenId::from(1);
        let token_id2 = TokenId::from(2);

        let conn = mint_auditor_db.get_conn().unwrap();

        let mut rng = mc_util_test_helper::get_seeded_rng();

        // Create gnosis deposits.
        let mut deposit1 = create_gnosis_safe_deposit(100, &mut rng);
        let mut deposit2 = create_gnosis_safe_deposit(200, &mut rng);
        let mut deposit3 = create_gnosis_safe_deposit_alternative_address(300, &mut rng);
        let mut deposit4 = create_gnosis_safe_deposit_alternative_address(400, &mut rng);

        let nonce1 = deposit1.expected_mc_mint_tx_nonce_hex().to_string();
        let nonce2 = deposit2.expected_mc_mint_tx_nonce_hex().to_string();
        let nonce3 = deposit3.expected_mc_mint_tx_nonce_hex().to_string();
        let nonce4 = deposit4.expected_mc_mint_tx_nonce_hex().to_string();

        // assert_eq!(nonce1, nonce3);
        // assert_eq!(nonce2, nonce4);

        // Create two MintTxs.
        let (_mint_config_tx1, signers1) = create_mint_config_tx_and_signers(token_id1, &mut rng);
        let (_mint_config_tx2, signers2) = create_mint_config_tx_and_signers(token_id2, &mut rng);

        let mut mint_tx1 = create_mint_tx(token_id1, &signers1, 100, &mut rng);
        let mut mint_tx2 = create_mint_tx(token_id1, &signers1, 100, &mut rng);
        let mut mint_tx1_tkn2 = create_mint_tx(token_id2, &signers2, 100, &mut rng);
        let mut mint_tx2_tkn2 = create_mint_tx(token_id2, &signers2, 100, &mut rng);

        mint_tx1.prefix.nonce = hex::decode(&nonce1).unwrap();
        mint_tx2.prefix.nonce = hex::decode(&nonce2).unwrap();
        mint_tx1_tkn2.prefix.nonce = hex::decode(&nonce1).unwrap();
        mint_tx2_tkn2.prefix.nonce = hex::decode(&nonce2).unwrap();

        let sql_mint_tx1 = MintTx::insert_from_core_mint_tx(0, None, &mint_tx1, &conn).unwrap();
        let sql_mint_tx2 = MintTx::insert_from_core_mint_tx(0, None, &mint_tx2, &conn).unwrap();
        let sql_mint_tx3 =
            MintTx::insert_from_core_mint_tx(0, None, &mint_tx1_tkn2, &conn).unwrap();
        let sql_mint_tx4 =
            MintTx::insert_from_core_mint_tx(0, None, &mint_tx2_tkn2, &conn).unwrap();

        // Since they haven't been inserted yet, they should not be found.
        assert!(
            GnosisSafeDeposit::find_unaudited_deposit_by_nonce_and_token_address(
                deposit1.token_addr(),
                &nonce1,
                &conn
            )
            .unwrap()
            .is_none()
        );

        assert!(
            GnosisSafeDeposit::find_unaudited_deposit_by_nonce_and_token_address(
                deposit2.token_addr(),
                &nonce2,
                &conn
            )
            .unwrap()
            .is_none()
        );

        // Insert the first deposit, it should now be found.
        insert_gnosis_deposit(&mut deposit1, &conn);

        assert_eq!(
            GnosisSafeDeposit::find_unaudited_deposit_by_nonce_and_token_address(
                deposit1.token_addr(),
                &nonce1,
                &conn
            )
            .unwrap()
            .unwrap(),
            deposit1
        );
        assert!(
            GnosisSafeDeposit::find_unaudited_deposit_by_nonce_and_token_address(
                deposit2.token_addr(),
                &nonce2,
                &conn
            )
            .unwrap()
            .is_none()
        );

        // Insert the second deposit, they should both be found.
        insert_gnosis_deposit(&mut deposit2, &conn);

        assert_eq!(
            GnosisSafeDeposit::find_unaudited_deposit_by_nonce_and_token_address(
                deposit1.token_addr(),
                &nonce1,
                &conn
            )
            .unwrap()
            .unwrap(),
            deposit1,
        );

        assert_eq!(
            GnosisSafeDeposit::find_unaudited_deposit_by_nonce_and_token_address(
                deposit2.token_addr(),
                &nonce2,
                &conn
            )
            .unwrap()
            .unwrap(),
            deposit2,
        );

        // Insert the token 2 deposits, they should both be found.
        insert_gnosis_deposit(&mut deposit3, &conn);
        insert_gnosis_deposit(&mut deposit4, &conn);
        assert_eq!(
            GnosisSafeDeposit::find_unaudited_deposit_by_nonce_and_token_address(
                deposit3.token_addr(),
                &nonce3,
                &conn
            )
            .unwrap()
            .unwrap(),
            deposit3,
        );

        assert_eq!(
            GnosisSafeDeposit::find_unaudited_deposit_by_nonce_and_token_address(
                deposit4.token_addr(),
                &nonce4,
                &conn
            )
            .unwrap()
            .unwrap(),
            deposit4,
        );

        // Insert a row to the `audited_mints` table marking the first deposit as
        // audited. We should no longer be able to find it.
        AuditedMint::associate_deposit_with_mint(
            deposit1.id().unwrap(),
            sql_mint_tx1.id().unwrap(),
            &conn,
        )
        .unwrap();

        assert!(
            GnosisSafeDeposit::find_unaudited_deposit_by_nonce_and_token_address(
                deposit1.token_addr(),
                &nonce1,
                &conn
            )
            .unwrap()
            .is_none()
        );

        assert_eq!(
            GnosisSafeDeposit::find_unaudited_deposit_by_nonce_and_token_address(
                deposit2.token_addr(),
                &nonce2,
                &conn
            )
            .unwrap()
            .unwrap(),
            deposit2,
        );
        assert_eq!(
            GnosisSafeDeposit::find_unaudited_deposit_by_nonce_and_token_address(
                deposit3.token_addr(),
                &nonce3,
                &conn
            )
            .unwrap()
            .unwrap(),
            deposit3,
        );

        assert_eq!(
            GnosisSafeDeposit::find_unaudited_deposit_by_nonce_and_token_address(
                deposit4.token_addr(),
                &nonce4,
                &conn
            )
            .unwrap()
            .unwrap(),
            deposit4,
        );
        // Mark the second deposit as audited. We should no longer be able to find it.
        AuditedMint::associate_deposit_with_mint(
            deposit2.id().unwrap(),
            sql_mint_tx2.id().unwrap(),
            &conn,
        )
        .unwrap();

        assert!(
            GnosisSafeDeposit::find_unaudited_deposit_by_nonce_and_token_address(
                deposit1.token_addr(),
                &nonce1,
                &conn
            )
            .unwrap()
            .is_none()
        );

        assert!(
            GnosisSafeDeposit::find_unaudited_deposit_by_nonce_and_token_address(
                deposit2.token_addr(),
                &nonce2,
                &conn
            )
            .unwrap()
            .is_none()
        );
        assert_eq!(
            GnosisSafeDeposit::find_unaudited_deposit_by_nonce_and_token_address(
                deposit3.token_addr(),
                &nonce3,
                &conn
            )
            .unwrap()
            .unwrap(),
            deposit3,
        );

        assert_eq!(
            GnosisSafeDeposit::find_unaudited_deposit_by_nonce_and_token_address(
                deposit4.token_addr(),
                &nonce4,
                &conn
            )
            .unwrap()
            .unwrap(),
            deposit4,
        );

        // Insert a row to the `audited_mints` table marking the token2 deposits as
        // audited. We should no longer be able to find them.
        AuditedMint::associate_deposit_with_mint(
            deposit3.id().unwrap(),
            sql_mint_tx3.id().unwrap(),
            &conn,
        )
        .unwrap();
        AuditedMint::associate_deposit_with_mint(
            deposit4.id().unwrap(),
            sql_mint_tx4.id().unwrap(),
            &conn,
        )
        .unwrap();
        assert!(
            GnosisSafeDeposit::find_unaudited_deposit_by_nonce_and_token_address(
                deposit3.token_addr(),
                &nonce3,
                &conn
            )
            .unwrap()
            .is_none()
        );

        assert!(
            GnosisSafeDeposit::find_unaudited_deposit_by_nonce_and_token_address(
                deposit4.token_addr(),
                &nonce4,
                &conn
            )
            .unwrap()
            .is_none()
        );
    }
}
