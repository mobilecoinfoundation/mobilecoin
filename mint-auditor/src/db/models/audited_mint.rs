// Copyright (c) 2018-2022 The MobileCoin Foundation

use crate::{
    db::{
        schema::{audited_mints, gnosis_safe_deposits, mint_txs},
        transaction, Conn, Counters, GnosisSafeDeposit, MintTx,
    },
    gnosis::{AuditedSafeConfig, GnosisSafeConfig},
    Error,
};
use diesel::prelude::*;
use serde::{Deserialize, Serialize};

/// Diesel model for the `audited_mints` table.
/// This stores audit data linking MintTxs with matching GnosisSafeDeposits.
#[derive(Clone, Debug, Deserialize, Eq, Hash, Insertable, PartialEq, Queryable, Serialize)]
pub struct AuditedMint {
    /// Id (required to keep Diesel happy).
    pub id: Option<i32>,

    /// Id pointing to the MintTx table.
    pub mint_tx_id: i32,

    /// Id pointing to the GnosisSafeDeposit table.
    pub gnosis_safe_deposit_id: i32,
}

impl AuditedMint {
    /// Attempt to find a matching [MintTx] for a given [GnosisSafeDeposit], and
    /// if successful return the [MintTx] and record the match in the
    /// database. Note that each [MintTx] can be matched to at most one
    /// [GnosisSafeDeposit], so calling this repeatedly over the same
    /// deposit will fail.
    pub fn try_match_deposit_with_mint(
        deposit: &GnosisSafeDeposit,
        config: &AuditedSafeConfig,
        conn: &Conn,
    ) -> Result<MintTx, Error> {
        // Wrapped in a closure to allow using the ? operator without returning from the
        // function.
        let result = || -> Result<MintTx, Error> {
            // We only operate on objects that were saved to the database.
            let deposit_id = deposit.id().ok_or(Error::ObjectNotSaved)?;

            // The deposit safe needs to match the audited safe configuration.
            // This shouldn't happen and indicates misuse of this function.
            if deposit.safe_addr() != &config.safe_addr {
                return Err(Error::Other(format!(
                    "Gnosis safe deposit addr {} does not match audited safe addr {}",
                    deposit.safe_addr(),
                    config.safe_addr
                )));
            }

            transaction(conn, |conn| {
                // Currently we only support 1:1 mapping between deposits and mints, so ensure
                // that there isn't already a match for this deposit.
                let existing_match: Option<(String, String)> = audited_mints::table
                    .inner_join(mint_txs::table)
                    .inner_join(gnosis_safe_deposits::table)
                    .select((mint_txs::nonce_hex, gnosis_safe_deposits::eth_tx_hash))
                    .filter(audited_mints::gnosis_safe_deposit_id.eq(deposit_id))
                    .first(conn)
                    .optional()?;
                if let Some((nonce_hex, eth_tx_hash)) = existing_match {
                    Counters::inc_num_unexpected_errors_matching_deposits_to_mints(conn)?;
                    return Err(Error::AlreadyExists(format!(
                        "GnosisSafeDeposit eth_tx_hash={} already matched with mint_tx nonce={}",
                        eth_tx_hash, nonce_hex,
                    )));
                }

                // See if we can find a MintTx that matches the expected nonce and has not been
                // associated with a deposit.
                let mint_tx = MintTx::find_unaudited_mint_tx_by_nonce(
                    deposit.expected_mc_mint_tx_nonce_hex(),
                    conn,
                )?
                .ok_or(Error::NotFound)?;

                // Check that the mint and deposit details match.
                Self::verify_mint_tx_matches_deposit(&mint_tx, deposit, config)?;

                // Associate the deposit with the mint.
                Self::associate_deposit_with_mint(
                    deposit_id,
                    mint_tx
                        .id()
                        .expect("got a MintTx without id but database auto-populates that field"),
                    conn,
                )?;

                Ok(mint_tx)
            })
        }();

        // Count certain errors. This needs to happen outside of the transaction because
        // errors result in the transaction getting rolled back.
        match result {
            Ok(_) => {}

            Err(Error::DepositAndMintMismatch(_)) => {
                Counters::inc_num_mismatching_mints_and_deposits(conn)?;
            }

            Err(Error::EthereumTokenNotAudited(_, _, _)) => {
                Counters::inc_num_unknown_ethereum_token_deposits(conn)?;
            }

            Err(_) => {
                Counters::inc_num_unexpected_errors_matching_deposits_to_mints(conn)?;
            }
        }

        result
    }

    /// Attempt to find a matching [GnosisSafeDeposit] for a given [MintTx], and
    /// if successful return the [GnosisSafeDeposit] and record the match in the
    /// database. Note that each [GnosisSafeDeposit] can be matched to at
    /// most one [MintTx], so calling this repeatedly over the same [MintTx]
    /// will fail.
    pub fn try_match_mint_with_deposit(
        mint_tx: &MintTx,
        config: &GnosisSafeConfig,
        conn: &Conn,
    ) -> Result<GnosisSafeDeposit, Error> {
        // Wrapped in a closure to allow using the ? operator without returning from the
        // function.
        let result = || -> Result<GnosisSafeDeposit, Error> {
            // We only operate on objects that were saved to the database.
            let mint_tx_id = mint_tx.id().ok_or(Error::ObjectNotSaved)?;

            transaction(conn, |conn| -> Result<GnosisSafeDeposit, Error> {
                // Currently we only support 1:1 mapping between deposits and mints, so ensure
                // that there isn't already a match for this mint.
                let existing_match: Option<(String, String)> = audited_mints::table
                    .inner_join(mint_txs::table)
                    .inner_join(gnosis_safe_deposits::table)
                    .select((mint_txs::nonce_hex, gnosis_safe_deposits::eth_tx_hash))
                    .filter(audited_mints::mint_tx_id.eq(mint_tx_id))
                    .first(conn)
                    .optional()?;
                if let Some((nonce_hex, eth_tx_hash)) = existing_match {
                    return Err(Error::AlreadyExists(format!(
                        "MintTx nonce={} already matched with GnosisSafeDeposit eth_tx_hash={}",
                        nonce_hex, eth_tx_hash,
                    )));
                }

                // See if we can find a GnosisSafeDeposit that matches the nonce and has not
                // been associated with a mint.
                let deposit =
                    GnosisSafeDeposit::find_unaudited_deposit_by_nonce(mint_tx.nonce_hex(), conn)?
                        .ok_or(Error::NotFound)?;

                // See if the deposit we found is for a safe we are auditing.
                let audited_safe_config = config
                    .get_audited_safe_config_by_safe_addr(deposit.safe_addr())
                    .ok_or_else(|| Error::GnosisSafeNotAudited(deposit.safe_addr().clone()))?;

                // See if they match.
                Self::verify_mint_tx_matches_deposit(mint_tx, &deposit, &audited_safe_config)?;

                // Associate the mint with the deposit.
                Self::associate_deposit_with_mint(
                    deposit.id().expect(
                        "got a GnosisSafeDeposit without id but database auto-populates that field",
                    ),
                    mint_tx_id,
                    conn,
                )?;

                Ok(deposit)
            })
        }();

        // Count certain errors. This needs to happen outside of the transaction because
        // errors result in the transaction getting rolled back.
        match result {
            Ok(_) => {}

            Err(Error::GnosisSafeNotAudited(_)) => {
                Counters::inc_num_mints_to_unknown_safe(conn)?;
            }

            Err(Error::DepositAndMintMismatch(_)) => {
                Counters::inc_num_mismatching_mints_and_deposits(conn)?;
            }

            Err(Error::EthereumTokenNotAudited(_, _, _)) => {
                Counters::inc_num_unknown_ethereum_token_deposits(conn)?;
            }

            Err(_) => {
                Counters::inc_num_unexpected_errors_matching_mints_to_deposits(conn)?;
            }
        }

        result
    }

    /// Verify that the details of a MintTx match the details of a
    /// GnosisSafeDeposit (amount/nonce/token).
    fn verify_mint_tx_matches_deposit(
        mint_tx: &MintTx,
        deposit: &GnosisSafeDeposit,
        config: &AuditedSafeConfig,
    ) -> Result<(), Error> {
        // The deposit safe needs to match the audited safe configuration.
        // This shouldn't happen and indicates misuse of this function.
        if deposit.safe_addr() != &config.safe_addr {
            return Err(Error::Other(format!(
                "Gnosis safe deposit addr {} does not match audited safe addr {}",
                deposit.safe_addr(),
                config.safe_addr
            )));
        }

        // Nonces should match.
        if mint_tx.nonce_hex() != deposit.expected_mc_mint_tx_nonce_hex() {
            return Err(Error::DepositAndMintMismatch(format!(
                "MintTx nonce {} does not match expected nonce {}",
                mint_tx.nonce_hex(),
                deposit.expected_mc_mint_tx_nonce_hex()
            )));
        }

        // Check to see if the amount matches the deposit.
        if mint_tx.amount() != deposit.amount() {
            return Err(Error::DepositAndMintMismatch(format!(
                "MintTx amount={} does not match GnosisSafeDeposit amount={} (nonce={})",
                mint_tx.amount(),
                deposit.amount(),
                deposit.expected_mc_mint_tx_nonce_hex(),
            )));
        }

        // Check and see if the tokens match.
        let audited_token = config
            .get_token_by_eth_contract_addr(deposit.token_addr())
            .ok_or_else(|| {
                Error::EthereumTokenNotAudited(
                    deposit.token_addr().clone(),
                    deposit.safe_addr().clone(),
                    *deposit.eth_tx_hash(),
                )
            })?;

        if audited_token.token_id != mint_tx.token_id() {
            return Err(Error::DepositAndMintMismatch(format!(
                "MintTx token_id={} does not match audited token_id={} (nonce={})",
                mint_tx.token_id(),
                audited_token.token_id,
                deposit.expected_mc_mint_tx_nonce_hex(),
            )));
        }

        Ok(())
    }

    // This is pub(crate) since its used in tests.
    pub(crate) fn associate_deposit_with_mint(
        gnosis_safe_deposit_id: i32,
        mint_tx_id: i32,
        conn: &Conn,
    ) -> Result<(), Error> {
        let audited_mint = Self {
            id: None,
            mint_tx_id,
            gnosis_safe_deposit_id,
        };
        let _ = diesel::insert_into(audited_mints::table)
            .values(&audited_mint)
            .execute(conn)?;

        Ok(())
    }

    /// Get paginated list of audited mints
    pub fn list_with_mint_and_deposit(
        offset: Option<u64>,
        limit: Option<u64>,
        conn: &Conn,
    ) -> Result<Vec<(AuditedMint, MintTx, GnosisSafeDeposit)>, Error> {
        let mut query = audited_mints::table
            .into_boxed()
            .inner_join(mint_txs::table)
            .inner_join(gnosis_safe_deposits::table);

        if let (Some(o), Some(l)) = (offset, limit) {
            query = query.offset(o as i64).limit(l as i64);
        }

        Ok(query
            .select((
                audited_mints::all_columns,
                mint_txs::all_columns,
                gnosis_safe_deposits::all_columns,
            ))
            .load(conn)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        db::{
            models::AuditedMint,
            test_utils::{
                create_gnosis_safe_deposit, insert_gnosis_deposit, insert_mint_tx_from_deposit,
                test_gnosis_config, TestDbContext,
            },
        },
        gnosis::EthAddr,
    };
    use mc_common::logger::{test_with_logger, Logger};
    use mc_transaction_core::TokenId;
    use mc_transaction_core_test_utils::{create_mint_config_tx_and_signers, create_mint_tx};
    use std::str::FromStr;

    fn assert_audited_mints_table_is_empty(conn: &Conn) {
        let num_rows: i64 = audited_mints::table
            .select(diesel::dsl::count(audited_mints::id))
            .first(conn)
            .unwrap();
        assert_eq!(num_rows, 0);
    }

    #[test_with_logger]
    fn test_try_match_deposit_with_mint_happy_flow(logger: Logger) {
        let config = &test_gnosis_config().safes[0];
        let mut rng = mc_util_test_helper::get_seeded_rng();
        let test_db_context = TestDbContext::default();
        let mint_auditor_db = test_db_context.get_db_instance(logger.clone());
        let conn = mint_auditor_db.get_conn().unwrap();

        // Create gnosis deposits.
        let mut deposit1 = create_gnosis_safe_deposit(100, &mut rng);
        let mut deposit2 = create_gnosis_safe_deposit(200, &mut rng);

        insert_gnosis_deposit(&mut deposit1, &conn);
        insert_gnosis_deposit(&mut deposit2, &conn);

        // Initially the database is empty.
        assert!(matches!(
            AuditedMint::try_match_deposit_with_mint(&deposit1, config, &conn),
            Err(Error::NotFound)
        ));
        assert!(matches!(
            AuditedMint::try_match_deposit_with_mint(&deposit2, config, &conn),
            Err(Error::NotFound)
        ));
        assert_audited_mints_table_is_empty(&conn);

        // Insert the first MintTx to the database, we should get a match now.
        let sql_mint_tx1 = insert_mint_tx_from_deposit(&deposit1, &conn, &mut rng);
        assert_eq!(
            sql_mint_tx1,
            AuditedMint::try_match_deposit_with_mint(&deposit1, config, &conn).unwrap()
        );
        assert!(matches!(
            AuditedMint::try_match_deposit_with_mint(&deposit2, config, &conn),
            Err(Error::NotFound)
        ));

        // Insert the second MintTx to the database, we should get a match on both.
        let sql_mint_tx2 = insert_mint_tx_from_deposit(&deposit2, &conn, &mut rng);
        assert!(matches!(
            AuditedMint::try_match_deposit_with_mint(&deposit1, config, &conn),
            Err(Error::AlreadyExists(_))
        ));
        assert_eq!(
            sql_mint_tx2,
            AuditedMint::try_match_deposit_with_mint(&deposit2, config, &conn).unwrap()
        );

        // Trying again should return AlreadyExists
        assert!(matches!(
            AuditedMint::try_match_deposit_with_mint(&deposit2, config, &conn),
            Err(Error::AlreadyExists(_))
        ));

        // No mismatching pairs were found.
        assert_eq!(
            Counters::get(&conn)
                .unwrap()
                .num_mismatching_mints_and_deposits(),
            0
        );
    }

    #[test_with_logger]
    fn test_try_match_deposit_with_mint_amount_mismatch(logger: Logger) {
        let config = &test_gnosis_config().safes[0];
        let mut rng = mc_util_test_helper::get_seeded_rng();
        let test_db_context = TestDbContext::default();
        let mint_auditor_db = test_db_context.get_db_instance(logger.clone());
        let token_id1 = config.tokens[0].token_id;
        let conn = mint_auditor_db.get_conn().unwrap();

        // Create gnosis deposit.
        let mut deposit = create_gnosis_safe_deposit(100, &mut rng);
        insert_gnosis_deposit(&mut deposit, &conn);

        // Create MintTxs with a mismatching amount.
        let (_mint_config_tx, signers) = create_mint_config_tx_and_signers(token_id1, &mut rng);
        let mut mint_tx = create_mint_tx(token_id1, &signers, deposit.amount() + 1, &mut rng);

        mint_tx.prefix.nonce = hex::decode(&deposit.expected_mc_mint_tx_nonce_hex()).unwrap();

        // Insert the MintTx to the database, and check that the mismatch is
        // detected.
        MintTx::insert_from_core_mint_tx(0, None, &mint_tx, &conn).unwrap();
        assert!(matches!(
            AuditedMint::try_match_deposit_with_mint(&deposit, config, &conn),
            Err(Error::DepositAndMintMismatch(_))
        ));

        // Check that nothing was written to the `audited_mints` table
        assert_audited_mints_table_is_empty(&conn);

        // Mismatch counter was incremented
        assert_eq!(
            Counters::get(&conn)
                .unwrap()
                .num_mismatching_mints_and_deposits(),
            1
        );
    }

    #[test_with_logger]
    fn test_try_match_deposit_with_mint_unsaved_object(logger: Logger) {
        let config = &test_gnosis_config().safes[0];
        let mut rng = mc_util_test_helper::get_seeded_rng();
        let test_db_context = TestDbContext::default();
        let mint_auditor_db = test_db_context.get_db_instance(logger.clone());
        let conn = mint_auditor_db.get_conn().unwrap();

        let deposit = create_gnosis_safe_deposit(100, &mut rng);

        assert!(matches!(
            AuditedMint::try_match_deposit_with_mint(&deposit, config, &conn),
            Err(Error::ObjectNotSaved)
        ));

        // Check that nothing was written to the `audited_mints` table
        assert_audited_mints_table_is_empty(&conn);

        assert_eq!(
            Counters::get(&conn)
                .unwrap()
                .num_unexpected_errors_matching_deposits_to_mints(),
            1
        );
    }

    #[test_with_logger]
    fn test_try_match_deposit_with_mint_mismatched_safe_addr(logger: Logger) {
        let mut config = test_gnosis_config().safes[0].clone();
        let mut rng = mc_util_test_helper::get_seeded_rng();
        let test_db_context = TestDbContext::default();
        let mint_auditor_db = test_db_context.get_db_instance(logger.clone());
        let conn = mint_auditor_db.get_conn().unwrap();

        let mut deposit = create_gnosis_safe_deposit(100, &mut rng);
        insert_gnosis_deposit(&mut deposit, &conn);
        insert_mint_tx_from_deposit(&deposit, &conn, &mut rng);

        config.safe_addr = EthAddr::from_str("0x0000000000000000000000000000000000000000").unwrap();
        assert!(matches!(
            AuditedMint::try_match_deposit_with_mint(&deposit, &config, &conn),
            Err(Error::Other(_))
        ));

        // Check that nothing was written to the `audited_mints` table
        assert_audited_mints_table_is_empty(&conn);

        assert_eq!(
            Counters::get(&conn)
                .unwrap()
                .num_unexpected_errors_matching_deposits_to_mints(),
            1
        );
    }

    #[test_with_logger]
    fn test_try_match_deposit_with_mint_mismatched_token_id(logger: Logger) {
        let mut config = test_gnosis_config().safes[0].clone();
        let mut rng = mc_util_test_helper::get_seeded_rng();
        let test_db_context = TestDbContext::default();
        let mint_auditor_db = test_db_context.get_db_instance(logger.clone());
        let conn = mint_auditor_db.get_conn().unwrap();

        let mut deposit = create_gnosis_safe_deposit(100, &mut rng);
        insert_gnosis_deposit(&mut deposit, &conn);
        insert_mint_tx_from_deposit(&deposit, &conn, &mut rng);

        config.tokens[0].token_id = TokenId::from(123);

        assert!(matches!(
            AuditedMint::try_match_deposit_with_mint(&deposit, &config, &conn),
            Err(Error::DepositAndMintMismatch(_))
        ));

        // Check that nothing was written to the `audited_mints` table
        assert_audited_mints_table_is_empty(&conn);

        // Mismatch counter was incremented
        assert_eq!(
            Counters::get(&conn)
                .unwrap()
                .num_mismatching_mints_and_deposits(),
            1
        );
    }

    #[test_with_logger]
    fn test_try_match_deposit_with_mint_mismatched_token_addr(logger: Logger) {
        let mut config = test_gnosis_config().safes[0].clone();
        let mut rng = mc_util_test_helper::get_seeded_rng();
        let test_db_context = TestDbContext::default();
        let mint_auditor_db = test_db_context.get_db_instance(logger.clone());
        let conn = mint_auditor_db.get_conn().unwrap();

        let mut deposit = create_gnosis_safe_deposit(100, &mut rng);
        insert_gnosis_deposit(&mut deposit, &conn);
        insert_mint_tx_from_deposit(&deposit, &conn, &mut rng);

        config.tokens[0].eth_token_contract_addr =
            EthAddr::from_str("0x0000000000000000000000000000000000000000").unwrap();

        assert!(matches!(
            AuditedMint::try_match_deposit_with_mint(&deposit, &config, &conn),
            Err(Error::EthereumTokenNotAudited(_, _, _))
        ));

        // Check that nothing was written to the `audited_mints` table
        assert_audited_mints_table_is_empty(&conn);

        assert_eq!(
            Counters::get(&conn)
                .unwrap()
                .num_unknown_ethereum_token_deposits(),
            1
        );
    }

    #[test_with_logger]
    fn test_try_match_mint_with_deposit_happy_flow(logger: Logger) {
        let config = test_gnosis_config();
        let mut rng = mc_util_test_helper::get_seeded_rng();
        let test_db_context = TestDbContext::default();
        let mint_auditor_db = test_db_context.get_db_instance(logger.clone());
        let conn = mint_auditor_db.get_conn().unwrap();

        // Create gnosis deposits (that are not yet in the database).
        let mut deposit1 = create_gnosis_safe_deposit(100, &mut rng);
        let mut deposit2 = create_gnosis_safe_deposit(200, &mut rng);

        // Create MintTxs.
        let sql_mint_tx1 = insert_mint_tx_from_deposit(&deposit1, &conn, &mut rng);
        let sql_mint_tx2 = insert_mint_tx_from_deposit(&deposit2, &conn, &mut rng);

        // Initially the database is empty.
        assert!(matches!(
            AuditedMint::try_match_mint_with_deposit(&sql_mint_tx1, &config, &conn),
            Err(Error::NotFound)
        ));
        assert!(matches!(
            AuditedMint::try_match_mint_with_deposit(&sql_mint_tx2, &config, &conn),
            Err(Error::NotFound)
        ));
        assert_audited_mints_table_is_empty(&conn);

        // Insert the first deposit to the database, we should get a match now.
        insert_gnosis_deposit(&mut deposit1, &conn);

        assert_eq!(
            deposit1,
            AuditedMint::try_match_mint_with_deposit(&sql_mint_tx1, &config, &conn).unwrap()
        );
        assert!(matches!(
            AuditedMint::try_match_mint_with_deposit(&sql_mint_tx2, &config, &conn),
            Err(Error::NotFound)
        ));

        // Insert the second deposit to the database, we should get a match on both.
        insert_gnosis_deposit(&mut deposit2, &conn);

        assert!(matches!(
            AuditedMint::try_match_mint_with_deposit(&sql_mint_tx1, &config, &conn),
            Err(Error::AlreadyExists(_))
        ));
        assert_eq!(
            deposit2,
            AuditedMint::try_match_mint_with_deposit(&sql_mint_tx2, &config, &conn).unwrap()
        );

        // Trying again should return AlreadyExists
        assert!(matches!(
            AuditedMint::try_match_mint_with_deposit(&sql_mint_tx2, &config, &conn),
            Err(Error::AlreadyExists(_))
        ));

        // No mismatching pairs were found.
        assert_eq!(
            Counters::get(&conn)
                .unwrap()
                .num_mismatching_mints_and_deposits(),
            0
        );
    }

    #[test_with_logger]
    fn test_try_match_mint_with_deposit_amount_mismatch(logger: Logger) {
        let config = test_gnosis_config();
        let mut rng = mc_util_test_helper::get_seeded_rng();
        let test_db_context = TestDbContext::default();
        let mint_auditor_db = test_db_context.get_db_instance(logger.clone());
        let token_id1 = config.safes[0].tokens[0].token_id;
        let conn = mint_auditor_db.get_conn().unwrap();

        // Create gnosis deposit.
        let mut deposit = create_gnosis_safe_deposit(100, &mut rng);
        insert_gnosis_deposit(&mut deposit, &conn);

        // Create  MintTxs with a mismatching amount.
        let (_mint_config_tx, signers) = create_mint_config_tx_and_signers(token_id1, &mut rng);
        let mut mint_tx = create_mint_tx(token_id1, &signers, deposit.amount() + 1, &mut rng);

        mint_tx.prefix.nonce = hex::decode(&deposit.expected_mc_mint_tx_nonce_hex()).unwrap();

        let sql_mint_tx = MintTx::insert_from_core_mint_tx(0, None, &mint_tx, &conn).unwrap();

        // Check that the mismatch is detected.
        assert!(matches!(
            AuditedMint::try_match_mint_with_deposit(&sql_mint_tx, &config, &conn),
            Err(Error::DepositAndMintMismatch(_))
        ));

        // Check that nothing was written to the `audited_mints` table
        assert_audited_mints_table_is_empty(&conn);

        // Mismatch counter was incremented
        assert_eq!(
            Counters::get(&conn)
                .unwrap()
                .num_mismatching_mints_and_deposits(),
            1
        );
    }

    #[test_with_logger]
    fn test_try_match_mint_with_deposit_unsaved_object(logger: Logger) {
        let config = test_gnosis_config();
        let mut rng = mc_util_test_helper::get_seeded_rng();
        let test_db_context = TestDbContext::default();
        let mint_auditor_db = test_db_context.get_db_instance(logger.clone());
        let token_id1 = config.safes[0].tokens[0].token_id;
        let conn = mint_auditor_db.get_conn().unwrap();

        let (_mint_config_tx, signers) = create_mint_config_tx_and_signers(token_id1, &mut rng);
        let mint_tx = create_mint_tx(token_id1, &signers, 100, &mut rng);
        let sql_mint_tx = MintTx::from_core_mint_tx(0, None, &mint_tx).unwrap();

        assert!(matches!(
            AuditedMint::try_match_mint_with_deposit(&sql_mint_tx, &config, &conn),
            Err(Error::ObjectNotSaved)
        ));

        // Check that nothing was written to the `audited_mints` table
        assert_audited_mints_table_is_empty(&conn);

        assert_eq!(
            Counters::get(&conn)
                .unwrap()
                .num_unexpected_errors_matching_mints_to_deposits(),
            1
        );
    }

    #[test_with_logger]
    fn test_try_match_mint_with_deposit_mismatched_safe_addr(logger: Logger) {
        let mut config = test_gnosis_config();
        let mut rng = mc_util_test_helper::get_seeded_rng();
        let test_db_context = TestDbContext::default();
        let mint_auditor_db = test_db_context.get_db_instance(logger.clone());
        let conn = mint_auditor_db.get_conn().unwrap();

        let mut deposit = create_gnosis_safe_deposit(100, &mut rng);
        insert_gnosis_deposit(&mut deposit, &conn);

        let mint_tx = insert_mint_tx_from_deposit(&deposit, &conn, &mut rng);

        config.safes[0].safe_addr =
            EthAddr::from_str("0x0000000000000000000000000000000000000000").unwrap();
        assert!(matches!(
            AuditedMint::try_match_mint_with_deposit(&mint_tx, &config, &conn),
            Err(Error::GnosisSafeNotAudited(_))
        ));

        // Check that nothing was written to the `audited_mints` table
        assert_audited_mints_table_is_empty(&conn);

        assert_eq!(Counters::get(&conn).unwrap().num_mints_to_unknown_safe(), 1);
    }

    #[test_with_logger]
    fn test_try_match_mint_with_deposit_mismatched_token_id(logger: Logger) {
        let mut config = test_gnosis_config();
        let mut rng = mc_util_test_helper::get_seeded_rng();
        let test_db_context = TestDbContext::default();
        let mint_auditor_db = test_db_context.get_db_instance(logger.clone());
        let conn = mint_auditor_db.get_conn().unwrap();

        let mut deposit = create_gnosis_safe_deposit(100, &mut rng);
        insert_gnosis_deposit(&mut deposit, &conn);
        let sql_mint_tx = insert_mint_tx_from_deposit(&deposit, &conn, &mut rng);

        config.safes[0].tokens[0].token_id = TokenId::from(123);

        assert!(matches!(
            AuditedMint::try_match_mint_with_deposit(&sql_mint_tx, &config, &conn),
            Err(Error::DepositAndMintMismatch(_))
        ));

        // Check that nothing was written to the `audited_mints` table
        assert_audited_mints_table_is_empty(&conn);

        // Mismatch counter was incremented
        assert_eq!(
            Counters::get(&conn)
                .unwrap()
                .num_mismatching_mints_and_deposits(),
            1
        );
    }

    #[test_with_logger]
    fn test_try_match_mint_with_deposit_mismatched_token_addr(logger: Logger) {
        let mut config = test_gnosis_config();
        let mut rng = mc_util_test_helper::get_seeded_rng();
        let test_db_context = TestDbContext::default();
        let mint_auditor_db = test_db_context.get_db_instance(logger.clone());
        let conn = mint_auditor_db.get_conn().unwrap();

        let mut deposit = create_gnosis_safe_deposit(100, &mut rng);
        insert_gnosis_deposit(&mut deposit, &conn);
        let sql_mint_tx = insert_mint_tx_from_deposit(&deposit, &conn, &mut rng);

        config.safes[0].tokens[0].eth_token_contract_addr =
            EthAddr::from_str("0x0000000000000000000000000000000000000000").unwrap();

        assert!(matches!(
            AuditedMint::try_match_mint_with_deposit(&sql_mint_tx, &config, &conn),
            Err(Error::EthereumTokenNotAudited(_, _, _))
        ));

        // Check that nothing was written to the `audited_mints` table
        assert_audited_mints_table_is_empty(&conn);

        assert_eq!(
            Counters::get(&conn)
                .unwrap()
                .num_unknown_ethereum_token_deposits(),
            1
        );
    }

    #[test_with_logger]
    fn test_list_audited_mints(logger: Logger) {
        let config = &test_gnosis_config();
        let mut rng = mc_util_test_helper::get_seeded_rng();
        let test_db_context = TestDbContext::default();
        let mint_auditor_db = test_db_context.get_db_instance(logger.clone());
        let conn = mint_auditor_db.get_conn().unwrap();

        let mut deposits: Vec<GnosisSafeDeposit> = vec![];
        let mut mints: Vec<MintTx> = vec![];

        for _ in 0..10 {
            let mut deposit = create_gnosis_safe_deposit(100, &mut rng);
            deposits.push(deposit.clone());
            insert_gnosis_deposit(&mut deposit, &conn);
            let mint = insert_mint_tx_from_deposit(&deposit, &conn, &mut rng);
            mints.push(mint.clone());
            AuditedMint::try_match_mint_with_deposit(&mint, config, &conn).unwrap();
        }

        let all_audited_mints = AuditedMint::list_with_mint_and_deposit(None, None, &conn).unwrap();
        assert_eq!(all_audited_mints.len(), 10);

        let (_audited_mint, mint_tx, deposit) = &all_audited_mints[0];
        assert_eq!(*mint_tx, mints[0]);
        assert_eq!(deposit.eth_tx_hash(), deposits[0].eth_tx_hash());

        let paginated_mints =
            AuditedMint::list_with_mint_and_deposit(Some(4), Some(3), &conn).unwrap();
        assert_eq!(paginated_mints.len(), 3);
        let (audited_mint, _mint_tx, _deposit) = &paginated_mints[0];
        assert_eq!(audited_mint.id.unwrap(), 5);
        let (audited_mint, _mint_tx, _deposit) = &paginated_mints[2];
        assert_eq!(audited_mint.id.unwrap(), 7);
    }
}
