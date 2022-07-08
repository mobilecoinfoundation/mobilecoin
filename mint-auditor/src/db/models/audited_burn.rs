// Copyright (c) 2018-2022 The MobileCoin Foundation

use crate::{
    db::{
        schema::{audited_burns, burn_tx_outs, gnosis_safe_withdrawals},
        transaction, BurnTxOut, Conn, Counters, GnosisSafeWithdrawal,
    },
    gnosis::{AuditedSafeConfig, GnosisSafeConfig},
    Error,
};
use diesel::prelude::*;
use serde::{Deserialize, Serialize};

/// Diesel model for the `audited_burns` table.
/// This stores audit data linking BurnTxOuts with matching
/// GnosisSafeWithdrawals.
#[derive(Clone, Debug, Deserialize, Eq, Hash, Insertable, PartialEq, Queryable, Serialize)]
pub struct AuditedBurn {
    /// Id (required to keep Diesel happy).
    pub id: Option<i32>,

    /// Id pointing to the BurnTxOut table.
    pub burn_tx_out_id: i32,

    /// Id pointing to the GnosisSafeWithdrawal table.
    pub gnosis_safe_withdrawal_id: i32,
}

impl AuditedBurn {
    /// Attempt to find a matching [BurnTxOut] for a given
    /// [GnosisSafeWithdrawal], and if successful return the [BurnTxOut] and
    /// record the match in the database. Note that each [BurnTxOut] can be
    /// matched to at most one [GnosisSafeWithdrawal], so calling this
    /// repeatedly over the same withdrawal will fail.
    pub fn attempt_match_withdrawal_with_burn(
        withdrawal: &GnosisSafeWithdrawal,
        config: &AuditedSafeConfig,
        conn: &Conn,
    ) -> Result<BurnTxOut, Error> {
        // We only operate on objects that were saved to the database.
        let withdrawal_id = withdrawal.id().ok_or(Error::ObjectNotSaved)?;

        // The withdrawal safe needs to match the audited safe configuration.
        // This shouldn't happen and indicates misuse of this function.
        if withdrawal.safe_addr() != &config.safe_addr {
            return Err(Error::Other(format!(
                "Gnosis safe withdrawal addr {} does not match audited safe addr {}",
                withdrawal.safe_addr(),
                config.safe_addr
            )));
        }

        let result = transaction(conn, |conn| {
            // Currently we only support 1:1 mapping between deposits and mints, so ensure
            // that there isn't already a match for this deposit.
            let existing_match = audited_burns::table
                .filter(audited_burns::gnosis_safe_withdrawal_id.eq(withdrawal_id))
                .first::<AuditedBurn>(conn)
                .optional()?;
            if let Some(existing_match) = existing_match {
                return Err(Error::AlreadyExists(format!(
                    // TODO fix to show nonce/tx hash
                    "GnosisSafeWithdrawal id={} already matched with burn_tx_out_id={}",
                    existing_match.gnosis_safe_withdrawal_id, existing_match.burn_tx_out_id
                )));
            }

            // See if we can find a BurnTxOut that matches the txout public key and has not
            // been associated with a deposit.
            let burn_tx_out = BurnTxOut::find_unaudited_burn_tx_out_by_public_key(
                withdrawal.mc_tx_out_public_key_hex(),
                conn,
            )?
            .ok_or(Error::NotFound)?;

            // Sanity - find_audited_burn_tx_out_by_public_key is broken if it returns a
            // BurnTxOut with a mismatching public key.
            assert_eq!(
                burn_tx_out.public_key_hex(),
                withdrawal.mc_tx_out_public_key_hex()
            );

            // Check that the burn and withdrawal details match.
            Self::verify_burn_tx_out_matches_withdrawal(&burn_tx_out, withdrawal, config)?;

            // Associate the withdrawal with the burn.
            Self::associate_withdrawal_with_burn(
                withdrawal_id,
                burn_tx_out
                    .id()
                    .expect("got a BurnTxOut without id but database auto-populates that field"),
                conn,
            )?;

            Ok(burn_tx_out)
        });

        // Count certain errors. This needs to happen outside of the transaction because
        // errors result in the transaction getting rolled back.
        match result {
            Ok(_) => {}

            Err(Error::WithdrawalAndBurnMismatch(_)) => {
                Counters::inc_num_mismatching_burns_and_withdrawals(conn)?;
            }

            Err(Error::EthereumTokenNotAudited(_, _, _)) => {
                // TODO Counters::
                // inc_num_unknown_ethereum_token_withdrawals(conn)?;
            }

            Err(_) => {
                Counters::inc_num_unexpected_errors_matching_burns_to_withdrawals(conn)?;
            }
        }

        result
    }

    /// Attempt to find a matching [GnosisSafeWithdrawal] for a given
    /// [BurnTxOut], and if successful return the [GnosisSafeWithdrawal] and
    /// record the match in the database. Note that each
    /// [GnosisSafeWithdrawal] can be matched to at most one [BurnTxOut], so
    /// calling this repeatedly over the same tx out will fail.
    pub fn attempt_match_burn_with_withdrawal(
        burn_tx_out: &BurnTxOut,
        config: &GnosisSafeConfig,
        conn: &Conn,
    ) -> Result<GnosisSafeWithdrawal, Error> {
        // Wrapped in a closure to allow using the ? operator without returning from the
        // function.
        let result = || -> Result<GnosisSafeWithdrawal, Error> {
            // We only operate on objects that were saved to the database.
            let burn_tx_out_id = burn_tx_out.id().ok_or(Error::ObjectNotSaved)?;

            transaction(conn, |conn| -> Result<GnosisSafeWithdrawal, Error> {
                // Currently we only support 1:1 mapping between deposits and mints, so ensure
                // that there isn't already a match for this mint.
                let existing_match: Option<(String, String)> = audited_burns::table
                    .inner_join(burn_tx_outs::table)
                    .inner_join(gnosis_safe_withdrawals::table)
                    .select((
                        burn_tx_outs::public_key_hex,
                        gnosis_safe_withdrawals::eth_tx_hash,
                    ))
                    .filter(audited_burns::burn_tx_out_id.eq(burn_tx_out_id))
                    .first(conn)
                    .optional()?;
                if let Some((public_key_hex, eth_tx_hash)) = existing_match {
                    return Err(Error::AlreadyExists(format!(
                        "BurnTxOut pub_key={} already matched with GnosisSafeDeposit eth_tx_hash={}",
                        public_key_hex, eth_tx_hash,
                    )));
                }

                // See if we can find a GnosisSafeWithdrawal that matches the nonce and has not
                // been associated with a mint.
                let withdrawal = GnosisSafeWithdrawal::find_unaudited_withdrawal_by_public_key(
                    burn_tx_out.public_key_hex(),
                    conn,
                )?
                .ok_or(Error::NotFound)?;

                // See if the deposit we found is for a safe we are auditing.
                let audited_safe_config = config
                    .get_audited_safe_config_by_safe_addr(withdrawal.safe_addr())
                    .ok_or_else(|| Error::GnosisSafeNotAudited(withdrawal.safe_addr().clone()))?;

                // See if they match.
                Self::verify_burn_tx_out_matches_withdrawal(
                    burn_tx_out,
                    &withdrawal,
                    &audited_safe_config,
                )?;

                // Associate the mint with the deposit.
                Self::associate_withdrawal_with_burn(
                    withdrawal.id().expect(
                        "got a GnosisSafeWithdrawal without id but database auto-populates that field",
                    ),
                    burn_tx_out_id,
                    conn,
                )?;

                Ok(withdrawal)
            })
        }();

        // Count certain errors. This needs to happen outside of the transaction because
        // errors result in the transaction getting rolled back.
        match result {
            Ok(_) => {}

            Err(Error::GnosisSafeNotAudited(_)) => {
                // TODO Counters::inc_num_burns_from_unknown_safe(conn)?;
            }

            Err(Error::WithdrawalAndBurnMismatch(_)) => {
                Counters::inc_num_mismatching_burns_and_withdrawals(conn)?;
            }

            Err(Error::EthereumTokenNotAudited(_, _, _)) => {
                // TODO Counters::
                // inc_num_unknown_ethereum_token_withdrawals(conn)?;
            }

            Err(_) => {
                Counters::inc_num_unexpected_errors_matching_burns_to_withdrawals(conn)?;
            }
        }

        result
    }

    /// Verify that the details of a BurnTxOut match the details of a
    /// GnosisSafeWithdrawal (amount/public key/token).
    fn verify_burn_tx_out_matches_withdrawal(
        burn_tx_out: &BurnTxOut,
        withdrawal: &GnosisSafeWithdrawal,
        config: &AuditedSafeConfig,
    ) -> Result<(), Error> {
        // The withdrawal safe needs to match the audited safe configuration.
        // This shouldn't happen and indicates misuse of this function.
        if withdrawal.safe_addr() != &config.safe_addr {
            return Err(Error::Other(format!(
                "Gnosis safe withdrawal addr {} does not match audited safe addr {}",
                withdrawal.safe_addr(),
                config.safe_addr
            )));
        }

        // Public keys should match.
        if burn_tx_out.public_key_hex() != withdrawal.mc_tx_out_public_key_hex() {
            return Err(Error::WithdrawalAndBurnMismatch(format!(
                "BurnTxOut pubkey {} does not match expected pubkey {}",
                burn_tx_out.public_key_hex(),
                withdrawal.mc_tx_out_public_key_hex()
            )));
        }

        // Check to see if the amount matches the withdrawal.
        if burn_tx_out.amount() != withdrawal.amount() {
            return Err(Error::WithdrawalAndBurnMismatch(format!(
                "BurnTxOut amount={} does not match GnosisSafewithdrawal amount={} (pubkey={})",
                burn_tx_out.amount(),
                withdrawal.amount(),
                withdrawal.mc_tx_out_public_key_hex(),
            )));
        }

        // Check and see if the tokens match.
        let audited_token = config
            .get_token_by_eth_contract_addr(withdrawal.token_addr())
            .ok_or_else(|| {
                Error::EthereumTokenNotAudited(
                    withdrawal.token_addr().clone(),
                    withdrawal.safe_addr().clone(),
                    *withdrawal.eth_tx_hash(),
                )
            })?;

        if audited_token.token_id != burn_tx_out.token_id() {
            return Err(Error::WithdrawalAndBurnMismatch(format!(
                "BurnTxOut token_id={} does not match audited token_id={} (pubkey={})",
                burn_tx_out.token_id(),
                audited_token.token_id,
                withdrawal.mc_tx_out_public_key_hex(),
            )));
        }

        Ok(())
    }

    // This is pub(crate) since its used in tests.
    pub(crate) fn associate_withdrawal_with_burn(
        gnosis_safe_withdrawal_id: i32,
        burn_tx_out_id: i32,
        conn: &Conn,
    ) -> Result<(), Error> {
        let audited_burn = Self {
            id: None,
            gnosis_safe_withdrawal_id,
            burn_tx_out_id,
        };
        let _ = diesel::insert_into(audited_burns::table)
            .values(&audited_burn)
            .execute(conn)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        db::test_utils::{
            create_and_insert_burn_tx_out, create_burn_tx_out, create_gnosis_safe_withdrawal,
            create_gnosis_safe_withdrawal_from_burn_tx_out, insert_gnosis_withdrawal,
            test_gnosis_config, TestDbContext, ETH_TOKEN_CONTRACT_ADDR, SAFE_ADDR,
        },
        gnosis::{EthAddr, EthTxHash},
    };
    use mc_common::logger::{test_with_logger, Logger};
    use mc_transaction_core::TokenId;
    use mc_util_from_random::FromRandom;
    use std::str::FromStr;

    fn assert_audited_burns_table_is_empty(conn: &Conn) {
        let num_rows: i64 = audited_burns::table
            .select(diesel::dsl::count(audited_burns::id))
            .first(conn)
            .unwrap();
        assert_eq!(num_rows, 0);
    }
    #[test_with_logger]
    fn test_attempt_match_withdrawal_with_burn_happy_flow(logger: Logger) {
        let config = &test_gnosis_config().safes[0];
        let mut rng = mc_util_test_helper::get_seeded_rng();
        let test_db_context = TestDbContext::default();
        let burn_auditor_db = test_db_context.get_db_instance(logger.clone());
        let conn = burn_auditor_db.get_conn().unwrap();
        let token_id = config.tokens[0].token_id;

        // Create burn tx outs.
        let mut burn_tx_out1 = create_burn_tx_out(token_id, 100, &mut rng);
        let mut burn_tx_out2 = create_burn_tx_out(token_id, 200, &mut rng);

        // Create gnosis withdrawals.
        let mut withdrawal1 =
            create_gnosis_safe_withdrawal_from_burn_tx_out(&burn_tx_out1, &mut rng);
        let mut withdrawal2 =
            create_gnosis_safe_withdrawal_from_burn_tx_out(&burn_tx_out2, &mut rng);

        insert_gnosis_withdrawal(&mut withdrawal1, &conn);
        insert_gnosis_withdrawal(&mut withdrawal2, &conn);

        // Initially the database is empty.
        assert!(matches!(
            AuditedBurn::attempt_match_withdrawal_with_burn(&withdrawal1, config, &conn),
            Err(Error::NotFound)
        ));
        assert!(matches!(
            AuditedBurn::attempt_match_withdrawal_with_burn(&withdrawal1, config, &conn),
            Err(Error::NotFound)
        ));
        assert_audited_burns_table_is_empty(&conn);

        // Insert the first BurnTx to the database, we should get a match now.
        burn_tx_out1.insert(&conn).unwrap();
        assert_eq!(
            burn_tx_out1,
            AuditedBurn::attempt_match_withdrawal_with_burn(&withdrawal1, config, &conn).unwrap()
        );
        assert!(matches!(
            AuditedBurn::attempt_match_withdrawal_with_burn(&withdrawal2, config, &conn),
            Err(Error::NotFound)
        ));

        // Insert the second BurnTx to the database, we should get a match on both.
        burn_tx_out2.insert(&conn).unwrap();
        assert!(matches!(
            AuditedBurn::attempt_match_withdrawal_with_burn(&withdrawal1, config, &conn),
            Err(Error::AlreadyExists(_))
        ));
        assert_eq!(
            burn_tx_out2,
            AuditedBurn::attempt_match_withdrawal_with_burn(&withdrawal2, config, &conn).unwrap()
        );

        // Trying again should return AlreadyExists
        assert!(matches!(
            AuditedBurn::attempt_match_withdrawal_with_burn(&withdrawal2, config, &conn),
            Err(Error::AlreadyExists(_))
        ));

        // No mismatching pairs were found.
        assert_eq!(
            Counters::get(&conn)
                .unwrap()
                .num_mismatching_burns_and_withdrawals(),
            0
        );
    }
    #[test_with_logger]
    fn test_attempt_match_withdrawal_with_burn_amount_mismatch(logger: Logger) {
        let config = &test_gnosis_config().safes[0];
        let mut rng = mc_util_test_helper::get_seeded_rng();
        let test_db_context = TestDbContext::default();
        let burn_auditor_db = test_db_context.get_db_instance(logger.clone());
        let token_id = config.tokens[0].token_id;
        let conn = burn_auditor_db.get_conn().unwrap();

        // Create burn tx out.
        let burn_tx_out = create_and_insert_burn_tx_out(token_id, 100, &conn, &mut rng);

        // Create gnosis withdrawal and make the amount msimatch.
        let mut withdrawal = GnosisSafeWithdrawal::new(
            None,
            EthTxHash::from_random(&mut rng),
            1,
            EthAddr::from_str(SAFE_ADDR).unwrap(),
            EthAddr::from_str(ETH_TOKEN_CONTRACT_ADDR).unwrap(),
            burn_tx_out.amount() + 1,
            burn_tx_out.public_key_hex().to_string(),
        );
        insert_gnosis_withdrawal(&mut withdrawal, &conn);

        // Insert the BurnTx to the database, and check that the mismatch is
        // detected.
        assert!(matches!(
            AuditedBurn::attempt_match_withdrawal_with_burn(&withdrawal, config, &conn),
            Err(Error::WithdrawalAndBurnMismatch(_))
        ));

        // Check that nothing was written to the `audited_burns` table
        assert_audited_burns_table_is_empty(&conn);

        // Mismatch counter was incremented
        assert_eq!(
            Counters::get(&conn)
                .unwrap()
                .num_mismatching_burns_and_withdrawals(),
            1
        );
    }

    #[test_with_logger]
    fn test_attempt_match_withdrawal_with_burn_unsaved_object(logger: Logger) {
        let config = &test_gnosis_config().safes[0];
        let mut rng = mc_util_test_helper::get_seeded_rng();
        let test_db_context = TestDbContext::default();
        let burn_auditor_db = test_db_context.get_db_instance(logger.clone());
        let conn = burn_auditor_db.get_conn().unwrap();

        let withdrawal = create_gnosis_safe_withdrawal(100, &mut rng);

        assert!(matches!(
            AuditedBurn::attempt_match_withdrawal_with_burn(&withdrawal, config, &conn),
            Err(Error::ObjectNotSaved)
        ));

        // Check that nothing was written to the `audited_burns` table
        assert_audited_burns_table_is_empty(&conn);
    }

    #[test_with_logger]
    fn test_attempt_match_withdrawal_with_burn_mismatched_safe_addr(logger: Logger) {
        let mut config = test_gnosis_config().safes[0].clone();
        let mut rng = mc_util_test_helper::get_seeded_rng();
        let test_db_context = TestDbContext::default();
        let burn_auditor_db = test_db_context.get_db_instance(logger.clone());
        let conn = burn_auditor_db.get_conn().unwrap();
        let token_id = config.tokens[0].token_id;

        let burn_tx_out = create_and_insert_burn_tx_out(token_id, 100, &conn, &mut rng);
        let mut withdrawal = create_gnosis_safe_withdrawal_from_burn_tx_out(&burn_tx_out, &mut rng);
        insert_gnosis_withdrawal(&mut withdrawal, &conn);

        config.safe_addr = EthAddr::from_str("0x0000000000000000000000000000000000000000").unwrap();
        assert!(matches!(
            AuditedBurn::attempt_match_withdrawal_with_burn(&withdrawal, &config, &conn),
            Err(Error::Other(_))
        ));

        // Check that nothing was written to the `audited_burns` table
        assert_audited_burns_table_is_empty(&conn);
    }

    #[test_with_logger]
    fn test_attempt_match_withdrawal_with_burn_mismatched_token_id(logger: Logger) {
        let mut config = test_gnosis_config().safes[0].clone();
        let mut rng = mc_util_test_helper::get_seeded_rng();
        let test_db_context = TestDbContext::default();
        let burn_auditor_db = test_db_context.get_db_instance(logger.clone());
        let conn = burn_auditor_db.get_conn().unwrap();
        let token_id = config.tokens[0].token_id;

        let burn_tx_out = create_and_insert_burn_tx_out(token_id, 100, &conn, &mut rng);
        let mut withdrawal = create_gnosis_safe_withdrawal_from_burn_tx_out(&burn_tx_out, &mut rng);
        insert_gnosis_withdrawal(&mut withdrawal, &conn);

        config.tokens[0].token_id = TokenId::from(123);

        assert!(matches!(
            AuditedBurn::attempt_match_withdrawal_with_burn(&withdrawal, &config, &conn),
            Err(Error::WithdrawalAndBurnMismatch(_))
        ));

        // Check that nothing was written to the `audited_burns` table
        assert_audited_burns_table_is_empty(&conn);

        // Mismatch counter was incremented
        assert_eq!(
            Counters::get(&conn)
                .unwrap()
                .num_mismatching_burns_and_withdrawals(),
            1
        );
    }

    #[test_with_logger]
    fn test_attempt_match_withdrawal_with_burn_mismatched_token_addr(logger: Logger) {
        let mut config = test_gnosis_config().safes[0].clone();
        let mut rng = mc_util_test_helper::get_seeded_rng();
        let test_db_context = TestDbContext::default();
        let burn_auditor_db = test_db_context.get_db_instance(logger.clone());
        let conn = burn_auditor_db.get_conn().unwrap();
        let token_id = config.tokens[0].token_id;

        let burn_tx_out = create_and_insert_burn_tx_out(token_id, 100, &conn, &mut rng);
        let mut withdrawal = create_gnosis_safe_withdrawal_from_burn_tx_out(&burn_tx_out, &mut rng);
        insert_gnosis_withdrawal(&mut withdrawal, &conn);

        config.tokens[0].eth_token_contract_addr =
            EthAddr::from_str("0x0000000000000000000000000000000000000000").unwrap();

        assert!(matches!(
            AuditedBurn::attempt_match_withdrawal_with_burn(&withdrawal, &config, &conn),
            Err(Error::EthereumTokenNotAudited(_, _, _))
        ));

        // Check that nothing was written to the `audited_burns` table
        assert_audited_burns_table_is_empty(&conn);
    }

    #[test_with_logger]
    fn test_attempt_match_burn_with_withdrawal_happy_flow(logger: Logger) {
        let config = test_gnosis_config();
        let mut rng = mc_util_test_helper::get_seeded_rng();
        let test_db_context = TestDbContext::default();
        let burn_auditor_db = test_db_context.get_db_instance(logger.clone());
        let conn = burn_auditor_db.get_conn().unwrap();
        let token_id = config.safes[0].tokens[0].token_id;

        // Create BurnTxs.
        let burn_tx_out1 = create_and_insert_burn_tx_out(token_id, 100, &conn, &mut rng);
        let burn_tx_out2 = create_and_insert_burn_tx_out(token_id, 200, &conn, &mut rng);

        // Create gnosis withdrawals (that are not yet in the database).
        let mut withdrawal1 =
            create_gnosis_safe_withdrawal_from_burn_tx_out(&burn_tx_out1, &mut rng);
        let mut withdrawal2 =
            create_gnosis_safe_withdrawal_from_burn_tx_out(&burn_tx_out2, &mut rng);

        // Initially the database is empty.
        assert!(matches!(
            AuditedBurn::attempt_match_burn_with_withdrawal(&burn_tx_out1, &config, &conn),
            Err(Error::NotFound)
        ));
        assert!(matches!(
            AuditedBurn::attempt_match_burn_with_withdrawal(&burn_tx_out2, &config, &conn),
            Err(Error::NotFound)
        ));
        assert_audited_burns_table_is_empty(&conn);

        // Insert the first withdrawal to the database, we should get a match now.
        insert_gnosis_withdrawal(&mut withdrawal1, &conn);

        assert_eq!(
            withdrawal1,
            AuditedBurn::attempt_match_burn_with_withdrawal(&burn_tx_out1, &config, &conn).unwrap()
        );
        assert!(matches!(
            AuditedBurn::attempt_match_burn_with_withdrawal(&burn_tx_out2, &config, &conn),
            Err(Error::NotFound)
        ));

        // Insert the second withdrawal to the database, we should get a match on both.
        insert_gnosis_withdrawal(&mut withdrawal2, &conn);

        assert!(matches!(
            AuditedBurn::attempt_match_burn_with_withdrawal(&burn_tx_out1, &config, &conn),
            Err(Error::AlreadyExists(_))
        ));
        assert_eq!(
            withdrawal2,
            AuditedBurn::attempt_match_burn_with_withdrawal(&burn_tx_out2, &config, &conn).unwrap()
        );

        // Trying again should return AlreadyExists
        assert!(matches!(
            AuditedBurn::attempt_match_burn_with_withdrawal(&burn_tx_out2, &config, &conn),
            Err(Error::AlreadyExists(_))
        ));

        // No mismatching pairs were found.
        assert_eq!(
            Counters::get(&conn)
                .unwrap()
                .num_mismatching_burns_and_withdrawals(),
            0
        );
    }

    #[test_with_logger]
    fn test_attempt_match_burn_with_withdrawal_amount_mismatch(logger: Logger) {
        let config = test_gnosis_config();
        let mut rng = mc_util_test_helper::get_seeded_rng();
        let test_db_context = TestDbContext::default();
        let burn_auditor_db = test_db_context.get_db_instance(logger.clone());
        let token_id = config.safes[0].tokens[0].token_id;
        let conn = burn_auditor_db.get_conn().unwrap();

        // Create burn tx out.
        let burn_tx_out = create_and_insert_burn_tx_out(token_id, 100, &conn, &mut rng);

        // Create gnosis withdrawal and make the amount msimatch.
        let mut withdrawal = GnosisSafeWithdrawal::new(
            None,
            EthTxHash::from_random(&mut rng),
            1,
            EthAddr::from_str(SAFE_ADDR).unwrap(),
            EthAddr::from_str(ETH_TOKEN_CONTRACT_ADDR).unwrap(),
            burn_tx_out.amount() + 1,
            burn_tx_out.public_key_hex().to_string(),
        );
        insert_gnosis_withdrawal(&mut withdrawal, &conn);

        // Check that the mismatch is detected.
        assert!(matches!(
            AuditedBurn::attempt_match_burn_with_withdrawal(&burn_tx_out, &config, &conn),
            Err(Error::WithdrawalAndBurnMismatch(_))
        ));

        // Check that nothing was written to the `audited_burns` table
        assert_audited_burns_table_is_empty(&conn);

        // Mismatch counter was incremented
        assert_eq!(
            Counters::get(&conn)
                .unwrap()
                .num_mismatching_burns_and_withdrawals(),
            1
        );
    }

    #[test_with_logger]
    fn test_attempt_match_burn_with_withdrawal_unsaved_object(logger: Logger) {
        let config = test_gnosis_config();
        let mut rng = mc_util_test_helper::get_seeded_rng();
        let test_db_context = TestDbContext::default();
        let burn_auditor_db = test_db_context.get_db_instance(logger.clone());
        let token_id = config.safes[0].tokens[0].token_id;
        let conn = burn_auditor_db.get_conn().unwrap();

        let burn_tx_out = create_burn_tx_out(token_id, 100, &mut rng);

        assert!(matches!(
            AuditedBurn::attempt_match_burn_with_withdrawal(&burn_tx_out, &config, &conn),
            Err(Error::ObjectNotSaved)
        ));

        // Check that nothing was written to the `audited_burns` table
        assert_audited_burns_table_is_empty(&conn);
    }

    #[test_with_logger]
    fn test_attempt_match_burn_with_withdrawal_mismatched_safe_addr(logger: Logger) {
        let mut config = test_gnosis_config();
        let mut rng = mc_util_test_helper::get_seeded_rng();
        let test_db_context = TestDbContext::default();
        let burn_auditor_db = test_db_context.get_db_instance(logger.clone());
        let conn = burn_auditor_db.get_conn().unwrap();
        let token_id = config.safes[0].tokens[0].token_id;

        let burn_tx_out = create_and_insert_burn_tx_out(token_id, 100, &conn, &mut rng);
        let mut withdrawal = create_gnosis_safe_withdrawal_from_burn_tx_out(&burn_tx_out, &mut rng);
        insert_gnosis_withdrawal(&mut withdrawal, &conn);

        config.safes[0].safe_addr =
            EthAddr::from_str("0x0000000000000000000000000000000000000000").unwrap();
        assert!(matches!(
            AuditedBurn::attempt_match_burn_with_withdrawal(&burn_tx_out, &config, &conn),
            Err(Error::GnosisSafeNotAudited(_))
        ));

        // Check that nothing was written to the `audited_burns` table
        assert_audited_burns_table_is_empty(&conn);
    }

    #[test_with_logger]
    fn test_attempt_match_burn_with_withdrawal_mismatched_token_id(logger: Logger) {
        let mut config = test_gnosis_config();
        let mut rng = mc_util_test_helper::get_seeded_rng();
        let test_db_context = TestDbContext::default();
        let burn_auditor_db = test_db_context.get_db_instance(logger.clone());
        let conn = burn_auditor_db.get_conn().unwrap();
        let token_id = config.safes[0].tokens[0].token_id;

        let burn_tx_out = create_and_insert_burn_tx_out(token_id, 100, &conn, &mut rng);
        let mut withdrawal = create_gnosis_safe_withdrawal_from_burn_tx_out(&burn_tx_out, &mut rng);
        insert_gnosis_withdrawal(&mut withdrawal, &conn);

        config.safes[0].tokens[0].token_id = TokenId::from(123);

        assert!(matches!(
            AuditedBurn::attempt_match_burn_with_withdrawal(&burn_tx_out, &config, &conn),
            Err(Error::WithdrawalAndBurnMismatch(_))
        ));

        // Check that nothing was written to the `audited_burns` table
        assert_audited_burns_table_is_empty(&conn);

        // Mismatch counter was incremented
        assert_eq!(
            Counters::get(&conn)
                .unwrap()
                .num_mismatching_burns_and_withdrawals(),
            1
        );
    }

    #[test_with_logger]
    fn test_attempt_match_burn_with_withdrawal_mismatched_token_addr(logger: Logger) {
        let mut config = test_gnosis_config();
        let mut rng = mc_util_test_helper::get_seeded_rng();
        let test_db_context = TestDbContext::default();
        let burn_auditor_db = test_db_context.get_db_instance(logger.clone());
        let conn = burn_auditor_db.get_conn().unwrap();
        let token_id = config.safes[0].tokens[0].token_id;

        let burn_tx_out = create_and_insert_burn_tx_out(token_id, 100, &conn, &mut rng);
        let mut withdrawal = create_gnosis_safe_withdrawal_from_burn_tx_out(&burn_tx_out, &mut rng);
        insert_gnosis_withdrawal(&mut withdrawal, &conn);

        config.safes[0].tokens[0].eth_token_contract_addr =
            EthAddr::from_str("0x0000000000000000000000000000000000000000").unwrap();

        assert!(matches!(
            AuditedBurn::attempt_match_burn_with_withdrawal(&burn_tx_out, &config, &conn),
            Err(Error::EthereumTokenNotAudited(_, _, _))
        ));

        // Check that nothing was written to the `audited_burns` table
        assert_audited_burns_table_is_empty(&conn);
    }
}
