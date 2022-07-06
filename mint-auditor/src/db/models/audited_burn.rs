// Copyright (c) 2018-2022 The MobileCoin Foundation

use crate::{
    db::{schema::audited_burns, transaction, BurnTxOut, Conn, Counters, GnosisSafeWithdrawal},
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

        // TODO counters

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
        todo!()
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
