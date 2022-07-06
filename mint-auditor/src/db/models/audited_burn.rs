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
        todo!()
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
}
