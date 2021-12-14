// Copyright (c) 2018-2021 The MobileCoin Foundation
//

use displaydoc::Display;
use mc_fog_recovery_db_iface::RecoveryDbError;
use mc_fog_sql_recovery_db::Error as SqlRecoveryDbError;

/// An error returned by the overseer service
#[derive(Debug, Display)]
pub enum OverseerError {
    /// RecoveryDbError: {0}
    RecoveryDb(Box<dyn RecoveryDbError>),
    // TODO: Add more errors as appropriate
    /// Reporting a lost key failed: {0}
    ReportLostKey(String),

    /// Setting a new key failed: {0}
    SetNewKey(String),

    /// Activating an idle node failed: {0}
    ActivateNode(String),

    /// There are multiple outstanding keys: {0}
    MultipleOutstandingKeys(String),
}

impl From<SqlRecoveryDbError> for OverseerError {
    fn from(src: SqlRecoveryDbError) -> Self {
        Self::RecoveryDb(Box::new(src))
    }
}
