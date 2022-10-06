// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Errors that can occur during Fog Overseer operation.

use displaydoc::Display;
use mc_fog_recovery_db_iface::RecoveryDbError;
use mc_fog_sql_recovery_db::Error as SqlRecoveryDbError;
use retry::Error as RetryError;

/// An error returned by the OverseerService.
#[derive(Debug, Display)]
pub enum OverseerError {
    /// RecoveryDbError: {0}
    RecoveryDb(Box<dyn RecoveryDbError>),

    /// A Fog Ingest node did not respond to Fog Overseer: {0}
    UnresponsiveNodeError(String),

    /// Reporting a lost key failed: {0}
    ReportLostKey(String),

    /// Setting a new key failed: {0}
    SetNewKey(String),

    /// Activating an idle node failed: {0}
    ActivateNode(String),

    /// Multiple inactive outstanding keys found: {0}
    MultipleInactiveOutstandingKeys(String),

    /// There are multiple active Fog Ingest nodes at once: {0}
    MultipleActiveNodes(String),
}

impl From<SqlRecoveryDbError> for OverseerError {
    fn from(src: SqlRecoveryDbError) -> Self {
        Self::RecoveryDb(Box::new(src))
    }
}

impl From<RetryError<OverseerError>> for OverseerError {
    fn from(src: RetryError<OverseerError>) -> Self {
        src.error
    }
}
