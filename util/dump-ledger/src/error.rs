// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Error types.

use displaydoc::Display;
use mc_ledger_db::Error as LedgerError;
use serde_json::Error as JsonError;

/// Convenience wrapper for `Result` with [Error].
pub type Result<T> = std::result::Result<T, Error>;

/// Error enum.
#[derive(Debug, Display)]
pub enum Error {
    /// Ledger: {0}
    Ledger(LedgerError),
    /// JSON: {0}
    Json(JsonError),
}

impl From<LedgerError> for Error {
    fn from(src: LedgerError) -> Self {
        Self::Ledger(src)
    }
}

impl From<JsonError> for Error {
    fn from(src: JsonError) -> Self {
        Self::Json(src)
    }
}
