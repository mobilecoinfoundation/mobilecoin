// Copyright (c) 2018-2022 The MobileCoin Foundation

//! MobileCoin stream errors to manage client future & stream operation

use displaydoc::Display;
use mc_ledger_db::{Error as LedgerDBError, Ledger};
use mc_transaction_core::BlockIndex;
use std::sync::{RwLockReadGuard, RwLockWriteGuard, TryLockError};

/// Errors specific to client
#[derive(Debug, Eq, PartialEq, Clone, Display)]
pub enum Error {
    /// LedgerDBError,
    LedgerDBNotFound,

    /// Failed to access DB
    CantAccessDB,

    /// Other Ledger DB Error
    LedgerDB(LedgerDBError),

    /// Block index {0} is too far ahead, wait
    BlockIndexTooFar(BlockIndex),

    /// Mutex Lock Error {0}
    Locked(LockReason),
}

/// A non-generic helper enum to avoid having to pass in generic type params
#[derive(Debug, Eq, PartialEq, Clone, Display)]
pub enum LockReason {
    /// Acquiring the lock would block
    WouldBlock,

    /// Lock poisoned
    Poisoned,
}

// Return specific errors for checking
impl From<LedgerDBError> for Error {
    fn from(ledgerdb_error: LedgerDBError) -> Self {
        match ledgerdb_error {
            LedgerDBError::NotFound => Error::LedgerDBNotFound,
            LedgerDBError::BadRslot => Error::CantAccessDB,
            err => Error::LedgerDB(err),
        }
    }
}

impl<L: Ledger> From<TryLockError<RwLockReadGuard<'_, L>>> for Error {
    fn from(lock_error: TryLockError<RwLockReadGuard<'_, L>>) -> Self {
        match lock_error {
            TryLockError::WouldBlock => Error::Locked(LockReason::WouldBlock),
            TryLockError::Poisoned(..) => Error::Locked(LockReason::Poisoned),
        }
    }
}

impl<L: Ledger> From<TryLockError<RwLockWriteGuard<'_, L>>> for Error {
    fn from(lock_error: TryLockError<RwLockWriteGuard<'_, L>>) -> Self {
        match lock_error {
            TryLockError::WouldBlock => Error::Locked(LockReason::WouldBlock),
            TryLockError::Poisoned(..) => Error::Locked(LockReason::Poisoned),
        }
    }
}
