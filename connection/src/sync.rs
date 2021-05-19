// Copyright (c) 2018-2021 The MobileCoin Foundation

//! A synchronous connection wrapper around an inner (thread-unsafe) connection

use crate::{
    error::RetryResult,
    traits::{
        BlockInfo, BlockchainConnection, Connection, RetryableBlockchainConnection,
        RetryableUserTxConnection, UserTxConnection,
    },
};
use mc_common::logger::Logger;
use mc_transaction_core::{tx::Tx, Block, BlockID, BlockIndex};
use std::{
    cmp::Ordering,
    fmt::{Display, Formatter, Result as FmtResult},
    hash::{Hash, Hasher},
    ops::{Deref, Range},
    sync::{Arc, RwLock, RwLockReadGuard, RwLockWriteGuard},
    time::Duration,
};

/// A synchronous wrapper for a connection object.
///
/// This object provides threadsafe access to the underlying connection.
pub struct SyncConnection<C: Connection> {
    inner: Arc<RwLock<C>>,
    cached_uri: C::Uri,
    cached_display: String,
    logger: Logger,
}

impl<C: Connection> SyncConnection<C> {
    pub fn new(inner: C, logger: Logger) -> Self {
        let cached_uri = inner.uri();
        let cached_display = inner.to_string();
        Self {
            inner: Arc::new(RwLock::new(inner)),
            cached_uri,
            cached_display,
            logger,
        }
    }

    pub fn read(&self) -> RwLockReadGuard<C> {
        self.inner
            .read()
            .expect("Could not acquire read lock on SyncConnection")
    }

    pub fn write(&self) -> RwLockWriteGuard<C> {
        self.inner
            .write()
            .expect("Could not acquire write lock on SyncConnection")
    }

    pub fn logger(&self) -> &Logger {
        &self.logger
    }
}

impl<C: Connection> Clone for SyncConnection<C> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            cached_uri: self.cached_uri.clone(),
            cached_display: self.cached_display.clone(),
            logger: self.logger.clone(),
        }
    }
}

impl<C: Connection> Connection for SyncConnection<C> {
    type Uri = C::Uri;

    fn uri(&self) -> Self::Uri {
        self.cached_uri.clone()
    }
}

impl<C: Connection> Display for SyncConnection<C> {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        write!(f, "{}", self.cached_display)
    }
}

impl<C: Connection> Eq for SyncConnection<C> {}

impl<C: Connection> Hash for SyncConnection<C> {
    fn hash<H: Hasher>(&self, hasher: &mut H) {
        self.read().hash(hasher)
    }
}

impl<C: Connection> Ord for SyncConnection<C> {
    fn cmp(&self, other: &Self) -> Ordering {
        let self_g = self.read();
        let other_g = other.read();
        self_g.deref().cmp(other_g.deref())
    }
}

impl<C: Connection> PartialEq for SyncConnection<C> {
    fn eq(&self, other: &Self) -> bool {
        let self_g = self.read();
        let other_g = other.read();
        self_g.deref().eq(other_g.deref())
    }
}

impl<C: Connection> PartialOrd for SyncConnection<C> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        let self_g = self.read();
        let other_g = other.read();
        self_g.deref().partial_cmp(other_g.deref())
    }
}

#[macro_export]
macro_rules! _retry_wrapper {
    ($pred:expr) => {{
        match $pred {
            Ok(retval) => $crate::_retry::OperationResult::Ok(retval),
            Err(err) => {
                if err.should_retry() {
                    $crate::_retry::OperationResult::Retry(err)
                } else {
                    $crate::_retry::OperationResult::Err(err)
                }
            }
        }
    }};
}

// Generic retry implementation, locks the inner object, calls the underlying
// function and passes the given argument(s).
//
// This will immediately stop on any non-gRPC error, however.
//
// This is required to allow the locks on the underlying object to live only for
// as long as the request itself (not the entire retry interval).
#[macro_export]
macro_rules! impl_sync_connection_retry {
    ($obj:expr, $logger:expr, $func:ident, $iter:expr) => {{
        $crate::_trace_time!(
            $logger,
            "SyncConnection.{}({})",
            stringify!($func),
            stringify!($iter)
        );
        $crate::_retry::retry($iter, || $crate::_retry_wrapper!($obj.$func()))
    }};
    ($obj:expr, $logger:expr, $func:ident, $iter:expr, $arg1:expr) => {{
        $crate::_trace_time!(
            $logger,
            "SyncConnection.{}({}, {})",
            stringify!($func),
            stringify!($arg1),
            stringify!($iter)
        );
        $crate::_retry::retry($iter, || $crate::_retry_wrapper!($obj.$func($arg1)))
    }};
    ($obj:expr, $logger:expr, $func:ident, $iter:expr, $arg1:expr, $arg2:expr) => {{
        $crate::_trace_time!(
            $logger,
            "SyncConnection.{}({}, {}, {})",
            stringify!($func),
            stringify!($arg1),
            stringify!($arg2),
            stringify!($iter)
        );
        $crate::_retry::retry($iter, || $crate::_retry_wrapper!($obj.$func($arg1, $arg2)))
    }};
}

impl<BC: BlockchainConnection> RetryableBlockchainConnection for SyncConnection<BC> {
    fn fetch_blocks(
        &self,
        range: Range<BlockIndex>,
        retry_iterator: impl IntoIterator<Item = Duration>,
    ) -> RetryResult<Vec<Block>> {
        impl_sync_connection_retry!(
            self.write(),
            self.logger,
            fetch_blocks,
            retry_iterator,
            range.clone()
        )
    }

    fn fetch_block_ids(
        &self,
        range: Range<BlockIndex>,
        retry_iterator: impl IntoIterator<Item = Duration>,
    ) -> RetryResult<Vec<BlockID>> {
        impl_sync_connection_retry!(
            self.write(),
            self.logger,
            fetch_block_ids,
            retry_iterator,
            range.clone()
        )
    }

    fn fetch_block_height(
        &self,
        retry_iterator: impl IntoIterator<Item = Duration>,
    ) -> RetryResult<BlockIndex> {
        impl_sync_connection_retry!(
            self.write(),
            self.logger,
            fetch_block_height,
            retry_iterator
        )
    }

    fn fetch_block_info(
        &self,
        retry_iterator: impl IntoIterator<Item = Duration>,
    ) -> RetryResult<BlockInfo> {
        impl_sync_connection_retry!(self.write(), self.logger, fetch_block_info, retry_iterator)
    }
}

impl<UTC: UserTxConnection> RetryableUserTxConnection for SyncConnection<UTC> {
    fn propose_tx(
        &self,
        tx: &Tx,
        retry_iterator: impl IntoIterator<Item = Duration>,
    ) -> RetryResult<BlockIndex> {
        impl_sync_connection_retry!(self.write(), self.logger, propose_tx, retry_iterator, tx)
    }
}
