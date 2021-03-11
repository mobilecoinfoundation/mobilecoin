// Copyright (c) 2018-2021 The MobileCoin Foundation

//! Types for processing timestamps in the watcher API.

use core::convert::TryFrom;
use displaydoc::Display;
use serde::{Deserialize, Serialize};

/// Enumerates result codes when obtaining a block timstamp from the watcher.
#[derive(PartialEq, Eq, Debug, Display, Clone, Serialize, Deserialize)]
#[repr(u32)]
pub enum TimestampResultCode {
    /// A timestamp was found.
    TimestampFound = 1,
    /// The timestamp was not found and the watcher is behind.
    WatcherBehind,
    /**
     * The timestamp cannot be known unless restarted with a different set
     * of watched nodes.
     */
    Unavailable,
    /// WatcherDBError when getting signatures and timestamps.
    WatcherDatabaseError,
    /// A timestamp was requested for an invalid block index.
    BlockIndexOutOfBounds,
}

impl TryFrom<u32> for TimestampResultCode {
    type Error = ();
    fn try_from(src: u32) -> Result<TimestampResultCode, ()> {
        if src == TimestampResultCode::TimestampFound as u32 {
            Ok(TimestampResultCode::TimestampFound)
        } else if src == TimestampResultCode::WatcherBehind as u32 {
            Ok(TimestampResultCode::WatcherBehind)
        } else if src == TimestampResultCode::Unavailable as u32 {
            Ok(TimestampResultCode::Unavailable)
        } else if src == TimestampResultCode::WatcherDatabaseError as u32 {
            Ok(TimestampResultCode::WatcherDatabaseError)
        } else if src == TimestampResultCode::BlockIndexOutOfBounds as u32 {
            Ok(TimestampResultCode::BlockIndexOutOfBounds)
        } else {
            Err(())
        }
    }
}
