//! Convert to/from watcher_api::*

use crate::{convert::ConversionError, watcher};
use mc_watcher_api::TimestampResultCode;
use std::convert::TryFrom;

impl From<&TimestampResultCode> for watcher::TimestampResultCode {
    fn from(src: &TimestampResultCode) -> Self {
        match src {
            TimestampResultCode::TimestampFound => watcher::TimestampResultCode::TimestampFound,
            TimestampResultCode::WatcherBehind => watcher::TimestampResultCode::WatcherBehind,
            TimestampResultCode::Unavailable => watcher::TimestampResultCode::Unavailable,
            TimestampResultCode::WatcherDatabaseError => {
                watcher::TimestampResultCode::WatcherDatabaseError
            }
            TimestampResultCode::BlockIndexOutOfBounds => {
                watcher::TimestampResultCode::BlockIndexOutOfBounds
            }
        }
    }
}

impl TryFrom<&watcher::TimestampResultCode> for TimestampResultCode {
    type Error = ConversionError;

    fn try_from(src: &watcher::TimestampResultCode) -> Result<Self, Self::Error> {
        match src {
            watcher::TimestampResultCode::UnusedField => Err(ConversionError::ObjectMissing),
            watcher::TimestampResultCode::TimestampFound => Ok(TimestampResultCode::TimestampFound),
            watcher::TimestampResultCode::WatcherBehind => Ok(TimestampResultCode::WatcherBehind),
            watcher::TimestampResultCode::Unavailable => Ok(TimestampResultCode::Unavailable),
            watcher::TimestampResultCode::WatcherDatabaseError => {
                Ok(TimestampResultCode::WatcherDatabaseError)
            }
            watcher::TimestampResultCode::BlockIndexOutOfBounds => {
                Ok(TimestampResultCode::BlockIndexOutOfBounds)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test that .proto enum values matches the Rust code
    #[test]
    fn test_timestamp_result_code_enum_values() {
        assert_eq!(
            TimestampResultCode::TimestampFound as u32,
            watcher::TimestampResultCode::TimestampFound as u32
        );
        assert_eq!(
            TimestampResultCode::WatcherBehind as u32,
            watcher::TimestampResultCode::WatcherBehind as u32
        );
        assert_eq!(
            TimestampResultCode::Unavailable as u32,
            watcher::TimestampResultCode::Unavailable as u32
        );
        assert_eq!(
            TimestampResultCode::WatcherDatabaseError as u32,
            watcher::TimestampResultCode::WatcherDatabaseError as u32
        );
        assert_eq!(
            TimestampResultCode::BlockIndexOutOfBounds as u32,
            watcher::TimestampResultCode::BlockIndexOutOfBounds as u32
        );
    }
}
