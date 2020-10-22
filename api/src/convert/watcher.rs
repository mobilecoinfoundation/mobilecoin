//! Convert to/from watcher_api::*

use crate::{convert::ConversionError, external};
use mc_watcher_api::TimestampResultCode;
use std::convert::TryFrom;

impl From<&TimestampResultCode> for external::TimestampResultCode {
    fn from(src: &TimestampResultCode) -> Self {
        match src {
            TimestampResultCode::TimestampFound => external::TimestampResultCode::TimestampFound,
            TimestampResultCode::WatcherBehind => external::TimestampResultCode::WatcherBehind,
            TimestampResultCode::Unavailable => external::TimestampResultCode::Unavailable,
            TimestampResultCode::WatcherDatabaseError => {
                external::TimestampResultCode::WatcherDatabaseError
            }
            TimestampResultCode::BlockIndexOutOfBounds => {
                external::TimestampResultCode::BlockIndexOutOfBounds
            }
        }
    }
}

impl TryFrom<&external::TimestampResultCode> for TimestampResultCode {
    type Error = ConversionError;

    fn try_from(src: &external::TimestampResultCode) -> Result<Self, Self::Error> {
        match src {
            external::TimestampResultCode::UnusedField => Err(ConversionError::ObjectMissing),
            external::TimestampResultCode::TimestampFound => {
                Ok(TimestampResultCode::TimestampFound)
            }
            external::TimestampResultCode::WatcherBehind => Ok(TimestampResultCode::WatcherBehind),
            external::TimestampResultCode::Unavailable => Ok(TimestampResultCode::Unavailable),
            external::TimestampResultCode::WatcherDatabaseError => {
                Ok(TimestampResultCode::WatcherDatabaseError)
            }
            external::TimestampResultCode::BlockIndexOutOfBounds => {
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
            external::TimestampResultCode::TimestampFound as u32
        );
        assert_eq!(
            TimestampResultCode::WatcherBehind as u32,
            external::TimestampResultCode::WatcherBehind as u32
        );
        assert_eq!(
            TimestampResultCode::Unavailable as u32,
            external::TimestampResultCode::Unavailable as u32
        );
        assert_eq!(
            TimestampResultCode::WatcherDatabaseError as u32,
            external::TimestampResultCode::WatcherDatabaseError as u32
        );
        assert_eq!(
            TimestampResultCode::BlockIndexOutOfBounds as u32,
            external::TimestampResultCode::BlockIndexOutOfBounds as u32
        );
    }
}
