// Copyright (c) 2023 The MobileCoin Foundation

use displaydoc::Display;

/// Provides logic for validating and ensuring that a timestamp exists when
/// combining `ConsensusValues`.

const MAX_TIMESTAMP_AGE: u64 = 30 * 1000; // 30 seconds

/// Errors related to validating timestamps
#[derive(Debug, Display, Clone, PartialEq)]
pub enum Error {
    /// The timestamp is in the future now{0}, timestamp{1}
    InFuture(u64, u64),
    /** The timestamp is older than the last bock: last_bock timestamp{0},
    timestamp{1} */
    OlderThanLastBlock(u64, u64),
    /// The timestamp is too far in the past now{0}, timestamp{1}
    TooOld(u64, u64),
    /// No timestamp provided
    NoTimestamp,
}

pub fn validate(timestamp: u64, last_block_timestamp: u64) -> Result<(), Error> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;

    if timestamp <= last_block_timestamp {
        return Err(Error::OlderThanLastBlock(last_block_timestamp, timestamp));
    }

    if timestamp > now {
        return Err(Error::InFuture(now, timestamp));
    }

    if timestamp + MAX_TIMESTAMP_AGE < now {
        return Err(Error::TooOld(now, timestamp));
    }

    Ok(())
}

/// Combines the provided timestamps into a single timestamp representing the latest time.
///
/// Errors:
/// `Error::NoTimestamp` if no timestamps are provided
pub fn combine(timestamps: impl IntoIterator<Item = u64>) -> Result<u64, Error> {
    timestamps.into_iter().max().ok_or(Error::NoTimestamp)
}

#[cfg(test)]
mod test {
    use assert_matches::assert_matches;
    use yare::parameterized;
    use super::*;

    #[test]
    fn timestamp_in_the_future_fails_to_validate() {
        // Because of the use of system time we can't test right at the
        // boundary, but 100ms should be sufficient to prevent someone
        // putting newer values into the blockchain and slowing down the
        // network.
        let now = std::time::SystemTime::now();
        let future = now
            .checked_add(std::time::Duration::from_millis(100))
            .unwrap()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;

        assert_matches!(
            validate(future, 0),
            Err(Error::InFuture(_, timestamp)) if timestamp == future
        );
    }

    #[test]
    fn current_timestamp_succeeds() {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;

        assert_eq!(
            validate(now, 0),
            Ok(())
        );
    }

    #[test]
    fn timestamp_older_than_30_seconds_fails() {
        let now = std::time::SystemTime::now();
        // Need to add 1 since at MAX_TIMESTAMP_AGE is still good
        let too_old = now.checked_sub(std::time::Duration::from_millis(MAX_TIMESTAMP_AGE + 1)).unwrap()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;

        assert_matches!(
            validate(too_old, 0),
            Err(Error::TooOld(_, timestamp)) if timestamp == too_old
        );
    }

    #[test]
    fn timestamp_same_as_last_block_timestamp() {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;

        assert_eq!(
            validate(now, now),
            Err(Error::OlderThanLastBlock(now, now))
        );
    }

    #[test]
    fn timestamp_earlier_than_last_block_timestamp() {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;

        assert_eq!(
            validate(now - 1, now),
            Err(Error::OlderThanLastBlock(now, now - 1))
        );
    }

    #[parameterized(
        one = { vec![1], 1 },
        two = { vec![1, 2], 2 },
        five = { vec![1, 2, 3, 4, 5], 5 },
        mixed = { vec![1, 2, 3, 4, 5, 4, 3, 2, 1], 5 },
        descending = { vec![5, 4, 3, 2, 1], 5 },
    )]
    fn combine_provides_the_max_timestamp(timestamps: Vec<u64>, expected: u64) {
        assert_eq!(
            combine(timestamps),
            Ok(expected)
        );
    }

    #[test]
    fn combine_errors_when_no_timestamps_provided() {
        assert_eq!(
            combine(vec![]),
            Err(Error::NoTimestamp)
        );
    }
}