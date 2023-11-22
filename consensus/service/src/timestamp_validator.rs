// Copyright (c) 2023 The MobileCoin Foundation

use displaydoc::Display;
use mc_blockchain_types::Block;
use mc_common::logger::{log, Logger};

/// Provides logic for validating a timestamp used in consensus

const MAX_TIMESTAMP_AGE: u64 = 30 * 1000; // 30 seconds

/// The maximum allowed skew between the system time and the timestamp. This
/// allows the system time to be a bit behind the timestamp.
/// The reason for this is that during consensus multiple nodes will be looking
/// at the time and those nodes may have skew between their clocks. If the node
/// with the latest time proposes a value, it's possible that the other nodes
/// will reject it because the timestamp is in the future.
///
/// The 3 seconds is taken from the `signed_at` values from the first 2 million
/// blocks of the blockchain. Throwing away significant outlier nodes most nodes
/// were almost always within 3 seconds of each other.
const ALLOWED_FUTURE_SKEW: u64 = 3 * 1000;

/// Errors related to validating timestamps
#[derive(Clone, Debug, Display, Eq, PartialEq)]
pub enum Error {
    /// The timestamp is too far in the future now: {0}, timestamp: {1}
    InFuture(u64, u64),
    /** The timestamp is not newer than the last bock. last_bock timestamp: {0},
    timestamp: {1} */
    NotNewerThanLastBlock(u64, u64),
    /// The timestamp is too far in the past now: {0}, timestamp: {1}
    TooOld(u64, u64),
}

pub fn validate_with_logger(
    timestamp: u64,
    latest_block: &Block,
    logger: &Logger,
) -> Result<(), Error> {
    validate(timestamp, latest_block).map_err(|e| {
        log::warn!(logger, "Consensus Value timestamp invalid: {e}");
        e
    })
}

pub fn validate(timestamp: u64, latest_block: &Block) -> Result<(), Error> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("Failed to get system time")
        .as_millis() as u64;

    if timestamp > (now + ALLOWED_FUTURE_SKEW) {
        return Err(Error::InFuture(now, timestamp));
    }

    if timestamp + MAX_TIMESTAMP_AGE < now {
        return Err(Error::TooOld(now, timestamp));
    }

    if timestamp <= latest_block.timestamp {
        return Err(Error::NotNewerThanLastBlock(
            latest_block.timestamp,
            timestamp,
        ));
    }

    Ok(())
}

/// Will sort and deduplicate the values, `V` such that only one instance of
/// `V` exists with the largest u64.
///
/// ```ignore
/// use crate::timestamp_validator;
/// let values = vec![("a", 1), ("a", 2), ("b", 3), ("b", 4)];
/// let deduped = timestamp_validator::sort_and_dedup(values.iter());
/// assert_eq!(deduped, vec![("a", 2), ("b", 4)]);
/// ```
pub fn sort_and_dedup<'a, V: Clone + Ord + 'a>(
    values: impl Iterator<Item = &'a (V, u64)>,
) -> Vec<(V, u64)> {
    let sorted = sort_by_value_then_timestamp(values);
    dedup(sorted)
}

/// Deduplicates based on the `V` of the tuple, ignoring the second element of
/// the tuple.
///
/// This deduplication only works on adjacent elements so the input should be
/// sorted.
fn dedup<V: Eq>(mut values: Vec<(V, u64)>) -> Vec<(V, u64)> {
    values.dedup_by(|a, b| a.0 == b.0);
    values
}

/// Will sort the values by the first element of the tuple, and then descending
/// by the second element of the tuple, the timestamp.
///
/// The reason for this sorting is to place the latest timestamp for a value
/// first in the sequence of the same value.
pub fn sort_by_value_then_timestamp<'a, V: Clone + Ord + 'a>(
    values: impl IntoIterator<Item = &'a (V, u64)>,
) -> Vec<(V, u64)> {
    let mut values: Vec<_> = values.into_iter().cloned().collect();
    values.sort_by(|a, b| {
        if a.0 == b.0 {
            b.1.cmp(&a.1)
        } else {
            a.0.cmp(&b.0)
        }
    });
    values
}

#[cfg(test)]
mod test {
    use super::*;
    use assert_matches::assert_matches;
    use yare::parameterized;

    #[test]
    fn timestamp_in_the_future_fails_to_validate() {
        // Because of the use of system time we can't test right at the
        // boundary, but 100ms should be sufficient to prevent someone
        // putting newer values into the blockchain and slowing down the
        // network.
        let now = std::time::SystemTime::now();
        let future = now
            .checked_add(std::time::Duration::from_millis(ALLOWED_FUTURE_SKEW + 100))
            .unwrap()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;

        let latest_block = Block::default();

        assert_matches!(
            validate(future, &latest_block),
            Err(Error::InFuture(_, timestamp)) if timestamp == future
        );
    }

    #[test]
    fn current_timestamp_succeeds() {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;

        let latest_block = Block::default();

        assert_eq!(validate(now, &latest_block), Ok(()));
    }

    #[test]
    fn timestamp_up_to_allowed_future_skew_succeeds() {
        let skewed_now = std::time::SystemTime::now()
            .checked_add(std::time::Duration::from_millis(ALLOWED_FUTURE_SKEW))
            .unwrap()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;

        let latest_block = Block::default();

        assert_eq!(validate(skewed_now, &latest_block), Ok(()));
    }

    #[test]
    fn timestamp_older_than_30_seconds_fails() {
        let now = std::time::SystemTime::now();
        // Need to add 1 since at MAX_TIMESTAMP_AGE is still good
        let too_old = now
            .checked_sub(std::time::Duration::from_millis(MAX_TIMESTAMP_AGE + 1))
            .unwrap()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;

        let latest_block = Block::default();

        assert_matches!(
            validate(too_old, &latest_block),
            Err(Error::TooOld(_, timestamp)) if timestamp == too_old
        );
    }

    #[test]
    fn timestamp_same_as_last_block_timestamp() {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;

        let latest_block = Block {
            timestamp: now,
            ..Default::default()
        };

        assert_eq!(
            validate(now, &latest_block),
            Err(Error::NotNewerThanLastBlock(now, now))
        );
    }

    #[test]
    fn timestamp_earlier_than_last_block_timestamp() {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;

        let latest_block = Block {
            timestamp: now,
            ..Default::default()
        };

        assert_eq!(
            validate(now - 1, &latest_block),
            Err(Error::NotNewerThanLastBlock(now, now - 1))
        );
    }

    #[test]
    fn sorting_empty() {
        let values: Vec<(&str, u64)> = vec![];
        let sorted = sort_by_value_then_timestamp(values.iter());
        assert_eq!(sorted, vec![])
    }

    #[parameterized(
        one = {&[("a", 1)], &[("a", 1)]},
        all_the_same = {&[("a", 1), ("a", 1), ("a", 1)], &[("a", 1), ("a", 1), ("a", 1)]},
        already_sorted_by_value = {&[("a", 1), ("b", 2), ("c", 3)], &[("a", 1), ("b", 2), ("c", 3)]},
        reversed_value = {&[("z", 1), ("y", 2), ("x", 3)], &[("x", 3), ("y", 2), ("z", 1)]},
        already_sorted_by_timestamp = {&[("a", 3), ("a", 2), ("a", 1)], &[("a", 3), ("a", 2), ("a", 1)]},
        reversed_timestamp = {&[("a", 1), ("a", 2), ("a", 3)], &[("a", 3), ("a", 2), ("a", 1)]},
        unsorted_duplicates_with_different_timestamps = {&[("b", 10), ("a", 2), ("a", 3), ("b", 11)], &[("a", 3), ("a", 2), ("b", 11), ("b", 10)]},
    )]
    fn sorting(unsorted: &[(&str, u64)], expected: &[(&str, u64)]) {
        let sorted = sort_by_value_then_timestamp(unsorted);
        assert_eq!(sorted, expected)
    }

    #[test]
    fn dedup_with_no_elements() {
        let deduped: Vec<(&str, u64)> = dedup(vec![]);
        assert_eq!(deduped, vec![])
    }

    #[parameterized(
        one = {&[("a", 1)], &[("a", 1)]},
        two_the_same = {&[("a", 1), ("a", 1)], &[("a", 1)]},
        two_different = {&[("a", 1), ("b", 2)], &[("a", 1), ("b", 2)]},
        last_two_duplicate_with_disparate_timestamp = {&[("a", 1), ("b", 2), ("b", 1)], &[("a", 1), ("b", 2)]},
        all_duplicate_with_disparate_timestamps = {&[("a", 100), ("a", 10), ("a", 1), ("b", 200), ("b", 20), ("c", 300)], &[("a", 100), ("b", 200), ("c", 300)]},
    )]
    fn deduping(unsorted: &[(&str, u64)], expected: &[(&str, u64)]) {
        let deduped = dedup(unsorted.to_vec());
        assert_eq!(deduped, expected)
    }

    #[test]
    fn sort_and_dedup_with_no_elements() {
        let deduped: Vec<(&str, u64)> = sort_and_dedup([].iter());
        assert_eq!(deduped, vec![])
    }

    #[test]
    fn sort_and_dedup_doc_example() {
        // The example cant be run as a doctest without making this module public
        let values = [("a", 1), ("a", 2), ("b", 3), ("b", 4)];
        let deduped = sort_and_dedup(values.iter());
        assert_eq!(deduped, vec![("a", 2), ("b", 4)]);
    }
}
