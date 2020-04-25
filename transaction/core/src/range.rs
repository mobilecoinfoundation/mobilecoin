// Copyright (c) 2018-2020 MobileCoin Inc.

use core::cmp::Ordering;
use mc_crypto_digestible::Digestible;
use prost::Message;
// These require the serde "derive" feature to be enabled.
use serde::{Deserialize, Serialize};

#[derive(Debug, Eq, PartialEq, Copy, Clone)]
pub struct RangeError {}

/// A range [from,to] of indices.
#[derive(Clone, Copy, Deserialize, Eq, Hash, PartialEq, Serialize, Message, Digestible)]
pub struct Range {
    #[prost(uint64, tag = "1")]
    pub from: u64,
    #[prost(uint64, tag = "2")]
    pub to: u64,
}
#[allow(clippy::len_without_is_empty)]
impl Range {
    pub fn new(from: u64, to: u64) -> Result<Self, RangeError> {
        if from <= to {
            Ok(Self { from, to })
        } else {
            Err(RangeError {})
        }
    }

    /// The number of indices in this Range.
    pub fn len(&self) -> u64 {
        self.to - self.from + 1
    }
}

/// Ranges are ordered by `len`. If two ranges have equal `len`, they are ordered by `from`.
impl Ord for Range {
    fn cmp(&self, other: &Range) -> Ordering {
        if self.len() != other.len() {
            self.len().cmp(&other.len())
        } else {
            self.from.cmp(&other.from)
        }
    }
}

impl PartialOrd for Range {
    fn partial_cmp(&self, other: &Range) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

#[cfg(test)]
mod range_tests {
    use super::Range;
    use alloc::vec::Vec;

    #[test]
    // `new` should return an Error if `from > to`.
    fn test_from_greater_than_to() {
        assert!(Range::new(999, 2).is_err());
    }

    #[test]
    fn test_ord() {
        let mut ranges: Vec<Range> = Vec::new();
        ranges.push(Range::new(2, 2).unwrap());
        ranges.push(Range::new(1, 1).unwrap());
        ranges.push(Range::new(8, 9).unwrap());
        ranges.push(Range::new(0, 1).unwrap());
        ranges.push(Range::new(0, 0).unwrap());
        ranges.push(Range::new(0, 2).unwrap());

        // [0,0] < [1,1] < [2,2] < [0,1] < ... < [8,9] < [0,2] ...
        ranges.sort();

        // Ranges of `len` 1
        assert_eq!(Range::new(0, 0).unwrap(), *ranges.get(0).unwrap());
        assert_eq!(Range::new(1, 1).unwrap(), *ranges.get(1).unwrap());
        assert_eq!(Range::new(2, 2).unwrap(), *ranges.get(2).unwrap());
        // Ranges of `len` 2
        assert_eq!(Range::new(0, 1).unwrap(), *ranges.get(3).unwrap());
        assert_eq!(Range::new(8, 9).unwrap(), *ranges.get(4).unwrap());
        // Ranges of `len` 3
        assert_eq!(Range::new(0, 2).unwrap(), *ranges.get(5).unwrap());
    }
}
