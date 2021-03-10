// Copyright (c) 2018-2021 The MobileCoin Foundation

use core::cmp::Ordering;
use mc_crypto_digestible::Digestible;
use prost::Message;
// These require the serde "derive" feature to be enabled.
use serde::{Deserialize, Serialize};

#[derive(Debug, Eq, PartialEq, Copy, Clone)]
pub struct RangeError {}

impl core::fmt::Display for RangeError {
    fn fmt(&self, fmt: &mut core::fmt::Formatter) -> core::fmt::Result {
        write!(fmt, "Invalid range")
    }
}

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
        if self.from <= self.to {
            self.to - self.from + 1
        } else {
            self.from - self.to + 1
        }
    }
}

/// Ranges are ordered by `len`, then lexicographically by (from,to).
///
/// This is a total ordering of (u64, u64) tuples. Additionally, when a node of
/// a binary tree (i.e. Merkle tree) is identified with the range of indices
/// below that node, the len of a range is equal to 2^h, where h is the height
/// of the node in the tree. This means that traversing a list of ranges sorted
/// in ascending order corresponds to a bottom-up traversal of the tree
/// (which is handy for computing Merkle hashes). Ordering ranges of equal len
/// lexicographically makes it a bottom-up and left-to-right traversal of the
/// tree.
impl Ord for Range {
    fn cmp(&self, other: &Range) -> Ordering {
        if self.len() != other.len() {
            self.len().cmp(&other.len())
        } else {
            (self.from, self.to).cmp(&(other.from, other.to))
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

    #[test]
    // `len` should return the number of indices in a range.
    fn test_len() {
        assert_eq!(Range::new(0, 0).unwrap().len(), 1);
        assert_eq!(Range::new(0, 7).unwrap().len(), 8);
        assert_eq!(Range::new(7, 7).unwrap().len(), 1);
        assert_eq!(Range::new(7, 8).unwrap().len(), 2);
        assert_eq!(Range::new(10233, 888374662).unwrap().len(), 888364430);
    }

    #[test]
    // `len` should return the number of indices in a "negative" range where from >
    // to.
    fn test_len_negative_range() {
        // A "negative" range is possible by bypassing the constructor, e.g. when
        // deserializing.
        assert_eq!(Range { from: 7, to: 0 }.len(), 8);
        assert_eq!(Range { from: 44, to: 6 }.len(), 39);
        assert_eq!(
            Range {
                from: 888374662,
                to: 10233
            }
            .len(),
            888364430
        );
    }

    #[test]
    // `new` should return an Error if `from > to`.
    fn test_from_greater_than_to() {
        assert!(Range::new(999, 2).is_err());
    }

    #[test]
    fn test_ord() {
        let mut ranges = vec![
            Range::new(2, 2).unwrap(),
            Range::new(1, 1).unwrap(),
            Range::new(8, 9).unwrap(),
            Range::new(0, 1).unwrap(),
            Range::new(0, 0).unwrap(),
            Range::new(0, 2).unwrap(),
        ];

        // [0,0] < [1,1] < [2,2] < [0,1] < ... < [8,9] < [0,2] ...
        ranges.sort();

        let expected_ordering = vec![
            // Ranges of `len` 1
            Range::new(0, 0).unwrap(),
            Range::new(1, 1).unwrap(),
            Range::new(2, 2).unwrap(),
            // Ranges of `len` 2
            Range::new(0, 1).unwrap(),
            Range::new(8, 9).unwrap(),
            // Ranges of `len` 3
            Range::new(0, 2).unwrap(),
        ];

        assert_eq!(ranges, expected_ordering);
    }

    #[test]
    // `ord` should correctly order ranges when from > to.
    fn test_ord_with_negative_ranges() {
        let mut ranges = vec![
            Range { from: 11, to: 13 },
            Range { from: 7, to: 0 }, // from > to
            Range { from: 0, to: 0 },
            Range { from: 11, to: 9 },  // from > to
            Range { from: 13, to: 11 }, // from > to
            Range { from: 13, to: 22 },
            Range { from: 5, to: 5 },
            Range { from: 9, to: 11 },
            Range { from: 11, to: 22 },
        ];

        ranges.sort();

        let expected_ordering = vec![
            // Ranges of `len` 1
            Range { from: 0, to: 0 },
            Range { from: 5, to: 5 },
            // Ranges of `len` 3
            Range { from: 9, to: 11 },
            Range { from: 11, to: 9 },
            Range { from: 11, to: 13 },
            Range { from: 13, to: 11 },
            // Ranges of `len` 8
            Range { from: 7, to: 0 },
            // Ranges of `len` 10
            Range { from: 13, to: 22 },
            // Ranges of `len` 12
            Range { from: 11, to: 22 },
        ];

        assert_eq!(ranges, expected_ordering);
    }
}
