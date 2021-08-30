// Copyright (c) 2018-2021 The MobileCoin Foundation

use prost::Message;
use serde::{Deserialize, Serialize};

/// A half-open [a, b) range of blocks
#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Message, Serialize, Deserialize)]
pub struct BlockRange {
    #[prost(uint64, tag = "1")]
    pub start_block: u64,
    #[prost(uint64, tag = "2")]
    pub end_block: u64,
}

impl BlockRange {
    pub fn new(start_block: u64, end_block: u64) -> Self {
        Self {
            start_block,
            end_block,
        }
    }

    pub fn contains(&self, block: u64) -> bool {
        block >= self.start_block && block < self.end_block
    }

    pub fn is_valid(&self) -> bool {
        self.end_block > self.start_block
    }

    pub fn overlaps(&self, other: &BlockRange) -> bool {
        self.start_block < other.end_block && other.start_block < self.end_block
    }
}

impl core::fmt::Display for BlockRange {
    fn fmt(&self, formatter: &mut core::fmt::Formatter) -> core::fmt::Result {
        write!(formatter, "[{},{})", self.start_block, self.end_block)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_contains() {
        let range = BlockRange::new(10, 13);
        assert!(!range.contains(8));
        assert!(!range.contains(9));
        assert!(range.contains(10));
        assert!(range.contains(11));
        assert!(range.contains(12));
        assert!(!range.contains(13));
        assert!(!range.contains(14));
    }

    #[test]
    fn test_is_valid() {
        assert!(BlockRange::new(0, 13).is_valid());
        assert!(BlockRange::new(10, 13).is_valid());
        assert!(!BlockRange::new(10, 10).is_valid());
        assert!(!BlockRange::new(11, 10).is_valid());
        assert!(!BlockRange::new(100, 10).is_valid());
    }

    #[test]
    fn test_overlaps() {
        let range = BlockRange::new(10, 13);

        assert!(range.overlaps(&BlockRange::new(10, 13)));
        assert!(range.overlaps(&BlockRange::new(11, 13)));
        assert!(range.overlaps(&BlockRange::new(12, 13)));
        assert!(range.overlaps(&BlockRange::new(10, 15)));
        assert!(range.overlaps(&BlockRange::new(11, 15)));
        assert!(range.overlaps(&BlockRange::new(12, 15)));
        assert!(range.overlaps(&BlockRange::new(0, 11)));
        assert!(range.overlaps(&BlockRange::new(0, 12)));
        assert!(range.overlaps(&BlockRange::new(0, 13)));
        assert!(range.overlaps(&BlockRange::new(0, 14)));
        assert!(range.overlaps(&BlockRange::new(0, 15)));
        assert!(!range.overlaps(&BlockRange::new(0, 10)));
        assert!(!range.overlaps(&BlockRange::new(13, 100)));
    }
}
