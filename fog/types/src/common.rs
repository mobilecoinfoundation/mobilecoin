// Copyright (c) 2018-2022 The MobileCoin Foundation

use alloc::{format, string::String, vec::Vec};
use core::str::FromStr;
use prost::Message;
use serde::{Deserialize, Serialize};

/// The string that delimits the start and end blocks in a string that
/// represents a BlockRange.
pub const BLOCK_RANGE_DELIMITER: &str = "-";

/// A half-open [a, b) range of blocks
#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Message, Serialize, Deserialize)]
pub struct BlockRange {
    /// The first block in the range
    #[prost(uint64, tag = "1")]
    pub start_block: u64,
    /// The end block, which is one past the end of the range.
    #[prost(uint64, tag = "2")]
    pub end_block: u64,
}

impl BlockRange {
    /// Create a new block range
    pub fn new(start_block: u64, end_block: u64) -> Self {
        Self {
            start_block,
            end_block,
        }
    }

    /// Create a new block range from length
    pub fn new_from_length(start_block: u64, length: u64) -> Self {
        Self {
            start_block,
            end_block: start_block + length,
        }
    }

    /// Test if a block index is in the range
    pub fn contains(&self, block: u64) -> bool {
        block >= self.start_block && block < self.end_block
    }

    /// Test if a block range is well-formed
    pub fn is_valid(&self) -> bool {
        self.end_block > self.start_block
    }

    /// Test if two block ranges overlap
    pub fn overlaps(&self, other: &BlockRange) -> bool {
        self.start_block < other.end_block && other.start_block < self.end_block
    }

    /// Returns the length of the BlockRange, i.e. the number of blocks.
    pub fn len(&self) -> u64 {
        self.end_block - self.start_block
    }

    /// Returns true if the BlockRange length is 0.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Merge the first contiguous ranges into a range
    ///
    /// The "ranges" input must be pre-sorted by increasing start_block to
    /// produce correct results. Sorting is left to the caller so as to
    /// return a meaningful "index" which indicates an input range that
    /// contains an "end_block" at the top of the first contiguous range of
    /// blocks.
    ///
    /// ```
    /// use mc_fog_types::common::BlockRange;
    ///
    /// let ranges = vec![BlockRange::new(0, 5), BlockRange::new(3, 8), BlockRange::new(8, 10), BlockRange::new(15, 16)];
    /// let (index, merged_range) = BlockRange::merge_from_ranges(ranges.iter()).unwrap();
    /// assert_eq!(index, 2);
    /// assert_eq!(merged_range, BlockRange::new(0, 10));
    ///
    /// let ranges = vec![BlockRange::new(3, 8), BlockRange::new(0, 5), BlockRange::new(8, 10), BlockRange::new(15, 16)];
    /// let (index, merged_range) = BlockRange::merge_from_ranges(ranges.iter()).unwrap();
    /// assert_eq!(index, 0);
    /// assert_eq!(merged_range, BlockRange::new(3, 8));
    /// ```
    ///
    /// Returns the index in `ranges` of the last block range merged, and the
    /// merged range
    pub fn merge_from_ranges<'a>(
        ranges: impl IntoIterator<Item = &'a BlockRange>,
    ) -> Option<(usize, BlockRange)> {
        let mut ranges = ranges.into_iter();
        let first = ranges.next().cloned();
        let mut merged_range = first?;
        let mut index = 0;

        for range in ranges {
            if range.start_block <= merged_range.end_block
                && merged_range.end_block <= range.end_block
            {
                merged_range.end_block = range.end_block;
                index += 1;
            } else {
                break;
            }
        }
        Some((index, merged_range))
    }
}

impl core::fmt::Display for BlockRange {
    fn fmt(&self, formatter: &mut core::fmt::Formatter) -> core::fmt::Result {
        write!(formatter, "[{},{})", self.start_block, self.end_block)
    }
}

impl FromStr for BlockRange {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let block_indices: Vec<u64> = s
            .split(BLOCK_RANGE_DELIMITER)
            .map(|index_str| index_str.trim().parse())
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| "BlockRange index is not a number.")?;
        if block_indices.len() != 2 {
            return Err(format!(
                "Block range is composed of two indices, found {} indices",
                block_indices.len()
            ));
        }
        let result = BlockRange::new(block_indices[0], block_indices[1]);

        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use yare::parameterized;

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

    #[test]
    fn from_string_well_formatted_creates_block_range() {
        let start_block = 0;
        let end_block = 10;
        let block_range_str = format!("{start_block}{BLOCK_RANGE_DELIMITER}{end_block}");

        let result = BlockRange::from_str(&block_range_str);

        assert!(result.is_ok());
        let block_range = result.unwrap();
        assert_eq!(block_range.start_block, start_block);
        assert_eq!(block_range.end_block, end_block);
    }

    #[test]
    fn from_string_well_formatted_with_whitespace_creates_block_range() {
        let start_block = 0;
        let end_block = 10;
        let block_range_str = format!(" {start_block} {BLOCK_RANGE_DELIMITER} {end_block} ");

        let result = BlockRange::from_str(&block_range_str);

        assert!(result.is_ok());
        let block_range = result.unwrap();
        assert_eq!(block_range.start_block, start_block);
        assert_eq!(block_range.end_block, end_block);
    }

    #[test]
    fn from_string_multiple_indices_errors() {
        let start_block = 0;
        let end_block = 10;
        let third_block = 10;
        let block_range_str = format!(
            "{start_block}{BLOCK_RANGE_DELIMITER}{end_block}{BLOCK_RANGE_DELIMITER}{third_block}"
        );

        let result = BlockRange::from_str(&block_range_str);

        assert!(result.is_err());
    }

    #[test]
    fn from_string_non_numbers_errors() {
        let start_block = 'a';
        let end_block = 'b';
        let block_range_str = format!("{start_block}{BLOCK_RANGE_DELIMITER}{end_block}");

        let result = BlockRange::from_str(&block_range_str);

        assert!(result.is_err());
    }

    #[parameterized(
        multiple_ranges = { vec![(0, 5), (3, 8), (8, 10), (15, 16)], 2, (0, 10) },
        single_range = { vec![(0, 10)], 0, (0, 10) },
        all_the_same = { vec![(0, 10), (0, 10), (0, 10)], 2, (0, 10) },
        reverse_order = { vec![(15, 16), (8, 10), (3, 8), (0, 5)], 0, (15, 16) },
        middle_breaks_up_series = { vec![(0, 5), (8, 10), (5, 8)], 0, (0, 5) },
    )]
    fn merge_ranges(ranges: Vec<(u64, u64)>, expected_index: usize, expected_range: (u64, u64)) {
        let ranges = ranges
            .iter()
            .map(|(start, end)| BlockRange::new(*start, *end))
            .collect::<Vec<_>>();
        let expected_range = BlockRange::new(expected_range.0, expected_range.1);
        let (merged_index, merged_range) = BlockRange::merge_from_ranges(ranges.iter()).unwrap();
        assert_eq!(merged_index, expected_index);
        assert_eq!(merged_range, expected_range);
    }

    #[test]
    fn no_range_to_merge() {
        assert_eq!(BlockRange::merge_from_ranges([].iter()), None);
    }
}
