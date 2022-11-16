// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Enables a Key Image Store to know for which blocks to process key images.
//!
//! By determining which key images to process, we are able to "shard" the set
//! of key images across Key Image Store instances.

use mc_blockchain_types::BlockIndex;
use mc_fog_types::{common::BlockRange, BlockCount};
use serde::Serialize;
use std::str::FromStr;

/// Tells a Key Image Store for which blocks it should process key images.
pub trait ShardingStrategy {
    /// Returns true if the Key Image Store should process this block.
    fn should_process_block(&self, block_index: BlockIndex) -> bool;

    /// Returns true if the Key Image Store is ready to serve key images to the
    /// client.
    ///
    /// Different sharding strategies might be ready to serve key images when
    /// different conditions have been met.
    fn ready(&self, processed_block_count: BlockCount) -> bool;

    /// Returns the block range that this sharding strategy is responsible for.
    fn get_block_range(&self) -> BlockRange;
}

/// Determines whether or not to process a block's key images based on the
/// "epoch" sharding strategy, in which a block is processed IFF it falls within
/// the contiguous range of blocks.
///
/// In practice, the set of Key Image Shards will contain overlapping
/// [epoch_block_ranges] in order to obfuscate which shard processed the key
/// images.
#[derive(Clone, Serialize)]
pub struct EpochShardingStrategy {
    /// If a block falls within this range, then the Key Image Store should
    /// process its key images.
    epoch_block_range: BlockRange,
}

impl ShardingStrategy for EpochShardingStrategy {
    fn should_process_block(&self, block_index: BlockIndex) -> bool {
        self.epoch_block_range.contains(block_index)
    }

    fn ready(&self, processed_block_count: BlockCount) -> bool {
        self.have_enough_blocks_been_processed(processed_block_count)
    }

    fn get_block_range(&self) -> BlockRange {
        self.epoch_block_range.clone()
    }
}

impl Default for EpochShardingStrategy {
    fn default() -> Self {
        Self {
            epoch_block_range: BlockRange::new(0, u64::MAX),
        }
    }
}

impl EpochShardingStrategy {
    #[allow(dead_code)]
    pub fn new(epoch_block_range: BlockRange) -> Self {
        Self { epoch_block_range }
    }

    fn have_enough_blocks_been_processed(&self, processed_block_count: BlockCount) -> bool {
        if self.is_first_epoch() {
            return true;
        }

        let epoch_block_range_length =
            self.epoch_block_range.end_block - self.epoch_block_range.start_block;
        let minimum_processed_block_count = epoch_block_range_length / 2;

        u64::from(processed_block_count) >= minimum_processed_block_count
    }

    fn is_first_epoch(&self) -> bool {
        self.epoch_block_range.start_block == 0
    }
}

impl FromStr for EpochShardingStrategy {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if let Ok(block_range) = BlockRange::from_str(s) {
            return Ok(Self::new(block_range));
        }

        Err("Invalid epoch sharding strategy.".to_string())
    }
}

#[cfg(test)]
mod epoch_sharding_strategy_tests {
    use super::*;

    #[test]
    fn should_process_block_block_index_is_before_epoch_start_returns_false() {
        const START_BLOCK: BlockIndex = 50;
        const END_BLOCK_EXCLUSIVE: BlockIndex = 100;
        let epoch_block_range = BlockRange::new(START_BLOCK, END_BLOCK_EXCLUSIVE);
        let epoch_sharding_strategy = EpochShardingStrategy::new(epoch_block_range);

        let should_process_block = epoch_sharding_strategy.should_process_block(START_BLOCK - 1);

        assert!(!should_process_block)
    }

    #[test]
    fn should_process_block_block_index_is_epoch_start_returns_true() {
        const START_BLOCK: BlockIndex = 50;
        const END_BLOCK_EXCLUSIVE: BlockIndex = 100;
        let epoch_block_range = BlockRange::new(START_BLOCK, END_BLOCK_EXCLUSIVE);
        let epoch_sharding_strategy = EpochShardingStrategy::new(epoch_block_range);

        let should_process_block = epoch_sharding_strategy.should_process_block(START_BLOCK);

        assert!(should_process_block)
    }

    #[test]
    fn should_process_block_block_index_is_in_epoch_block_range_returns_true() {
        const START_BLOCK: BlockIndex = 50;
        const END_BLOCK_EXCLUSIVE: BlockIndex = 100;
        let included_block_index = ((END_BLOCK_EXCLUSIVE - START_BLOCK) / 2) + START_BLOCK;
        let epoch_block_range = BlockRange::new(START_BLOCK, END_BLOCK_EXCLUSIVE);
        let epoch_sharding_strategy = EpochShardingStrategy::new(epoch_block_range);

        let should_process_block =
            epoch_sharding_strategy.should_process_block(included_block_index);

        assert!(should_process_block)
    }

    #[test]
    fn should_process_block_block_index_is_one_before_epoch_end_block_range_returns_true() {
        const START_BLOCK: BlockIndex = 50;
        const END_BLOCK_EXCLUSIVE: BlockIndex = 100;
        let epoch_block_range = BlockRange::new(START_BLOCK, END_BLOCK_EXCLUSIVE);
        let epoch_sharding_strategy = EpochShardingStrategy::new(epoch_block_range);
        let should_process_block =
            epoch_sharding_strategy.should_process_block(END_BLOCK_EXCLUSIVE - 1);
        assert!(should_process_block)
    }

    #[test]
    fn should_process_block_block_index_is_epoch_end_block_range_returns_false() {
        const START_BLOCK: BlockIndex = 50;
        const END_BLOCK_EXCLUSIVE: BlockIndex = 100;
        let epoch_block_range = BlockRange::new(START_BLOCK, END_BLOCK_EXCLUSIVE);
        let epoch_sharding_strategy = EpochShardingStrategy::new(epoch_block_range);

        let should_process_block =
            epoch_sharding_strategy.should_process_block(END_BLOCK_EXCLUSIVE);

        assert!(!should_process_block)
    }

    #[test]
    fn should_process_block_block_index_is_after_epoch_end_block_range_returns_false() {
        const START_BLOCK: BlockIndex = 50;
        const END_BLOCK_EXCLUSIVE: BlockIndex = 100;
        let epoch_block_range = BlockRange::new(START_BLOCK, END_BLOCK_EXCLUSIVE);
        let epoch_sharding_strategy = EpochShardingStrategy::new(epoch_block_range);

        let should_process_block =
            epoch_sharding_strategy.should_process_block(END_BLOCK_EXCLUSIVE + 1);

        assert!(!should_process_block)
    }

    #[test]
    fn ready_allows_0_in_0_to_100_shard() {
        // The first epoch has a start block == 0.
        const START_BLOCK: BlockIndex = 0;
        const END_BLOCK_EXCLUSIVE: BlockIndex = 100;
        let epoch_block_range = BlockRange::new(START_BLOCK, END_BLOCK_EXCLUSIVE);
        let epoch_sharding_strategy = EpochShardingStrategy::new(epoch_block_range);

        let ready = epoch_sharding_strategy.ready(0.into());

        assert!(ready)
    }

    #[test]
    fn ready_to_serve_allows_70_in_0_to_100_shard() {
        // The first epoch has a start block == 0.
        const START_BLOCK: BlockIndex = 0;
        const END_BLOCK_EXCLUSIVE: BlockIndex = 100;
        let epoch_block_range = BlockRange::new(START_BLOCK, END_BLOCK_EXCLUSIVE);
        let epoch_sharding_strategy = EpochShardingStrategy::new(epoch_block_range);

        let ready = epoch_sharding_strategy.ready(70.into());

        assert!(ready)
    }

    #[test]
    fn ready_not_first_shard_prevents_less_than_minimum() {
        const START_BLOCK: BlockIndex = 100;
        const END_BLOCK_EXCLUSIVE: BlockIndex = 111;
        let epoch_block_range_length = END_BLOCK_EXCLUSIVE - START_BLOCK;
        let minimum_processed_block_count = epoch_block_range_length / 2;
        let epoch_block_range = BlockRange::new(START_BLOCK, END_BLOCK_EXCLUSIVE);
        let epoch_sharding_strategy = EpochShardingStrategy::new(epoch_block_range);

        let ready = epoch_sharding_strategy.ready((minimum_processed_block_count - 1).into());

        assert!(!ready)
    }

    #[test]
    fn ready_not_first_shard_allows_minimum() {
        const START_BLOCK: BlockIndex = 100;
        const END_BLOCK_EXCLUSIVE: BlockIndex = 111;
        let epoch_block_range_length = END_BLOCK_EXCLUSIVE - START_BLOCK;
        let minimum_processed_block_count = epoch_block_range_length / 2;
        let epoch_block_range = BlockRange::new(START_BLOCK, END_BLOCK_EXCLUSIVE);
        let epoch_sharding_strategy = EpochShardingStrategy::new(epoch_block_range);

        let ready = epoch_sharding_strategy.ready(minimum_processed_block_count.into());

        assert!(ready)
    }

    #[test]
    fn ready_not_first_shard_allows_over_minimum() {
        const START_BLOCK: BlockIndex = 100;
        const END_BLOCK_EXCLUSIVE: BlockIndex = 110;
        let epoch_block_range_length = END_BLOCK_EXCLUSIVE - START_BLOCK;
        let minimum_processed_block_count = epoch_block_range_length / 2;
        let epoch_block_range = BlockRange::new(START_BLOCK, END_BLOCK_EXCLUSIVE);
        let epoch_sharding_strategy = EpochShardingStrategy::new(epoch_block_range);

        let ready = epoch_sharding_strategy.ready((minimum_processed_block_count + 1).into());

        assert!(ready)
    }
}
