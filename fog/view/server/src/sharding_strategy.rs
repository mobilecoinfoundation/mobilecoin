// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Enables a Fog View Store to know for which blocks to process TxOuts.
//!
//! By determining which TxOuts to process, we are able to "shard" the set of
//! TxOuts across Fog View Store instances.

use mc_blockchain_types::BlockIndex;
use mc_fog_types::common::BlockRange;

/// Tells a Fog View Store for which blocks it should process TxOuts.
pub trait ShardingStrategy {
    /// Returns true if the Fog View Store should process this block.
    fn should_process_block(&self, block_index: BlockIndex) -> bool;
}

/// Determines whether or not to process a block's TxOuts based on the "epoch"
/// sharding strategy, in which a block is processed IFF it falls within the
/// contiguous range of blocks.
///
/// In practice, the set of Fog View Shards will contain overlapping
/// [epoch_block_ranges] in order to obfuscate which shard processed the TxOuts.
#[derive(Clone)]
pub struct EpochShardingStrategy {
    /// If a block falls within this range, then the Fog View Store should
    /// process its TxOuts.
    epoch_block_range: BlockRange,
}

impl ShardingStrategy for EpochShardingStrategy {
    fn should_process_block(&self, block_index: BlockIndex) -> bool {
        self.epoch_block_range.contains(block_index)
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
}
