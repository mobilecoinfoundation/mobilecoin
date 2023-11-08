// Copyright (c) 2018-2023 The MobileCoin Foundation

//! Abstractions for getting ledger db data, either from a local LedgerDB or a
//! remote mobilecoind. Geared towards the specific data fog services require.

mod error;
mod local;

use mc_blockchain_types::{Block, BlockContents, BlockIndex};
use std::time::Duration;

pub use error::Error;
pub use local::LocalBlockProvider;

pub trait BlockProvider: Send {
    /// Get the number of blocks currently in the ledger.
    fn num_blocks(&self) -> Result<u64, Error>;

    /// Get block contents by block number, and in addition get information
    /// about the latest block.
    fn get_block_contents(&self, block_index: BlockIndex) -> Result<BlockContentsResponse, Error>;

    /// Poll indefinitely for a watcher timestamp, logging warnings if we wait
    /// for more than watcher_timeout.
    fn poll_block_timestamp(&self, block_index: BlockIndex, watcher_timeout: Duration) -> u64;
}

#[derive(Clone, Debug)]
pub struct BlockContentsResponse {
    /// The block contents.
    pub block_contents: BlockContents,

    /// The latest block
    pub latest_block: Block,
}
