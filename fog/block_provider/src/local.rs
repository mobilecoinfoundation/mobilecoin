// Copyright (c) 2018-2023 The MobileCoin Foundation

use crate::{BlockContentsResponse, BlockProvider, Error};
use mc_blockchain_types::BlockIndex;
use mc_ledger_db::Ledger;
use mc_watcher::watcher_db::WatcherDB;
use std::time::Duration;

pub struct LocalBlockProvider<L: Ledger> {
    ledger: L,
    watcher: WatcherDB,
}

impl<L: Ledger> LocalBlockProvider<L> {
    pub fn new(ledger: L, watcher: WatcherDB) -> Box<Self> {
        Box::new(Self { ledger, watcher })
    }
}

impl<L: Ledger> BlockProvider for LocalBlockProvider<L> {
    fn num_blocks(&self) -> Result<u64, Error> {
        Ok(self.ledger.num_blocks()?)
    }

    fn get_block_contents(&self, block_index: BlockIndex) -> Result<BlockContentsResponse, Error> {
        let block_contents = self.ledger.get_block_contents(block_index)?;
        let latest_block = self.ledger.get_latest_block()?;
        Ok(BlockContentsResponse {
            block_contents,
            latest_block,
        })
    }

    fn poll_block_timestamp(&self, block_index: BlockIndex, watcher_timeout: Duration) -> u64 {
        self.watcher
            .poll_block_timestamp(block_index, watcher_timeout)
    }
}
