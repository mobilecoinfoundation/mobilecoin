// Copyright (c) 2018-2023 The MobileCoin Foundation

use crate::{BlockContentsResponse, BlockProvider, Error};
use mc_blockchain_types::{Block, BlockIndex};
use mc_ledger_db::Ledger;
use mc_transaction_core::tx::{TxOut, TxOutMembershipProof};
use mc_watcher::watcher_db::WatcherDB;
use std::time::Duration;

#[derive(Clone)]
pub struct LocalBlockProvider<L: Ledger + Clone + Sync> {
    ledger: L,
    watcher: Option<WatcherDB>,
}

impl<L: Ledger + Clone + Sync> LocalBlockProvider<L> {
    pub fn new(ledger: L, watcher: impl Into<Option<WatcherDB>>) -> Box<Self> {
        Box::new(Self {
            ledger,
            watcher: watcher.into(),
        })
    }
}

impl<L: Ledger + Clone + Sync> BlockProvider for LocalBlockProvider<L> {
    fn num_blocks(&self) -> Result<u64, Error> {
        Ok(self.ledger.num_blocks()?)
    }

    fn get_latest_block(&self) -> Result<Block, Error> {
        Ok(self.ledger.get_latest_block()?)
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
            .as_ref()
            .expect("poll_block_timestamp requires a watcher")
            .poll_block_timestamp(block_index, watcher_timeout)
    }

    fn get_tx_out_and_membership_proof_by_index(
        &self,
        tx_out_index: u64,
    ) -> Result<(TxOut, TxOutMembershipProof), Error> {
        Ok(self
            .ledger
            .get_tx_out_by_index(tx_out_index)
            .and_then(|tx_out| {
                let proofs = self
                    .ledger
                    .get_tx_out_proof_of_memberships(&[tx_out_index])?;
                Ok((tx_out, proofs[0].clone()))
            })?)
    }
}
