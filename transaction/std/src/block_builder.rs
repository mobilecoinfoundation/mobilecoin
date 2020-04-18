// Copyright (c) 2018-2020 MobileCoin Inc.

use transaction::{
    tx::{Tx, TxOutMembershipElement},
    Block, BlockID, RedactedTx, BLOCK_VERSION,
};

#[derive(Debug)]
pub struct BlockBuilder {
    parent_block: Option<Block>,
    root_element: TxOutMembershipElement,
    transactions: Vec<Tx>,
}

impl BlockBuilder {
    pub fn new(parent_block: Option<Block>, root_element: TxOutMembershipElement) -> Self {
        BlockBuilder {
            parent_block,
            root_element,
            transactions: Vec::new(),
        }
    }

    pub fn add_transaction(&mut self, tx: Tx) -> &mut Self {
        self.transactions.push(tx);
        self
    }

    pub fn add_transactions(&mut self, transactions: Vec<Tx>) -> &mut Self {
        self.transactions.extend(transactions);
        self
    }

    pub fn build(&self) -> (Block, Vec<RedactedTx>) {
        // Convert to "persistence-type" transactions.
        let redacted_transactions: Vec<RedactedTx> = self
            .transactions
            .iter()
            .cloned()
            .map(|tx| tx.redact())
            .collect();

        // Get parent block id
        let parent_id = self
            .parent_block
            .as_ref()
            .map(|block| block.id.clone())
            .unwrap_or_else(BlockID::default);

        // Create block
        let new_block_index = self
            .parent_block
            .as_ref()
            .map_or(0, |block| block.index + 1);
        let new_cumulative_txo_count = self
            .parent_block
            .as_ref()
            .map_or(0, |block| block.cumulative_txo_count)
            + redacted_transactions.len() as u64;
        let block = Block::new(
            BLOCK_VERSION,
            &parent_id,
            new_block_index,
            new_cumulative_txo_count,
            &self.root_element,
            &redacted_transactions,
        );
        (block, redacted_transactions)
    }
}
