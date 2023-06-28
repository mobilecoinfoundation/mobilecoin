// Copyright (c) 2018-2023 The MobileCoin Foundation

use mc_blockchain_types::{Block, BlockContents, BlockMetadata};
use mc_common::logger::{log, Logger};
use mc_transaction_core::tx::TxOut;

// A sync which can send interesting blocks and metadata found by the relayer to
// its intended destination.
pub trait Sender {
    fn send(
        &mut self,
        outputs: Vec<TxOut>,
        block: &Block,
        block_contents: &BlockContents,
        block_metadata: Vec<BlockMetadata>,
    );
}

/// A dummy sender which just logs anything that is sent.
pub struct DummySender {
    pub logger: Logger,
}

impl Sender for DummySender {
    fn send(
        &mut self,
        outputs: Vec<TxOut>,
        block: &Block,
        _block_contents: &BlockContents,
        block_metadata: Vec<BlockMetadata>,
    ) {
        log::info!(
            self.logger,
            "Dummy sender: Got {} outputs and {} signatures to be sent in connection to block {}",
            outputs.len(),
            block_metadata.len(),
            block.index
        );
    }
}
