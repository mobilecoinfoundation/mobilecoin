// Copyright (c) 2018-2020 MobileCoin Inc.

use crate::Error;
use common::Hash;
use transaction::{
    ring_signature::KeyImage,
    tx::{TxOut, TxOutMembershipProof},
    Block, BlockContents, BlockSignature,
};

pub trait Ledger: Clone + Send {
    /// Appends a block along with transactions.
    fn append_block(
        &mut self,
        block: &Block,
        block_contents: &BlockContents,
        signature: Option<&BlockSignature>,
    ) -> Result<(), Error>;

    /// Get the total number of blocks in the ledger.
    fn num_blocks(&self) -> Result<u64, Error>;

    /// Gets a Block by its index in the blockchain.
    fn get_block(&self, block_number: u64) -> Result<Block, Error>;

    /// Get the contents of a block.
    fn get_block_contents(&self, block_number: u64) -> Result<BlockContents, Error>;

    /// Gets a block signature by its index in the blockchain.
    fn get_block_signature(&self, block_number: u64) -> Result<BlockSignature, Error>;

    /// Get the total number of TxOuts in the ledger.
    fn num_txos(&self) -> Result<u64, Error>;

    /// Returns the index of the TxOut with the given hash.
    fn get_tx_out_index_by_hash(&self, tx_out_hash: &Hash) -> Result<u64, Error>;

    /// Gets a TxOut by its index in the ledger.
    fn get_tx_out_by_index(&self, index: u64) -> Result<TxOut, Error>;

    /// Gets a proof of memberships for TxOuts with indexes `indexes`.
    fn get_tx_out_proof_of_memberships(
        &self,
        indexes: &[u64],
    ) -> Result<Vec<TxOutMembershipProof>, Error>;

    // /// Get the total number of transactions in the ledger.
    // fn num_txs(&self) -> Result<u64, Error>;
    //
    // /// Gets all transactions associated with a given block.
    // fn get_transactions_by_block(&self, block_number: u64) -> Result<Vec<RedactedTx>, Error>;

    /// Returns true if the Ledger contains the given key image.
    fn contains_key_image(&self, key_image: &KeyImage) -> Result<bool, Error> {
        self.check_key_image(key_image).map(|x| x.is_some())
    }

    /// Checks if the ledger contains a given key image
    /// If so, returns the block height at which it entered the ledger.
    /// Ok(None) is returned when the key image is not in the ledger.
    fn check_key_image(&self, key_image: &KeyImage) -> Result<Option<u64>, Error>;

    /// Gets the key images used by transactions in a single block.
    fn get_key_images_by_block(&self, block_number: u64) -> Result<Vec<KeyImage>, Error>;
}
