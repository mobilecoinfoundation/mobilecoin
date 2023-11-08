// Copyright (c) 2018-2023 The MobileCoin Foundation

//! Abstractions for getting ledger db data, either from a local LedgerDB or a
//! remote mobilecoind. Geared towards the specific data fog services require.

mod error;
mod local;

use dyn_clone::DynClone;
use mc_blockchain_types::{Block, BlockContents, BlockIndex};
use mc_crypto_keys::CompressedRistrettoPublic;
use mc_fog_api::ledger::TxOutResult;
use mc_transaction_core::tx::{TxOut, TxOutMembershipProof};
use std::time::Duration;

pub use error::Error;
pub use local::LocalBlockProvider;

pub trait BlockProvider: DynClone + Send + Sync {
    /// Get the number of blocks currently in the ledger.
    fn num_blocks(&self) -> Result<u64, Error>;

    /// Get the latest block in the ledger.
    fn get_latest_block(&self) -> Result<Block, Error>;

    /// Get block contents by block number, and in addition get information
    /// about the latest block.
    fn get_block_contents(&self, block_index: BlockIndex) -> Result<BlockContentsResponse, Error>;

    /// Poll indefinitely for a watcher timestamp, logging warnings if we wait
    /// for more than watcher_timeout.
    fn poll_block_timestamp(&self, block_index: BlockIndex, watcher_timeout: Duration) -> u64;

    /// Get TxOut and membership proof by tx out index.
    fn get_tx_out_and_membership_proof_by_index(
        &self,
        tx_out_index: u64,
    ) -> Result<(TxOut, TxOutMembershipProof), Error>;

    /// Get information about multiple TxOuts by their public keys, and in
    /// addition get information about the latest block.
    fn get_tx_out_info_by_public_key(
        &self,
        tx_out_pub_keys: &[CompressedRistrettoPublic],
    ) -> Result<TxOutInfoByPublicKeyResponse, Error>;
}

dyn_clone::clone_trait_object!(BlockProvider);

#[derive(Clone, Debug)]
pub struct BlockContentsResponse {
    /// The block contents.
    pub block_contents: BlockContents,

    /// The latest block.
    pub latest_block: Block,
}

#[derive(Clone, Debug)]
pub struct TxOutInfoByPublicKeyResponse {
    /// Reuslts.
    pub results: Vec<TxOutResult>,

    /// The latest block.
    pub latest_block: Block,
}
