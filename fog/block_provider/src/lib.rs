// Copyright (c) 2018-2023 The MobileCoin Foundation

//! Abstractions for getting ledger db data, either from a local LedgerDB or a
//! remote mobilecoind. Geared towards the specific data fog services require.

mod error;
mod local;
mod mobilecoind;

use dyn_clone::DynClone;
use mc_blockchain_types::{Block, BlockData, BlockIndex};
use mc_crypto_keys::CompressedRistrettoPublic;
use mc_fog_api::ledger::TxOutResult;
use mc_transaction_core::tx::{TxOut, TxOutMembershipProof};
use mc_watcher_api::TimestampResultCode;
use std::time::Duration;

pub use error::Error;
pub use local::LocalBlockProvider;
pub use mobilecoind::MobilecoindBlockProvider;

pub trait BlockProvider: DynClone + Send + Sync {
    /// Get the number of blocks currently in the ledger.
    fn num_blocks(&self) -> Result<u64, Error>;

    /// Get the latest block in the ledger.
    fn get_latest_block(&self) -> Result<Block, Error>;

    /// Get block data of multiple blocks by block number, and in addition get
    /// information about the latest block. Also include block timestamp for
    /// each block, if available.
    fn get_blocks_data(&self, block_indices: &[BlockIndex]) -> Result<BlocksDataResponse, Error>;

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

    /// Convenience method to get a single block data by block number.
    fn get_block_data(&self, block_index: BlockIndex) -> Result<BlockDataResponse, Error> {
        let BlocksDataResponse {
            mut results,
            latest_block,
        } = self.get_blocks_data(&[block_index])?;

        let result = results.pop().flatten().ok_or(Error::NotFound)?;

        Ok(BlockDataResponse {
            result,
            latest_block,
        })
    }
}

dyn_clone::clone_trait_object!(BlockProvider);

#[derive(Clone, Debug)]
pub struct BlockDataWithTimestamp {
    /// The block data.
    pub block_data: BlockData,

    /// Block timestamp, if available (u64::MAX if not).
    pub block_timestamp: u64,

    /// Timestamp result code.
    pub block_timestamp_result_code: TimestampResultCode,
}

#[derive(Clone, Debug)]
pub struct BlocksDataResponse {
    /// Results.
    pub results: Vec<Option<BlockDataWithTimestamp>>,

    /// The latest block.
    pub latest_block: Block,
}

#[derive(Clone, Debug)]
pub struct BlockDataResponse {
    /// Result.
    pub result: BlockDataWithTimestamp,

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
