// Copyright (c) 2018-2021 The MobileCoin Foundation

//! Traits which connection implementations can implement.

use crate::error::{Result, RetryResult};
use grpcio::Error as GrpcError;
use mc_attest_core::VerificationReport;
use mc_consensus_api::consensus_common::LastBlockInfoResponse;
use mc_transaction_core::{tokens::Mob, tx::Tx, Block, BlockID, BlockIndex, Token, TokenId};
use mc_util_serial::prost::alloc::fmt::Formatter;
use mc_util_uri::ConnectionUri;
use std::{
    collections::BTreeMap,
    fmt::{Debug, Display, Result as FmtResult},
    hash::Hash,
    iter::FromIterator,
    ops::Range,
    result::Result as StdResult,
    time::Duration,
};

/// A base connection trait, applicable to all connections.
pub trait Connection: Display + Eq + Hash + Ord + PartialEq + PartialOrd + Send + Sync {
    type Uri: ConnectionUri;

    fn uri(&self) -> Self::Uri;
}

/// A marker trait used to encapsulate connection-impl-specific attestation
/// errors.
pub trait AttestationError: Debug + Display + Send + Sync {}

pub trait AttestedConnection: Connection {
    type Error: AttestationError + From<GrpcError>;

    fn is_attested(&self) -> bool;

    fn attest(&mut self) -> StdResult<VerificationReport, Self::Error>;

    fn deattest(&mut self);

    fn attested_call<T>(
        &mut self,
        func: impl FnOnce(&mut Self) -> StdResult<T, GrpcError>,
    ) -> StdResult<T, Self::Error> {
        if !self.is_attested() {
            let _verification_report = self.attest()?;
        }

        let result = func(self);

        if let Err(GrpcError::RpcFailure(_rpc_status)) = &result {
            self.deattest();
        }

        Ok(result?)
    }
}

/// A structure meant to contain the results of a GetLastBlockInfo response
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct BlockInfo {
    /// The index of the last block (aka the block height)
    pub block_index: BlockIndex,

    /// Minimum fee for each token id supported by the node
    pub minimum_fees: BTreeMap<TokenId, u64>,
}

impl BlockInfo {
    /// Returns the minimum fee for a given token id, or None if no fee was
    /// available OR if it was zero.
    pub fn minimum_fee_or_none(&self, token_id: &TokenId) -> Option<u64> {
        match self.minimum_fees.get(&token_id) {
            None | Some(&0) => None,
            Some(fee) => Some(*fee),
        }
    }
}

impl Display for BlockInfo {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        write!(
            f,
            "Block {} with minimum fess {:?}",
            self.block_index, self.minimum_fees
        )
    }
}

impl From<LastBlockInfoResponse> for BlockInfo {
    fn from(src: LastBlockInfoResponse) -> Self {
        // Needed for nodes that do not yet return the fee map.
        let minimum_fees = if src.minimum_fees.is_empty() {
            BTreeMap::from_iter([(Mob::ID, src.mob_minimum_fee)])
        } else {
            BTreeMap::from_iter(
                src.minimum_fees
                    .iter()
                    .map(|(token_id, fee)| (TokenId::from(*token_id), *fee)),
            )
        };

        BlockInfo {
            block_index: src.index,
            minimum_fees,
        }
    }
}

/// A connection trait providing APIs for use in retrieving blocks from a
/// consensus node.
pub trait BlockchainConnection: Connection {
    /// Retrieve the block metadata from the blockchain service.
    fn fetch_blocks(&mut self, range: Range<BlockIndex>) -> Result<Vec<Block>>;

    /// Retrieve the BlockIDs (hashes) of the given blocks from the blockchain
    /// service.
    fn fetch_block_ids(&mut self, range: Range<BlockIndex>) -> Result<Vec<BlockID>>;

    /// Retrieve the consensus node's current block height
    fn fetch_block_height(&mut self) -> Result<BlockIndex>;

    /// Retrieve the consensus node's current block height and fee
    fn fetch_block_info(&mut self) -> Result<BlockInfo>;
}

/// A trait which supports supporting the submission of transactions to a node
pub trait UserTxConnection: Connection {
    /// Propose a transaction over the encrypted channel.
    /// Returns the number of blocks in the ledger at the time the call was
    /// received.
    fn propose_tx(&mut self, tx: &Tx) -> Result<u64>;
}

// Retryable connections: these traits exist to allow SyncConnection to extend
// itself when its inner connection API supports additional APIs.

/// A connection trait providing retryable blockchain data APIs
pub trait RetryableBlockchainConnection {
    /// Retrieve the block metadata from the blockchain service.
    fn fetch_blocks(
        &self,
        range: Range<BlockIndex>,
        retry_iterator: impl IntoIterator<Item = Duration>,
    ) -> RetryResult<Vec<Block>>;

    /// Retrieve the BlockIDs (hashes) of the given blocks from the blockchain
    /// service.
    fn fetch_block_ids(
        &self,
        range: Range<BlockIndex>,
        retry_iterator: impl IntoIterator<Item = Duration>,
    ) -> RetryResult<Vec<BlockID>>;

    /// Retrieve the highest block index published
    fn fetch_block_height(
        &self,
        retry_iterator: impl IntoIterator<Item = Duration>,
    ) -> RetryResult<BlockIndex>;

    /// Retrieve the highest block index published
    fn fetch_block_info(
        &self,
        retry_iterator: impl IntoIterator<Item = Duration>,
    ) -> RetryResult<BlockInfo>;
}

/// A trait which supports re-trying transaction submission
pub trait RetryableUserTxConnection {
    /// Propose a transaction over the encrypted channel.
    /// Returns the number of blocks in the ledger at the time the call was
    /// received.
    fn propose_tx(
        &self,
        tx: &Tx,
        retry_iterator: impl IntoIterator<Item = Duration>,
    ) -> RetryResult<BlockIndex>;
}
