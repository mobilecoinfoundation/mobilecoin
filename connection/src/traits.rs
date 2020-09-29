// Copyright (c) 2018-2020 MobileCoin Inc.

//! Traits which connection implementations can implement.

use crate::error::{Result, RetryResult};
use grpcio::{Error as GrpcError, RpcStatusCode};
use mc_transaction_core::{tx::Tx, Block, BlockID, BlockIndex};
use mc_util_uri::ConnectionUri;
use std::{
    fmt::{Debug, Display},
    hash::Hash,
    ops::Range,
    result::Result as StdResult,
    time::Duration,
};

/// A base connection trait, applicable to all connections.
pub trait Connection: Display + Eq + Hash + Ord + PartialEq + PartialOrd + Send + Sync {
    type Uri: ConnectionUri;

    fn uri(&self) -> Self::Uri;
}

/// A marker trait used to encapsulate connection-impl-specific attestation errors.
pub trait AttestationError: Debug + Display + Send + Sync {}

pub trait AttestedConnection: Connection {
    type Error: AttestationError + From<GrpcError>;

    fn is_attested(&self) -> bool;

    fn attest(&mut self) -> StdResult<(), Self::Error>;

    fn deattest(&mut self);

    fn attested_call<T>(
        &mut self,
        func: impl FnOnce(&mut Self) -> StdResult<T, GrpcError>,
    ) -> StdResult<T, Self::Error> {
        if !self.is_attested() {
            self.attest()?;
        }

        let result = func(self);

        if let Err(GrpcError::RpcFailure(rpc_status)) = &result {
            if rpc_status.status == RpcStatusCode::PERMISSION_DENIED {
                self.deattest();
            }
        }

        Ok(result?)
    }
}

/// A connection trait providing APIs for use in retrieving blocks from a consensus node.
pub trait BlockchainConnection: Connection {
    /// Retrieve the block metadata from the blockchain service.
    fn fetch_blocks(&mut self, range: Range<BlockIndex>) -> Result<Vec<Block>>;

    /// Retrieve the BlockIDs (hashes) of the given blocks from the blockchain service.
    fn fetch_block_ids(&mut self, range: Range<BlockIndex>) -> Result<Vec<BlockID>>;

    /// Retrieve the consensus node's current block height
    fn fetch_block_height(&mut self) -> Result<BlockIndex>;
}

/// A trait which supports supporting the submission of transactions to a node
pub trait UserTxConnection: Connection {
    /// Propose a transaction over the encrypted channel.
    /// Returns the number of blocks in the ledger at the time the call was received.
    fn propose_tx(&mut self, tx: &Tx) -> Result<BlockIndex>;
}

// Retryable connections: these traits exist to allow SyncConnection to extend itself when its
// inner connection API supports additional APIs.

/// A connection trait providing retryable blockchain data APIs
pub trait RetryableBlockchainConnection {
    /// Retrieve the block metadata from the blockchain service.
    fn fetch_blocks(
        &self,
        range: Range<BlockIndex>,
        retry_iterator: impl IntoIterator<Item = Duration>,
    ) -> RetryResult<Vec<Block>>;

    /// Retrieve the BlockIDs (hashes) of the given blocks from the blockchain service.
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
}

/// A trait which supports re-trying transaction submission
pub trait RetryableUserTxConnection {
    /// Propose a transaction over the encrypted channel.
    /// Returns the number of blocks in the ledger at the time the call was received.
    fn propose_tx(
        &self,
        tx: &Tx,
        retry_iterator: impl IntoIterator<Item = Duration>,
    ) -> RetryResult<BlockIndex>;
}
