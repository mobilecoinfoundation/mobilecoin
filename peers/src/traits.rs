// Copyright (c) 2018-2021 The MobileCoin Foundation

//! Traits and objects specific to peering connections.

use crate::{
    error::{Result, RetryResult},
    ConsensusMsg,
};
use mc_common::{NodeID, ResponderId};
use mc_connection::Connection;
use mc_consensus_api::consensus_peer::ConsensusMsgResponse;
use mc_consensus_enclave_api::{TxContext, WellFormedEncryptedTx};
use mc_transaction_core::tx::TxHash;
use std::time::Duration;

/// A trait which describes a connection from one consensus node to another.
pub trait ConsensusConnection: Connection {
    /// Retrieve the remote peer ResponderId.
    fn remote_responder_id(&self) -> ResponderId;

    /// Retrieve the local node ID.
    fn local_node_id(&self) -> NodeID;

    /// Send the given consensus message to the remote peer.
    fn send_consensus_msg(&mut self, msg: &ConsensusMsg) -> Result<ConsensusMsgResponse>;

    /// Send the given propose tx message to the remote peer.
    fn send_propose_tx(
        &mut self,
        encrypted_tx: &WellFormedEncryptedTx,
        origin_node: &NodeID,
    ) -> Result<()>;

    /// Retrieve encrypted transactions which match the provided hashes.
    fn fetch_txs(&mut self, hashes: &[TxHash]) -> Result<Vec<TxContext>>;

    /// Retrieve the most recent consensus message sent by this peer.
    fn fetch_latest_msg(&mut self) -> Result<Option<ConsensusMsg>>;
}

/// Retriable versions of the ConsensusConnection methods
pub trait RetryableConsensusConnection {
    /// Retrieve the remote peer ResponderId.
    fn remote_responder_id(&self) -> ResponderId;

    /// Retryable version of the consensus message transmitter
    fn send_consensus_msg(
        &self,
        msg: &ConsensusMsg,
        retry_iterator: impl IntoIterator<Item = Duration>,
    ) -> RetryResult<ConsensusMsgResponse>;

    /// Retryable version of the propose tx message transmitter
    fn send_propose_tx(
        &self,
        encrypted_tx: &WellFormedEncryptedTx,
        origin_node: &NodeID,
        retry_iterator: impl IntoIterator<Item = Duration>,
    ) -> RetryResult<()>;

    ///
    fn fetch_txs(
        &self,
        hashes: &[TxHash],
        retry_iterator: impl IntoIterator<Item = Duration>,
    ) -> RetryResult<Vec<TxContext>>;

    fn fetch_latest_msg(
        &self,
        retry_iterator: impl IntoIterator<Item = Duration>,
    ) -> RetryResult<Option<ConsensusMsg>>;
}
