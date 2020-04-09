// Copyright (c) 2018-2020 MobileCoin Inc.

//! Mix-in application of local peers traits to SyncConnection.

use crate::{
    consensus_msg::ConsensusMsg,
    error::RetryResult,
    traits::{ConsensusConnection, RetryableConsensusConnection},
};
use common::{NodeID, ResponderId};
use consensus_enclave_api::{TxContext, WellFormedEncryptedTx};
use mcconnection::{impl_sync_connection_retry, SyncConnection};
use std::time::Duration;
use transaction::tx::TxHash;

/// Blanket implementation of RetryableConsensusConnection for SyncConnection objects which own a
/// ConsensusConnection.
impl<CC: ConsensusConnection> RetryableConsensusConnection for SyncConnection<CC> {
    fn remote_responder_id(&self) -> ResponderId {
        self.read().remote_responder_id()
    }

    fn send_consensus_msg(
        &self,
        msg: &ConsensusMsg,
        retry_iterator: impl IntoIterator<Item = Duration>,
    ) -> RetryResult<()> {
        impl_sync_connection_retry!(
            self.write(),
            self.logger(),
            send_consensus_msg,
            retry_iterator,
            msg
        )
    }

    fn send_propose_tx(
        &self,
        encrypted_tx: &WellFormedEncryptedTx,
        origin_node: &NodeID,
        retry_iterator: impl IntoIterator<Item = Duration>,
    ) -> RetryResult<()> {
        impl_sync_connection_retry!(
            self.write(),
            self.logger(),
            send_propose_tx,
            retry_iterator,
            encrypted_tx,
            origin_node
        )
    }

    fn fetch_txs(
        &self,
        hashes: &[TxHash],
        retry_iterator: impl IntoIterator<Item = Duration>,
    ) -> RetryResult<Vec<TxContext>> {
        impl_sync_connection_retry!(
            self.write(),
            self.logger(),
            fetch_txs,
            retry_iterator,
            hashes
        )
    }

    fn fetch_latest_msg(
        &self,
        retry_iterator: impl IntoIterator<Item = Duration>,
    ) -> RetryResult<Option<ConsensusMsg>> {
        impl_sync_connection_retry!(
            self.write(),
            self.logger(),
            fetch_latest_msg,
            retry_iterator
        )
    }
}
