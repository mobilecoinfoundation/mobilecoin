// Copyright (c) 2018-2021 MobileCoin Inc.

//! Traits and objects specific to peering connections.

use crate::connection_error::Result;
use mc_attest_api::attest::Message;
use mc_common::ResponderId;
use mc_connection::Connection;
use mc_crypto_keys::CompressedRistrettoPublic;
use mc_fog_api::ingest_common::IngestSummary;
use mc_fog_uri::IngestPeerUri;
use std::collections::BTreeSet;

/// A trait which describes a connection from one ingest node to another.
pub trait IngestConnection: Connection {
    /// Retrieve the remote peer ResponderId.
    fn remote_responder_id(&self) -> ResponderId;

    /// Retrieve the local node ID.
    fn local_node_id(&self) -> ResponderId;

    /// Get the status of the peer
    fn get_status(&mut self) -> Result<IngestSummary>;

    /// Set the list of peers of the peer
    fn set_peers(&mut self, peers: BTreeSet<IngestPeerUri>) -> Result<IngestSummary>;

    /// Get the ingress private key from the remote peer.
    fn get_ingress_private_key(&mut self) -> Result<Message>;

    /// Send the ingress private key from ourselves to the remote peer.
    ///
    /// Note: The enclave has a thread-safe API to change its private keys.
    /// So, another thread can potentially change the private key of our
    /// enclave, while we are executing this function. That may result in us
    /// not sending the key that we expected to send.
    ///
    /// To avoid races, this also takes the value that we currently think is
    /// our ingress public key.
    ///
    /// If when we get the sealed key from the enclave, it doesn't match this,
    /// this function returns Error::UnexpectedKeyInEnclave, likely indicating a
    /// race. If desired you can then retry.
    fn set_ingress_private_key(
        &mut self,
        current_ingress_public_key: &CompressedRistrettoPublic,
    ) -> Result<IngestSummary>;
}
