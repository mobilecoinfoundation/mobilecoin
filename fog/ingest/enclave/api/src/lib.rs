// Copyright (c) 2018-2021 The MobileCoin Foundation

//! APIs for MobileCoin Fog Ingest Node Enclaves

#![no_std]
#![deny(missing_docs)]

extern crate alloc;

mod error;
mod messages;

pub use crate::{
    error::{Error, RotateKeysError},
    messages::{EnclaveCall, IngestEnclaveInitParams},
};

use alloc::vec::Vec;
use core::result::Result as StdResult;
use mc_attest_core::VerificationReport;
use mc_attest_enclave_api::{EnclaveMessage, PeerAuthRequest, PeerAuthResponse, PeerSession};
use mc_common::ResponderId;
use mc_crypto_keys::{CompressedRistrettoPublic, RistrettoPublic, X25519Public};
use mc_fog_kex_rng::KexRngPubkey;
use mc_fog_types::{ingest::TxsForIngest, ETxOutRecord};
use mc_sgx_report_cache_api::ReportableEnclave;

/// A generic result type for enclave calls
pub type Result<T> = StdResult<T, Error>;

/// Type representing the sealed ingest private key
pub type SealedIngestKey = Vec<u8>;

/// The API of the ingest enclave
pub trait IngestEnclave: ReportableEnclave {
    /// Initialize the enclave with its ResponderId
    fn enclave_init(&self, params: IngestEnclaveInitParams) -> Result<()>;

    /// Make new ingress and egress keys, and wipe out ORAM state.
    /// This is similar to re-initializing the enclave and deleting all secrets,
    /// but it doesn't reset AKE state, at least at this revision.
    fn new_keys(&self) -> Result<()>;

    /// Make new egress key, and wipe out ORAM state.
    /// This does not affect ingress key or AKE state.
    /// This is done when we scan a block but it is never published.
    fn new_egress_key(&self) -> Result<()>;

    /// Retrieve the ingress public key of the enclave.
    fn get_ingress_pubkey(&self) -> Result<RistrettoPublic>;

    /// Retrieve the ingress private key of the enclave, sealed to this enclave
    /// The public key corresponding to this value is also returned to help
    /// catch races.
    fn get_sealed_ingress_private_key(
        &self,
    ) -> Result<(SealedIngestKey, CompressedRistrettoPublic)>;

    /// Retrieve the ingress private key of the enclave, encrypted for the peer
    /// The public key corresponding to this value is also returned to help
    /// catch races.
    fn get_ingress_private_key(
        &self,
        peer: PeerSession,
    ) -> Result<(EnclaveMessage<PeerSession>, CompressedRistrettoPublic)>;

    /// Set the private key of the enclave, encrypted by the peer for this
    /// enclave
    fn set_ingress_private_key(
        &self,
        msg: EnclaveMessage<PeerSession>,
    ) -> Result<(RistrettoPublic, SealedIngestKey)>;

    /// Retrieve the current KexRngPubkey for the enclave. This corresponds to
    /// the egress key.
    fn get_kex_rng_pubkey(&self) -> Result<KexRngPubkey>;

    /// Consume all the transactions and emit corresponding rows for the
    /// recovery database
    fn ingest_txs(&self, chunk: TxsForIngest) -> Result<(Vec<ETxOutRecord>, Option<KexRngPubkey>)>;

    /// Retrieve the public identity of the enclave, for peering
    fn get_identity(&self) -> Result<X25519Public>;

    /// Initiate peering with a remote ingest enclave
    fn peer_init(&self, peer_id: &ResponderId) -> Result<PeerAuthRequest>;

    /// Accept a connection proposal from a remote ingest enclave
    fn peer_accept(&self, req: PeerAuthRequest) -> Result<(PeerAuthResponse, PeerSession)>;

    /// Handle the remote peer_accept response to form the connection
    fn peer_connect(
        &self,
        peer_id: &ResponderId,
        msg: PeerAuthResponse,
    ) -> Result<(PeerSession, VerificationReport)>;

    /// Close a connection with a peer
    fn peer_close(&self, session_id: &PeerSession) -> Result<()>;
}

/// Helper trait which reduces boiler-plate in untrusted side
/// The trusted object which implements the above api usually cannot implement
/// Clone, Send, Sync, etc., but the untrusted side can and usually having a
/// "handle to an enclave" is what is most useful for a webserver.
/// This marker trait can be implemented for the untrusted-side representation
/// of the enclave.
pub trait IngestEnclaveProxy: IngestEnclave + Clone + Send + Sync + 'static {}

impl<T> IngestEnclaveProxy for T where T: IngestEnclave + Clone + Send + Sync + 'static {}
