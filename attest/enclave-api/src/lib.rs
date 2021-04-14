// Copyright (c) 2018-2021 The MobileCoin Foundation

//! Common structs used in enclave apis in connection to attestation and
//! attested key exchange

#![no_std]

extern crate alloc;

mod error;

pub use error::{Error, Result};

use alloc::vec::Vec;
use core::hash::Hash;
use mc_attest_core::{QuoteNonce, Report};
use serde::{Deserialize, Serialize};

/// The raw authentication request message, sent from an initiator to a
/// responder
#[derive(Clone, Debug, Default, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub struct ClientAuthRequest(Vec<u8>);

impl From<Vec<u8>> for ClientAuthRequest {
    fn from(src: Vec<u8>) -> Self {
        Self(src)
    }
}

impl From<ClientAuthRequest> for Vec<u8> {
    fn from(src: ClientAuthRequest) -> Vec<u8> {
        src.0
    }
}

/// The raw authentication response message, sent from a responder to an
/// initiator.
#[derive(Clone, Debug, Default, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub struct ClientAuthResponse(Vec<u8>);

impl From<ClientAuthResponse> for Vec<u8> {
    fn from(src: ClientAuthResponse) -> Vec<u8> {
        src.0
    }
}

impl From<Vec<u8>> for ClientAuthResponse {
    fn from(src: Vec<u8>) -> Self {
        Self(src)
    }
}

/// The raw authentication request message, sent from an initiator to a
/// responder
#[derive(Clone, Debug, Default, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub struct PeerAuthRequest(Vec<u8>);

impl From<Vec<u8>> for PeerAuthRequest {
    fn from(src: Vec<u8>) -> Self {
        Self(src)
    }
}

impl From<PeerAuthRequest> for Vec<u8> {
    fn from(src: PeerAuthRequest) -> Vec<u8> {
        src.0
    }
}

/// The raw authentication response message, sent from a responder to an
/// initiator.
#[derive(Clone, Debug, Default, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub struct PeerAuthResponse(Vec<u8>);

impl From<PeerAuthResponse> for Vec<u8> {
    fn from(src: PeerAuthResponse) -> Vec<u8> {
        src.0
    }
}

impl From<Vec<u8>> for PeerAuthResponse {
    fn from(src: Vec<u8>) -> Self {
        Self(src)
    }
}

/// Inbound and outbound messages to/from an enclave.
#[derive(Clone, Debug, Default, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub struct EnclaveMessage<S: Session> {
    /// Authenticated data, if any.
    pub aad: Vec<u8>,
    /// The channel ID of this message.
    pub channel_id: S,
    /// The encrypted payload data of this message.
    pub data: Vec<u8>,
}

/// The response to a request for a new report. The enclave will expect the
/// QuoteNonce to be used when the report is quoted, and both the quote and
/// report to be returned to the enclave during the verify_quote() phase.
#[derive(Clone, Debug, Deserialize, Hash, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct NewEReportResponse {
    pub report: Report,
    pub quote_nonce: QuoteNonce,
}

/// A helper trait to aid in generic implementation of enclave methods
pub trait Session:
    Clone + Default + Eq + Hash + for<'bytes> From<&'bytes [u8]> + Into<Vec<u8>>
{
    type Request: Into<Vec<u8>>;
    type Response: From<Vec<u8>>;
}

/// An opaque bytestream used as a client session
#[derive(Clone, Debug, Default, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub struct ClientSession(pub Vec<u8>);

impl AsRef<[u8]> for ClientSession {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl<'bytes> From<&'bytes [u8]> for ClientSession {
    fn from(src: &[u8]) -> ClientSession {
        Self(Vec::from(src))
    }
}

impl From<Vec<u8>> for ClientSession {
    fn from(src: Vec<u8>) -> ClientSession {
        ClientSession(src)
    }
}

impl From<ClientSession> for Vec<u8> {
    fn from(src: ClientSession) -> Vec<u8> {
        src.0
    }
}

impl Session for ClientSession {
    type Request = ClientAuthRequest;
    type Response = ClientAuthResponse;
}

/// An opaque bytestream used as a peer session ID.
#[derive(Clone, Debug, Default, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub struct PeerSession(Vec<u8>);

impl AsRef<[u8]> for PeerSession {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl<'bytes> From<&'bytes [u8]> for PeerSession {
    fn from(src: &[u8]) -> PeerSession {
        Self(Vec::from(src))
    }
}

impl From<Vec<u8>> for PeerSession {
    fn from(src: Vec<u8>) -> PeerSession {
        PeerSession(src)
    }
}

impl From<PeerSession> for Vec<u8> {
    fn from(src: PeerSession) -> Vec<u8> {
        src.0
    }
}

impl Session for PeerSession {
    type Request = PeerAuthRequest;
    type Response = PeerAuthResponse;
}
