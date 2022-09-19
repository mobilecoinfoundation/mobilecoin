// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Common structs used in enclave apis in connection to attestation and
//! attested key exchange

#![no_std]

extern crate alloc;

mod error;

pub use error::{Error, Result};

use alloc::vec::Vec;
use core::hash::{Hash, Hasher};
use mc_attest_core::{IntelSealed, QuoteNonce, Report};
use serde::{Deserialize, Serialize};

macro_rules! impl_newtype_vec_inout {
    ($($newtype:ident;)*) => {$(
        impl From<alloc::vec::Vec<u8>> for $newtype {
            fn from(src: alloc::vec::Vec<u8>) -> $newtype {
                $newtype(src)
            }
        }

        impl From<$newtype> for alloc::vec::Vec<u8> {
            fn from(src: $newtype) -> alloc::vec::Vec<u8> {
                src.0
            }
        }
    )*}
}

impl_newtype_vec_inout! {
    ClientAuthRequest; ClientAuthResponse; ClientSession;
    PeerAuthRequest; PeerAuthResponse; PeerSession;
    NonceAuthRequest; NonceAuthResponse;
}

/// The raw authentication request message, sent from an initiator to a
/// responder
#[derive(Clone, Debug, Default, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub struct ClientAuthRequest(Vec<u8>);

/// The raw authentication response message, sent from a responder to an
/// initiator.
#[derive(Clone, Debug, Default, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub struct ClientAuthResponse(Vec<u8>);

/// The raw authentication request message, sent from an initiator to a
/// responder
#[derive(Clone, Debug, Default, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub struct PeerAuthRequest(Vec<u8>);

/// The raw authentication response message, sent from a responder to an
/// initiator.
#[derive(Clone, Debug, Default, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub struct PeerAuthResponse(Vec<u8>);

/// The raw authentication request message, sent from an initiator to a
/// responder.
#[derive(Clone, Debug, Default, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub struct NonceAuthRequest(Vec<u8>);

/// The raw authentication response message, sent from a responder to an
/// initiator.
#[derive(Clone, Debug, Default, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub struct NonceAuthResponse(Vec<u8>);

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

/// An EnclaveMessage<ClientSession> sealed for the current enclave
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SealedClientMessage {
    pub aad: Vec<u8>,
    pub channel_id: ClientSession,
    pub data: IntelSealed,
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
    Clone + Default + Hash + for<'bytes> From<&'bytes [u8]> + Into<Vec<u8>> + PartialEq + PartialOrd
{
    type Request: Into<Vec<u8>>;
    type Response: From<Vec<u8>>;
}

macro_rules! impl_newtype_asref_and_from_bytes {
    ($($newtype:ident;)*) => {$(
        impl AsRef<[u8]> for $newtype {
            fn as_ref(&self) -> &[u8] {
                self.0.as_ref()
            }
        }

        impl<'bytes> From<&'bytes [u8]> for $newtype {
            fn from(src: &[u8]) -> $newtype {
                Self(alloc::vec::Vec::from(src))
            }
        }
    )*}
}

impl_newtype_asref_and_from_bytes! {
    ClientSession; PeerSession;
}

/// An opaque bytestream used as a client session
#[derive(Clone, Debug, Default, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub struct ClientSession(Vec<u8>);

impl Session for ClientSession {
    type Request = ClientAuthRequest;
    type Response = ClientAuthResponse;
}

/// An opaque bytestream used as a peer session ID.
#[derive(Clone, Debug, Default, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub struct PeerSession(Vec<u8>);

impl Session for PeerSession {
    type Request = PeerAuthRequest;
    type Response = PeerAuthResponse;
}

/// An opaque bytestream used as a session ID for a session which uses explicit
/// nonces.
#[derive(Clone, Debug, Default, Deserialize, PartialOrd, Serialize)]
pub struct NonceSession {
    channel_id: Vec<u8>,
    nonce: u64,
}

impl NonceSession {
    /// Create a new nonce session from a vector and nonce.
    ///
    /// This takes a pre-created Vec in order to remove an extra allocation that
    /// would be required when converting from a NonceMessage to an
    /// [`EnclaveMessage`]`<`[`NonceSession`]`>`.
    pub fn new(channel_id: Vec<u8>, nonce: u64) -> Self {
        Self { channel_id, nonce }
    }

    /// Retrieves the nonce for this session
    pub fn peek_nonce(&self) -> u64 {
        self.nonce
    }

    /// Retrieves a copy of the nonce, and increments it for the next time.
    pub fn get_nonce(&mut self) -> u64 {
        let retval = self.nonce;
        self.nonce += 1;
        retval
    }
}

impl AsRef<[u8]> for NonceSession {
    fn as_ref(&self) -> &[u8] {
        self.channel_id.as_ref()
    }
}

impl<'bytes> From<&'bytes [u8]> for NonceSession {
    fn from(src: &'bytes [u8]) -> Self {
        Self::from(Vec::from(src))
    }
}

impl From<Vec<u8>> for NonceSession {
    fn from(channel_id: Vec<u8>) -> Self {
        NonceSession {
            channel_id,
            nonce: 0,
        }
    }
}

impl From<NonceSession> for Vec<u8> {
    fn from(src: NonceSession) -> Self {
        src.channel_id
    }
}

impl Hash for NonceSession {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.channel_id.hash(state)
    }
}

impl PartialEq for NonceSession {
    fn eq(&self, other: &Self) -> bool {
        self.channel_id == other.channel_id
    }
}

impl Session for NonceSession {
    type Request = NonceAuthRequest;
    type Response = NonceAuthResponse;
}
