// Copyright (c) 2018-2021 The MobileCoin Foundation

//! AKE Errors

use displaydoc::Display;
use mc_attest_core::VerifierError;
use mc_crypto_noise::{CipherError, HandshakeError};
use serde::{Deserialize, Serialize};

/// An enumeration of errors which can occur during key exchange
#[derive(Clone, Debug, Deserialize, Display, PartialEq, PartialOrd, Serialize)]
pub enum Error {
    /// The handshake state could not be initialized: {0}
    HandshakeInit(HandshakeError),
    /// The initiator's handshake message could not be written: {0}
    HandshakeWrite(HandshakeError),
    /// The initiator's handshake message could not be read: {0}
    HandshakeRead(HandshakeError),
    /// The handshake completed, but we're not done yet
    EarlyHandshakeComplete,
    /// Handshake should have been completed
    HandshakeNotComplete,
    /// The IAS report could not be serialized
    ReportSerialization,
    /// The IAS report could not be deserialized
    ReportDeserialization,
    /// The IAS report could not be verified: {0}
    ReportVerification(VerifierError),
    /// The remote identity was not in a format that fit within report data
    BadRemoteIdentity,
    /// Invariant problem: we completed a handshake without a remote identity
    MissingRemoteIdentity,
    /// The message could not be encrypted: {0}
    EncryptError(CipherError),
    /// The message could not be decrypted: {0}
    DecryptError(CipherError),
    /// Unknown error while initiating a new AKE
    Unknown,
}

impl From<VerifierError> for Error {
    fn from(src: VerifierError) -> Error {
        Error::ReportVerification(src)
    }
}
