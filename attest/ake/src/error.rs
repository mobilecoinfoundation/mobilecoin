// Copyright (c) 2018-2020 MobileCoin Inc.

//! AKE Errors

use attest::VerifyError;
use failure::Fail;
use mcnoise::{CipherError, HandshakeError};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, Fail, PartialEq, PartialOrd, Serialize)]
pub enum Error {
    #[fail(display = "The handshake state could not be initialized: {}", _0)]
    HandshakeInit(HandshakeError),
    #[fail(
        display = "The initiator's handshake message could not be written: {}",
        _0
    )]
    HandshakeWrite(HandshakeError),
    #[fail(
        display = "The initiator's handshake message could not be read: {}",
        _0
    )]
    HandshakeRead(HandshakeError),
    #[fail(display = "The handshake completed, but we're not done yet")]
    EarlyHandshakeComplete,
    #[fail(display = "Handshake should have been completed")]
    HandshakeNotComplete,
    #[fail(display = "The IAS report could not be serialized")]
    ReportSerialization,
    #[fail(display = "The IAS report could not be deserialized")]
    ReportDeserialization,
    #[fail(display = "The IAS report could not be verified: {}", _0)]
    ReportVerification(VerifyError),
    #[fail(display = "The remote identity was not in a format that fit within report data")]
    BadRemoteIdentity,
    #[fail(display = "Invariant problem: we completed a handshake without a remote identity")]
    MissingRemoteIdentity,
    #[fail(display = "The message could not be encrypted: {}", _0)]
    EncryptError(CipherError),
    #[fail(display = "The message could not be decrypted: {}", _0)]
    DecryptError(CipherError),
    #[fail(display = "Unknown error while initiating a new AKE")]
    Unknown,
}

impl From<VerifyError> for Error {
    fn from(src: VerifyError) -> Self {
        Error::ReportVerification(src)
    }
}
