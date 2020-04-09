// Copyright (c) 2018-2020 MobileCoin Inc.

//! Enclave API Errors

use attest::{NonceError, QuoteError, SgxError, SignatureError, VerifyError};
use attest_ake::Error as AkeError;
use core::result::Result as StdResult;
use failure::Fail;
use mcnoise::CipherError;
use serde::{Deserialize, Serialize};
use sgx_compat::sync::PoisonError;

/// A generic result type for enclave calls
pub type Result<T> = StdResult<T, Error>;

/// An enumeration of errors which can occur inside an enclave, in connection to attestation or AKE
#[derive(Clone, Debug, Deserialize, Fail, PartialEq, PartialOrd, Serialize)]
pub enum Error {
    /// Enclave not initialized
    #[fail(display = "Enclave not initialized")]
    NotInit,

    /// Enclave already initialized
    #[fail(display = "Enclave already initialized")]
    AlreadyInit,

    /// A call to the SGX SDK has failed
    #[fail(display = "Error communicating with SGX: {}", _0)]
    Sgx(SgxError),

    /// There was an error while performing a peer handshake, encryption, or key exchange
    #[fail(display = "Handshake error: {}", _0)]
    Kex(AkeError),

    /// There was an error encrypting or decrypting data for a peer or client.
    #[fail(display = "Encryption error after handshake: {}", _0)]
    Cipher(CipherError),

    /// There was an error generating or verifying a nonce.
    ///
    /// This can represent a significant programming bug in the nonce
    /// generation or report parsing code, or a simple mismatch.
    #[fail(display = "There was an error while handling a nonce: {}", _0)]
    Nonce(NonceError),

    /// There was a problem with the quote or it's report.
    #[fail(display = "The local quote could not be verified: {}", _0)]
    Quote(QuoteError),

    /// There was an error validating the report, described by the newtype
    /// inner.
    #[fail(display = "The local report could not be verified: {}", _0)]
    Verify(VerifyError),

    /// An panic occurred on another thread
    #[fail(display = "Another thread crashed while holding a lock")]
    Poison,

    /// The method call was not valid for the state machine for the data.
    ///
    /// This indicates a bug in the calling code, typically attempting to
    /// re-submit an already-verified quote or IAS report.
    #[fail(display = "Invalid state for call")]
    InvalidState,

    /// No report has been cached yet.
    #[fail(display = "No IAS report has been verified yet.")]
    NoReportAvailable,

    /// Too many reports are currently outstanding.
    #[fail(display = "Too many IAS reports are already in-flight.")]
    TooManyPendingReports,

    /// The connection could not be found by channel binding or node ID.
    #[fail(display = "Connection not found by node ID or session")]
    NotFound,
}

impl From<AkeError> for Error {
    fn from(src: AkeError) -> Self {
        Error::Kex(src)
    }
}

impl From<CipherError> for Error {
    fn from(src: CipherError) -> Self {
        Error::Cipher(src)
    }
}

impl<T> From<PoisonError<T>> for Error {
    fn from(_src: PoisonError<T>) -> Self {
        Error::Poison
    }
}

impl From<SgxError> for Error {
    fn from(src: SgxError) -> Self {
        Error::Sgx(src)
    }
}

impl From<NonceError> for Error {
    fn from(src: NonceError) -> Error {
        Error::Nonce(src)
    }
}

impl From<QuoteError> for Error {
    fn from(src: QuoteError) -> Error {
        Error::Quote(src)
    }
}

impl From<SignatureError> for Error {
    fn from(src: SignatureError) -> Error {
        Error::Verify(src.into())
    }
}

impl From<VerifyError> for Error {
    fn from(src: VerifyError) -> Error {
        Error::Verify(src)
    }
}
