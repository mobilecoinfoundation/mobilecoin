// Copyright (c) 2018-2021 The MobileCoin Foundation

//! Enclave API Errors

use core::result::Result as StdResult;
use displaydoc::Display;
use mc_attest_ake::Error as AkeError;
use mc_attest_core::{NonceError, QuoteError, SgxError, VerifierError};
use mc_crypto_noise::CipherError;
use mc_sgx_compat::sync::PoisonError;
use serde::{Deserialize, Serialize};

/// A generic result type for enclave calls
pub type Result<T> = StdResult<T, Error>;

/// An enumeration of errors which can occur inside an enclave, in connection to
/// attestation or AKE
#[derive(Clone, Debug, Deserialize, Display, PartialEq, PartialOrd, Serialize)]
pub enum Error {
    /// Enclave not initialized
    NotInit,

    /// Enclave already initialized
    AlreadyInit,

    /// Error communicating with SGX: {0}
    Sgx(SgxError),

    /// Handshake error: {0}
    Kex(AkeError),

    /// Encryption error after handshake: {0}
    Cipher(CipherError),

    /**
     * There was an error while handling a nonce: {0}
     *
     * This can represent a significant programming bug in the nonce
     * generation or report parsing code, or a simple mismatch.
     */
    Nonce(NonceError),

    /// The local quote could not be verified: {0}
    Quote(QuoteError),

    /// The local report could not be verified: {0}
    Verify(VerifierError),

    /// Another thread crashed while holding a lock
    Poison,

    /**
     * Invalid state for call
     *
     * This indicates a bug in the calling code, typically attempting to
     * re-submit an already-verified quote or IAS report.
     */
    InvalidState,

    /// No IAS report has been verified yet
    NoReportAvailable,

    /// Too many IAS reports are already in-flight
    TooManyPendingReports,

    /// Connection not found by node ID or session
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

impl From<VerifierError> for Error {
    fn from(src: VerifierError) -> Error {
        Error::Verify(src)
    }
}
