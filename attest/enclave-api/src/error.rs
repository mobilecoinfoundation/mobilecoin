// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Enclave API Errors

use alloc::string::{String, ToString};
use core::result::Result as StdResult;
use displaydoc::Display;
use mc_attest_ake::Error as AkeError;
use mc_attest_core::{IntelSealingError, NonceError, ParseSealedError, SgxError};
use mc_attest_verifier::Error as VerifierError;
use mc_attestation_verifier::Error as AttestationVerifierError;
use mc_crypto_noise::CipherError;
use mc_sgx_compat::sync::PoisonError;
use serde::{Deserialize, Serialize};

/// A generic result type for enclave calls
pub type Result<T> = StdResult<T, Error>;

/// An enumeration of errors which can occur inside an enclave, in connection to
/// attestation or AKE
#[derive(Clone, Debug, Deserialize, Display, PartialEq, Serialize)]
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
     * generation or attestation evidence parsing code, or a simple
     * mismatch.
     */
    Nonce(NonceError),

    /// The local attestation evidence could not be verified: {0}
    Verify(VerifierError),

    /// Attestation verifier error: {0}
    AttestationVerify(AttestationVerifierError),

    /// Another thread crashed while holding a lock
    Poison,

    /// An error occurred during a sealing operation
    Seal(IntelSealingError),

    /// An error occurred during an unsealing operation
    Unseal(ParseSealedError),

    /**
     * Invalid state for call
     *
     * This indicates a bug in the calling code, typically attempting to
     * re-submit an already-verified quote or attestation evidence.
     */
    InvalidState,

    /// No attestation evidence has been verified yet
    NoAttestationEvidenceAvailable,

    /// Too many attestation evidence instances are already in-flight
    TooManyPendingAttestationEvidenceInstances,

    /// Encoding error
    Encode(String),

    /// Decoding error
    Decode(String),

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

impl From<VerifierError> for Error {
    fn from(src: VerifierError) -> Error {
        Error::Verify(src)
    }
}

impl From<IntelSealingError> for Error {
    fn from(src: IntelSealingError) -> Error {
        Error::Seal(src)
    }
}

impl From<ParseSealedError> for Error {
    fn from(src: ParseSealedError) -> Error {
        Error::Unseal(src)
    }
}

impl From<mc_util_serial::encode::Error> for Error {
    fn from(src: mc_util_serial::encode::Error) -> Self {
        Error::Encode(src.to_string())
    }
}

impl From<mc_util_serial::decode::Error> for Error {
    fn from(src: mc_util_serial::decode::Error) -> Self {
        Error::Decode(src.to_string())
    }
}

impl From<AttestationVerifierError> for Error {
    fn from(src: AttestationVerifierError) -> Self {
        Error::AttestationVerify(src)
    }
}
