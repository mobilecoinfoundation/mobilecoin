// Copyright (c) 2018-2020 MobileCoin Inc.

//! Enclave API Errors

use alloc::string::String;
use failure::Fail;
use mc_attest_core::SgxError;
use mc_attest_enclave_api::Error as AttestEnclaveError;
use mc_crypto_keys::Ed25519SignatureError;
use mc_crypto_message_cipher::CipherError as MessageCipherError;
use mc_sgx_compat::sync::PoisonError;
use mc_transaction_core::validation::TransactionValidationError;
use mc_util_serial::{
    decode::Error as RmpDecodeError, encode::Error as RmpEncodeError,
    DecodeError as ProstDecodeError, EncodeError as ProstEncodeError,
};
use serde::{Deserialize, Serialize};

/// An enumeration of errors which can occur inside a consensus enclave.
#[derive(Clone, Debug, Deserialize, Fail, PartialEq, PartialOrd, Serialize)]
pub enum Error {
    /// A call to the SGX SDK has failed
    #[fail(display = "Error communicating with SGX: {}", _0)]
    Sgx(SgxError),

    /// Error with attestation or ake
    #[fail(display = "Attested AKE error: {}", _0)]
    Attest(AttestEnclaveError),

    /// There was an error encrypting or decrypting local data.
    #[fail(display = "Local cache cipher error: {}", _0)]
    CacheCipher(MessageCipherError),

    /// There was an error serializing or deserializing data
    #[fail(display = "Error while serializing/deserializing")]
    Serialization,

    /// An panic occurred on another thread
    #[fail(display = "Another thread crashed while holding a lock")]
    Poison,

    /// Indicates that the transaction is malformed.
    #[fail(display = "Malformed transaction: {}", _0)]
    MalformedTx(TransactionValidationError),

    /// A membership proof provided by the local system is invalid.
    #[fail(display = "Invalid membership proof provided by local system")]
    InvalidLocalMembershipProof,

    /// Error forming block (not expected to happen if untrusted plays by the rules).
    #[fail(display = "Form block error: {}", _0)]
    FormBlock(String),

    /// Signature error
    #[fail(display = "Signature error")]
    Signature,

    /// Fee Public Address Error
    #[fail(display = "Fee public address error: {}", _0)]
    FeePublicAddress(String),
}

impl From<MessageCipherError> for Error {
    fn from(src: MessageCipherError) -> Self {
        Error::CacheCipher(src)
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

impl From<RmpEncodeError> for Error {
    fn from(_src: RmpEncodeError) -> Error {
        Error::Serialization
    }
}

impl From<RmpDecodeError> for Error {
    fn from(_src: RmpDecodeError) -> Error {
        Error::Serialization
    }
}

impl From<ProstEncodeError> for Error {
    fn from(_src: ProstEncodeError) -> Error {
        Error::Serialization
    }
}

impl From<ProstDecodeError> for Error {
    fn from(_src: ProstDecodeError) -> Error {
        Error::Serialization
    }
}

impl From<TransactionValidationError> for Error {
    fn from(src: TransactionValidationError) -> Error {
        Error::MalformedTx(src)
    }
}

impl From<AttestEnclaveError> for Error {
    fn from(src: AttestEnclaveError) -> Error {
        Error::Attest(src)
    }
}

impl From<Ed25519SignatureError> for Error {
    fn from(_src: Ed25519SignatureError) -> Error {
        Error::Signature
    }
}
