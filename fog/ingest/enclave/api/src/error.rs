// Copyright (c) 2018-2021 The MobileCoin Foundation

//! Enclave API Errors

use displaydoc::Display;
use mc_attest_core::{
    NonceError, ParseSealedError, QuoteError, SgxError, SignatureError, VerifyError,
};
use mc_attest_enclave_api::Error as AttestEnclaveError;
use mc_crypto_keys::KeyError;
use mc_sgx_compat::sync::PoisonError;
use mc_util_serial::{
    decode::Error as RmpDecodeError, encode::Error as RmpEncodeError,
    DecodeError as ProstDecodeError, EncodeError as ProstEncodeError,
};
use serde::{Deserialize, Serialize};

/// An enumeration of errors which can occur when rotating keys in the ingest
/// enclave
#[derive(Clone, Debug, Deserialize, Display, PartialEq, PartialOrd, Serialize)]
pub enum RotateKeysError {
    /**
     * We tried to rotate keys when there was an existing rotated key that
     * hasn't expired
     */
    AlreadyExists,

    /// Error parsing key: {0}
    Key(KeyError),
}

/// An enumeration of errors which can occur inside an ingest enclave.
#[derive(Clone, Debug, Deserialize, Display, PartialEq, PartialOrd, Serialize)]
pub enum Error {
    /// Enclave not initialized
    NotInit,

    /// Enclave already initialized
    AlreadyInit,

    /// Error communciating with SGX: {0}
    Sgx(SgxError),

    /// An error with attestation or AKE: {0}
    Attest(AttestEnclaveError),

    /// There was an error serializing or deserializing data
    //
    // NOTE: This refers only to errors traversing the ecall boundary. Errors related
    //       to serialization for a particular RPC call's (encrypted) data should be
    //       in an enum/variant for that call.
    Serialization,

    /// There was an error while handling a nonce: {0}
    //
    // This can represent a significant programming bug in the nonce
    // generation or report parsing code, or a simple mismatch.
    Nonce(NonceError),

    /// The local quote could not be verified: {0}
    Quote(QuoteError),

    /// The local report could not be verified: {0}
    Verify(VerifyError),

    /// An panic occurred on another thread while holding a lock
    Poison,

    /// The method call was not valid for the state machine for the data.
    //
    // This indicates a bug in the calling code, typically attempting to
    // re-submit an already-verified quote or IAS report.
    InvalidState,

    /// No IAS report has been verified yet
    NoReportAvailable,

    /// Too many IAS reports are already in-flight
    TooManyPendingReports,

    /// Error parsing key: {0}
    Key(KeyError),

    /**
     * ChunkTooBig: Failed processing {0} txouts, overflowed {1} times in a
     * row: capacity was {2}
     */
    ChunkTooBig(usize, usize, u64),

    /// Error when rotating keys: {0}
    RotateKeys(RotateKeysError),

    /// Intel sealing format error
    // FIXME: Attach ParseSealedError here when that implements Serde
    ParseSealed,
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

impl From<KeyError> for Error {
    fn from(src: KeyError) -> Self {
        Error::Key(src)
    }
}

impl From<AttestEnclaveError> for Error {
    fn from(src: AttestEnclaveError) -> Error {
        Error::Attest(src)
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

impl From<ParseSealedError> for Error {
    fn from(_src: ParseSealedError) -> Error {
        Error::ParseSealed
    }
}
