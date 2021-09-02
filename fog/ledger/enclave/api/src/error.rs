// Copyright (c) 2018-2021 The MobileCoin Foundation

//! Enclave API Errors

use displaydoc::Display;
use mc_attest_core::SgxError;
use mc_attest_enclave_api::Error as AttestEnclaveError;
use mc_sgx_compat::sync::PoisonError;
use mc_transaction_core::ring_signature::Error as RingSignatureError;
use mc_util_encodings::Error as EncodingError;
use mc_util_serial::{
    decode::Error as RmpDecodeError, encode::Error as RmpEncodeError,
    DecodeError as ProstDecodeError, EncodeError as ProstEncodeError,
};
use serde::{Deserialize, Serialize};

/// An enumeration of errors which can occur inside a ledger enclave.
#[derive(Clone, Debug, Deserialize, Display, PartialEq, PartialOrd, Serialize)]
pub enum Error {
    /// A call to the SGX SDK has failed: {0}
    Sgx(SgxError),

    /// An error with attestation or AKE: {0}
    Attest(AttestEnclaveError),

    /// There was an error serializing or deserializing data
    Serialization,

    /// An panic occurred on another thread holding a lock
    Poison,

    /// Add records: {0}
    AddRecords(AddRecordsError),

    /// Enclave not initialized
    EnclaveNotInitialized,

    /// Prost encode error
    ProstEncode,

    /// Prost decode error
    ProstDecode,
}

/// An error when something goes wrong with adding a record
#[derive(Serialize, Deserialize, Debug, Display, Clone, PartialEq, PartialOrd)]
pub enum AddRecordsError {
    /// Key was wrong sizes
    KeyWrongSize,

    /// Key was rejected
    KeyRejected,

    /// Value was the wrong size
    ValueWrongSize,

    /// Map Overflowed: len = {0}, capacity = {1}
    MapOverflow(u64, u64),
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

impl From<AttestEnclaveError> for Error {
    fn from(src: AttestEnclaveError) -> Error {
        Error::Attest(src)
    }
}

impl From<AddRecordsError> for Error {
    fn from(src: AddRecordsError) -> Error {
        Error::AddRecords(src)
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

impl From<EncodingError> for Error {
    fn from(_src: EncodingError) -> Error {
        Error::Serialization
    }
}

impl From<RingSignatureError> for Error {
    fn from(_src: RingSignatureError) -> Error {
        Error::Serialization
    }
}
