// Copyright (c) 2018-2021 The MobileCoin Foundation

//! A Peer-to-Peer networking error.

use crate::ConsensusMsgError;
use displaydoc::Display;
use grpcio::Error as GrpcError;
use mc_connection::AttestationError;
use mc_consensus_api::ConversionError;
use mc_consensus_enclave_api::Error as EnclaveError;
use mc_transaction_core::tx::TxHash;
use mc_util_serial::{
    decode::Error as RmpDecodeError, encode::Error as RmpEncodeError,
    DecodeError as ProstDecodeError, EncodeError as ProstEncodeError,
};
use retry::Error as RetryError;
use std::{array::TryFromSliceError, result::Result as StdResult};

/// A convenience wrapper for a [std::result::Result] object which contains a
/// peer [Error].
pub type Result<T> = StdResult<T, Error>;

/// A convenience wrapper for an [std::result::Result] which contains a
/// [RetryError] for a peer [Error].
pub type RetryResult<T> = StdResult<T, RetryError<Error>>;

/// An enumeration of errors which can occur as the result of a peer connection
/// issue
#[derive(Debug, Display)]
pub enum Error {
    /// Attestation failure: {0}
    Attestation(PeerAttestationError),
    /// Resource not found
    NotFound,
    /// Channel disconnected, could not send
    ChannelSend,
    /// Request range too large
    RequestTooLarge,
    /// gRPC failure: {0}
    Grpc(GrpcError),
    /// Internal retry failure: {0}
    RetryInternal(String),
    /// Conversion failure: {0}
    Conversion(ConversionError),
    /// Serialization
    Serialization,
    /// Enclave error: {0}
    Enclave(EnclaveError),
    /// Conensus message: {0}
    ConsensusMsg(ConsensusMsgError),
    /// Tx hashes not in cache: {0:?}
    TxHashesNotInCache(Vec<TxHash>),
    /// Unknown peering issue
    Other,
}

impl Error {
    pub fn should_retry(&self) -> bool {
        matches!(
            self,
            Error::Grpc(_) | Error::Attestation(_) | Error::Enclave(EnclaveError::Attest(_))
        )
    }
}

impl From<ConversionError> for Error {
    fn from(src: ConversionError) -> Self {
        Error::Conversion(src)
    }
}

impl From<PeerAttestationError> for Error {
    fn from(src: PeerAttestationError) -> Self {
        Error::Attestation(src)
    }
}

impl From<GrpcError> for Error {
    fn from(src: GrpcError) -> Self {
        Error::Grpc(src)
    }
}

impl From<ProstDecodeError> for Error {
    fn from(_src: ProstDecodeError) -> Self {
        Error::Serialization
    }
}

impl From<ProstEncodeError> for Error {
    fn from(_src: ProstEncodeError) -> Self {
        Error::Serialization
    }
}

impl From<RetryError<Self>> for Error {
    fn from(src: RetryError<Self>) -> Self {
        match src {
            RetryError::Operation { error, .. } => error,
            RetryError::Internal(s) => Error::RetryInternal(s),
        }
    }
}

impl From<RmpDecodeError> for Error {
    fn from(_src: RmpDecodeError) -> Self {
        Error::Serialization
    }
}

impl From<RmpEncodeError> for Error {
    fn from(_src: RmpEncodeError) -> Self {
        Error::Serialization
    }
}

impl From<TryFromSliceError> for Error {
    fn from(_src: TryFromSliceError) -> Self {
        ConversionError::ArrayCastError.into()
    }
}

impl From<EnclaveError> for Error {
    fn from(src: EnclaveError) -> Self {
        Self::Enclave(src)
    }
}

impl From<ConsensusMsgError> for Error {
    fn from(src: ConsensusMsgError) -> Self {
        Self::ConsensusMsg(src)
    }
}

#[derive(Debug, Display)]
pub enum PeerAttestationError {
    /// gRPC failure during attestation: {0}
    Grpc(GrpcError),
    /// Local enclave failure during attestation: {0}
    Enclave(EnclaveError),
}

impl From<GrpcError> for PeerAttestationError {
    fn from(src: GrpcError) -> Self {
        PeerAttestationError::Grpc(src)
    }
}

impl From<EnclaveError> for PeerAttestationError {
    fn from(src: EnclaveError) -> Self {
        PeerAttestationError::Enclave(src)
    }
}

impl AttestationError for PeerAttestationError {}
