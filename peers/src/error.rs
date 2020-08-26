// Copyright (c) 2018-2020 MobileCoin Inc.

//! A Peer-to-Peer networking error.

use crate::ConsensusMsgError;
use failure::Fail;
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

/// A convenience wrapper for a [std::result::Result] object which contains a peer [Error].
pub type Result<T> = StdResult<T, Error>;

/// A convenience wrapper for an [std::result::Result] which contains a [RetryError] for a peer
/// [Error].
pub type RetryResult<T> = StdResult<T, RetryError<Error>>;

/// An enumeration of errors which can occur as the result of a peer connection issue
#[derive(Debug, Fail)]
pub enum Error {
    /// There was an eror during attestation
    #[fail(display = "Attestation failure: {}", _0)]
    Attestation(PeerAttestationError),
    /// A requested resource was not found.
    #[fail(display = "Resource not found")]
    NotFound,
    /// The message could not be sent because the channel is disconnected.
    #[fail(display = "Channel disconnected, could not send")]
    ChannelSend,
    /// The requested range was too large for the API to support
    #[fail(display = "Request range too large")]
    RequestTooLarge,
    /// GRPC error.
    #[fail(display = "gRPC failure: {}", _0)]
    Grpc(GrpcError),
    /// Retry error.
    #[fail(display = "Internal retry failure: {}", _0)]
    RetryInternal(String),
    /// Error converting from gRPC protobuf type to the business-logic type.
    #[fail(display = "Conversion failure: {}", _0)]
    Conversion(ConversionError),
    /// Deserialize error.
    #[fail(display = "Serialization")]
    Serialization,
    #[fail(display = "Enclave error: {}", _0)]
    Enclave(EnclaveError),
    /// Consensus message error.
    #[fail(display = "Conensus message: {}", _0)]
    ConsensusMsg(ConsensusMsgError),
    /// Tx hashes not in cache.
    #[fail(display = "Tx hashes not in cache: {:?}", _0)]
    TxHashesNotInCache(Vec<TxHash>),
    /// Some other error.
    #[fail(display = "Unknown peering issue")]
    Other,
}

impl Error {
    pub fn should_retry(&self) -> bool {
        match self {
            Error::Grpc(_ge) => true,
            Error::Attestation(_ae) => true,
            Error::Enclave(EnclaveError::Attest(_ae)) => true,
            _ => false,
        }
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

#[derive(Debug, Fail)]
pub enum PeerAttestationError {
    #[fail(display = "gRPC failure during attestation: {}", _0)]
    Grpc(GrpcError),
    #[fail(display = "Local enclave failure during attestation: {}", _0)]
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
