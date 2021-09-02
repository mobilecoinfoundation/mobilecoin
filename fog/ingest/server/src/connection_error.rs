// Copyright (c) 2018-2021 MobileCoin Inc.

//! A Peer-to-Peer networking error.

use displaydoc::Display;
use grpcio::Error as GrpcError;
use mc_connection::AttestationError;
use mc_crypto_keys::CompressedRistrettoPublic;
use mc_fog_ingest_enclave_api::Error as EnclaveError;
use mc_util_serial::{
    decode::Error as RmpDecodeError, encode::Error as RmpEncodeError,
    DecodeError as ProstDecodeError, EncodeError as ProstEncodeError,
};
use retry::Error as RetryError;
use std::result::Result as StdResult;

/// A convenience wrapper for a [std::result::Result] object which contains a
/// peer [Error].
pub type Result<T> = StdResult<T, Error>;

/// A convenience wrapper for an [std::result::Result] which contains a
/// [RetryError] for a peer [Error].
//pub type RetryResult<T> = StdResult<T, RetryError<Error>>;

/// An enumeration of errors which can occur as the result of a peer connection
/// issue
#[derive(Debug, Display)]
pub enum Error {
    /// There was an eror during attestation: {0}
    Attestation(PeerAttestationError),
    /// The message could not be sent because the channel is disconnected.
    ChannelSend,
    /// GRPC error: {0}
    Grpc(GrpcError),
    /// Retry error: {0}
    RetryInternal(String),
    /// Serialization
    Serialization,
    /// Enclave error: {0}
    Enclave(EnclaveError),
    /// Unexpected key in enclave when sending to peer: {0}
    UnexpectedKeyInEnclave(CompressedRistrettoPublic),
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

impl From<EnclaveError> for Error {
    fn from(src: EnclaveError) -> Self {
        Self::Enclave(src)
    }
}

/// An error which can occur when attesting to a peer
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
