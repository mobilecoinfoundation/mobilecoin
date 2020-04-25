// Copyright (c) 2018-2020 MobileCoin Inc.

//! Error types used by this crate

pub use retry::Error as RetryError;

use crate::traits::AttestationError;
use failure::Fail;
use grpcio::Error as GrpcError;
use mc_consensus_api::{consensus_common::ProposeTxResult, ConversionError};
use mc_crypto_noise::CipherError;
use mc_transaction_core::validation::TransactionValidationError;
use std::{array::TryFromSliceError, convert::TryInto, result::Result as StdResult};

pub type Result<T> = StdResult<T, Error>;
pub type RetryResult<T> = StdResult<T, RetryError<Error>>;

#[derive(Debug, Fail)]
pub enum Error {
    #[fail(display = "The given measurement type is not MRSIGNER or MRENCLAVE")]
    UnknownMeasurement,
    #[fail(display = "No measurement value given")]
    NoMeasurement,
    #[fail(display = "The requested range was too large")]
    RequestTooLarge,
    #[fail(display = "Not found")]
    NotFound,
    #[fail(display = "Could not convert gRPC type to working type")]
    Conversion(ConversionError),
    #[fail(display = "gRPC failure: {}", _0)]
    Grpc(GrpcError),
    #[fail(display = "Encryption/decryption failure: {}", _0)]
    Cipher(CipherError),
    #[fail(display = "Attestation failure: {}", _0)]
    Attestation(Box<dyn AttestationError + 'static>),
    #[fail(display = "Transaction validation failure: {}", _0)]
    TransactionValidation(TransactionValidationError),
    #[fail(display = "Other: {}", _0)]
    Other(String),
}

impl Error {
    /// Policy decision, whether the call should be retried.
    pub fn should_retry(&self) -> bool {
        match self {
            Error::Grpc(_ge) => true,
            Error::Attestation(_ae) => true,
            _ => false,
        }
    }
}

impl<AE: AttestationError + 'static> From<AE> for Error {
    fn from(src: AE) -> Self {
        Error::Attestation(Box::new(src))
    }
}

impl From<CipherError> for Error {
    fn from(src: CipherError) -> Self {
        Error::Cipher(src)
    }
}

impl From<GrpcError> for Error {
    fn from(src: GrpcError) -> Self {
        Error::Grpc(src)
    }
}

impl TryInto<GrpcError> for Error {
    type Error = Error;

    fn try_into(self) -> Result<GrpcError> {
        match self {
            Error::Grpc(ge) => Ok(ge),
            error => Err(error),
        }
    }
}

impl From<ConversionError> for Error {
    fn from(src: ConversionError) -> Self {
        Error::Conversion(src)
    }
}

impl From<TryFromSliceError> for Error {
    fn from(_src: TryFromSliceError) -> Self {
        ConversionError::ArrayCastError.into()
    }
}

impl From<ProposeTxResult> for Error {
    fn from(src: ProposeTxResult) -> Self {
        src.try_into()
            .map(Self::TransactionValidation)
            .unwrap_or_else(|err| Error::Other(err.into()))
    }
}

impl From<mc_transaction_core::ConvertError> for Error {
    fn from(_src: mc_transaction_core::ConvertError) -> Self {
        ConversionError::ArrayCastError.into()
    }
}
