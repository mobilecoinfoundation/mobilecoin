// Copyright (c) 2018-2020 MobileCoin Inc.

use failure::Fail;
use transaction::{amount::AmountError, ring_signature, ring_signature::Error};

#[derive(Debug, Fail)]
pub enum TxBuilderError {
    #[fail(display = "Ring Signature construction failed")]
    RingSignatureFailed,

    #[fail(display = "Range proof construction failed")]
    RangeProofFailed,

    #[fail(display = "Serialization failed: {}", _0)]
    SerializationFailed(mcserial::encode::Error),

    #[fail(display = "Serialization failed: {}", _0)]
    EncodingFailed(prost::EncodeError),

    #[fail(display = "Bad Amount: {}", _0)]
    BadAmount(AmountError),

    #[fail(display = "Ring has incorrect size")]
    InvalidRingSize,

    #[fail(display = "Input credentials: Ring contained invalid curve point")]
    RingInvalidCurvePoint,

    #[fail(display = "No inputs")]
    NoInputs,

    #[fail(
        display = "When building a transaction, a public key was provided for the recipient's fog server, but their public address does not have a Fog server"
    )]
    IngestPubkeyUnexpectedlyProvided,

    #[fail(
        display = "When building a transaction, a public key was not provided for the recipient's fog server, but their public address does have a Fog server"
    )]
    IngestPubkeyNotProvided,

    #[fail(display = "Key error: {}", _0)]
    KeyError(keys::KeyError),
}

impl From<mcserial::encode::Error> for TxBuilderError {
    fn from(x: mcserial::encode::Error) -> Self {
        TxBuilderError::SerializationFailed(x)
    }
}

impl From<prost::EncodeError> for TxBuilderError {
    fn from(x: prost::EncodeError) -> Self {
        TxBuilderError::EncodingFailed(x)
    }
}

impl From<transaction::amount::AmountError> for TxBuilderError {
    fn from(x: transaction::amount::AmountError) -> Self {
        TxBuilderError::BadAmount(x)
    }
}

impl From<keys::KeyError> for TxBuilderError {
    fn from(e: keys::KeyError) -> Self {
        TxBuilderError::KeyError(e)
    }
}

impl From<ring_signature::Error> for TxBuilderError {
    fn from(_: Error) -> Self {
        TxBuilderError::RingSignatureFailed
    }
}
