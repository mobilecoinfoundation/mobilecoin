// Copyright (c) 2018-2020 MobileCoin Inc.

use failure::Fail;
use mc_fog_report_validation::FogPubkeyError;
use mc_transaction_core::{ring_signature, ring_signature::Error, AmountError};

#[derive(Debug, Fail)]
pub enum TxBuilderError {
    #[fail(display = "Ring Signature construction failed")]
    RingSignatureFailed,

    #[fail(display = "Range proof construction failed")]
    RangeProofFailed,

    #[fail(display = "Serialization failed: {}", _0)]
    SerializationFailed(mc_util_serial::encode::Error),

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

    #[fail(display = "Fog public key error: {}", _0)]
    FogPublicKey(FogPubkeyError),

    #[fail(display = "Key error: {}", _0)]
    KeyError(mc_crypto_keys::KeyError),
}

impl From<mc_util_serial::encode::Error> for TxBuilderError {
    fn from(x: mc_util_serial::encode::Error) -> Self {
        TxBuilderError::SerializationFailed(x)
    }
}

impl From<prost::EncodeError> for TxBuilderError {
    fn from(x: prost::EncodeError) -> Self {
        TxBuilderError::EncodingFailed(x)
    }
}

impl From<AmountError> for TxBuilderError {
    fn from(x: AmountError) -> Self {
        TxBuilderError::BadAmount(x)
    }
}

impl From<mc_crypto_keys::KeyError> for TxBuilderError {
    fn from(e: mc_crypto_keys::KeyError) -> Self {
        TxBuilderError::KeyError(e)
    }
}

impl From<ring_signature::Error> for TxBuilderError {
    fn from(_: Error) -> Self {
        TxBuilderError::RingSignatureFailed
    }
}

impl From<FogPubkeyError> for TxBuilderError {
    fn from(src: FogPubkeyError) -> Self {
        TxBuilderError::FogPublicKey(src)
    }
}
