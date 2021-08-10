// Copyright (c) 2018-2021 The MobileCoin Foundation

use displaydoc::Display;
use mc_fog_report_validation::FogPubkeyError;
use mc_transaction_core::{
    ring_signature, ring_signature::Error, AmountError, NewMemoError, NewTxError,
};

/// An error that can occur when using the TransactionBuilder
#[derive(Debug, Display)]
pub enum TxBuilderError {
    /// Ring Signature construction failed
    RingSignatureFailed,

    /// Range proof construction failed
    RangeProofFailed,

    /// Serialization: {0}
    SerializationFailed(mc_util_serial::encode::Error),

    /// Serialization: {0}
    EncodingFailed(prost::EncodeError),

    /// Bad Amount: {0}
    BadAmount(AmountError),

    /// New Tx: {0}
    NewTx(NewTxError),

    /// Ring has incorrect size
    InvalidRingSize,

    /// Input credentials: Ring contained invalid curve point
    RingInvalidCurvePoint,

    /// No inputs
    NoInputs,

    /// Fog public key: {0}
    FogPublicKey(FogPubkeyError),

    /// Key: {0}
    KeyError(mc_crypto_keys::KeyError),

    /// Memo: {0}
    Memo(NewMemoError),
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

impl From<NewTxError> for TxBuilderError {
    fn from(x: NewTxError) -> Self {
        TxBuilderError::NewTx(x)
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

impl From<NewMemoError> for TxBuilderError {
    fn from(src: NewMemoError) -> Self {
        TxBuilderError::Memo(src)
    }
}
