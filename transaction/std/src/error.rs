// Copyright (c) 2018-2022 The MobileCoin Foundation

use displaydoc::Display;
use mc_crypto_ring_signature_signer::Error as SignerError;
use mc_fog_report_validation::FogPubkeyError;
use mc_transaction_core::{
    ring_ct::Error as RingCtError, AmountError, NewMemoError, NewTxError, TokenId,
    TxOutConversionError,
};

/// An error that can occur when using the TransactionBuilder
#[derive(Debug, Display)]
pub enum TxBuilderError {
    /// Ring Signature construction failed: {0}
    RingSignatureFailed(RingCtError),

    /// Range proof construction failed
    RangeProofFailed,

    /// Serialization: {0}
    SerializationFailed(mc_util_serial::encode::Error),

    /// Serialization: {0}
    EncodingFailed(prost::EncodeError),

    /// Bad Amount: {0}
    BadAmount(AmountError),

    /// Mixed Transactions not allowed: Expected {0}, Found {1}
    MixedTransactionsNotAllowed(TokenId, TokenId),

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

    /// Block version ({0} < {1}) is too old to be supported
    BlockVersionTooOld(u32, u32),

    /// Block version ({0} > {1}) is too new to be supported
    BlockVersionTooNew(u32, u32),

    /// Feature is not supported at this block version ({0}): {1}
    FeatureNotSupportedAtBlockVersion(u32, &'static str),

    /// Signed input rules not allowed at this block version
    SignedInputRulesNotAllowed,

    /// Missing membership proof
    MissingMembershipProofs,

    /// Signer: {0}
    Signer(SignerError),

    /// TxOut Conversion: {0}
    TxOutConversion(TxOutConversionError),
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

impl From<RingCtError> for TxBuilderError {
    fn from(src: RingCtError) -> Self {
        TxBuilderError::RingSignatureFailed(src)
    }
}

impl From<SignerError> for TxBuilderError {
    fn from(src: SignerError) -> Self {
        TxBuilderError::Signer(src)
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

impl From<TxOutConversionError> for TxBuilderError {
    fn from(src: TxOutConversionError) -> Self {
        TxBuilderError::TxOutConversion(src)
    }
}

/// An error that can occur when creating a signed contingent input builder
#[derive(Debug, Display)]
pub enum SignedContingentInputBuilderError {
    /// Missing proofs: {0} ring elements, {1} proofs
    MissingProofs(usize, usize),
    /// Memo: {0}
    Memo(NewMemoError),
}

impl From<NewMemoError> for SignedContingentInputBuilderError {
    fn from(src: NewMemoError) -> Self {
        SignedContingentInputBuilderError::Memo(src)
    }
}
