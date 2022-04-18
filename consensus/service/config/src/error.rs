// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Configuration error data type

use displaydoc::Display;
use mc_common::ResponderId;
use mc_consensus_enclave_api::{FeeMapError, MasterMintersMapError};
use mc_crypto_keys::SignatureError;
use mc_transaction_core::TokenId;
use mc_util_uri::UriConversionError;
use serde_json::Error as JsonError;
use std::io::Error as IoError;
use toml::de::Error as TomlError;

/// Configuration error data type
#[derive(Debug, Display)]
pub enum Error {
    /// Missing minimum fee for token id {0}
    MissingMinimumFee(TokenId),

    /// Fee {0} for token id {1} is out of bounds
    FeeOutOfBounds(u64, TokenId),

    /// allow_any_fee cannot be used for token id {0}
    AllowAnyFeeNotAllowed(TokenId),

    /// Mint configuration is not allowed for token id {0}
    MintConfigNotAllowed(TokenId),

    /**
     * Invalid mint configuration for token id {0}: must have at least one
     * signer
     */
    NoSigners(TokenId),

    /** Invalid mint configuration for token id {0}: signer set threshold
     * exceeds number of signers
     */
    SignerSetThresholdExceedsSigners(TokenId),

    /// Cannot figure out file extension
    PathExtension,

    /// Unrecognized file extension {0}
    UnrecognizedExtension(String),

    /// Duplicate token configuration
    DuplicateTokenConfig,

    /// Missing MOB token configuration
    MissingMobConfig,

    /// Missing minimum fee for token id {0}
    MissingMininumFee(TokenId),

    /// Fee map: {0}
    FeeMap(FeeMapError),

    /// Master minters map: {0}
    MasterMintersMap(MasterMintersMapError),

    /// JSON: {0}
    Json(JsonError),

    /// TOML: {0}
    Toml(TomlError),

    /// IO: {0}
    Io(IoError),

    /// URI conversion of {0}: {1}
    UriConversion(String, UriConversionError),

    /// Duplicate responder id in network configuration: {0}
    DuplicateResponderId(ResponderId),

    /// Known peers should not contain our peer responder id ({0})
    KnownPeersContainsSelf(ResponderId),

    /// Missing tx_source_urls
    MissingTxSourceUrls,

    /// Missing master_minters_signature configuration key
    MissingMasterMintersSignature,

    /// Signature error: {0}
    Signature(SignatureError),
}

impl From<IoError> for Error {
    fn from(src: IoError) -> Self {
        Self::Io(src)
    }
}

impl From<FeeMapError> for Error {
    fn from(src: FeeMapError) -> Self {
        Self::FeeMap(src)
    }
}

impl From<MasterMintersMapError> for Error {
    fn from(src: MasterMintersMapError) -> Self {
        Self::MasterMintersMap(src)
    }
}

impl From<JsonError> for Error {
    fn from(src: JsonError) -> Self {
        Self::Json(src)
    }
}

impl From<TomlError> for Error {
    fn from(src: TomlError) -> Self {
        Self::Toml(src)
    }
}

impl From<SignatureError> for Error {
    fn from(src: SignatureError) -> Self {
        Self::Signature(src)
    }
}

impl std::error::Error for Error {}
