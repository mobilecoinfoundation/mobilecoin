// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Errors that can occur during Block Metadata validation and parsing
//! of file containing historical metadata records

use displaydoc::Display;
use hex::FromHexError;
use mc_attest_core::VerifyError;
use mc_attest_verifier::Error as VerifierError;
use mc_blockchain_types::BlockIndex;
use mc_common::ResponderId;
use mc_crypto_keys::{KeyError, SignatureError};
use pem::PemError;
use serde_json::Error as JsonError;
use std::{io::Error as IoError, path::PathBuf};
use toml::de::Error as FromTomlError;

/// Block metadata validation errors
#[derive(Debug, Display, Eq, PartialEq)]
pub enum ValidationError {
    /// Failed to parse key: {0}
    Key(KeyError),

    /// Unrecognized message signing key.
    UnknownPubKey,

    /// Expired/Invalid message signing key.
    InvalidPubKey,

    /// Signature error: {0}
    Signature(String),

    /// Block Signer key: {0} does not match public key from AVR: {0}
    InvalidBlockSigningKey(String, String),

    /// No AVR found for signing key {0}
    AvrNotFound(String),

    /// Signer key contained in AVR was invalid: {0},
    AvrKeyData(String),

    /// AVR failed to verify against intel roots of trust: {0},
    InvalidAvr(String),

    /// Signing Key is out of range for block: {0}
    BlockSigningKeyExpired(BlockIndex),

    /// ResponderId: {0} does not match expected ResponderId: {1}
    ResponderIdMismatch(ResponderId, ResponderId),

    /// No block signature found at for block: {0},
    NoBlockSignature(BlockIndex),

    /// Other error: {0}
    Other(String),
}

impl From<SignatureError> for ValidationError {
    fn from(src: SignatureError) -> Self {
        Self::Signature(src.to_string())
    }
}

impl From<KeyError> for ValidationError {
    fn from(err: KeyError) -> Self {
        ValidationError::Key(err)
    }
}

impl From<VerifierError> for ValidationError {
    fn from(err: VerifierError) -> Self {
        ValidationError::InvalidAvr(err.to_string())
    }
}

impl From<VerifyError> for ValidationError {
    fn from(err: VerifyError) -> Self {
        ValidationError::AvrKeyData(err.to_string())
    }
}

/// Parsing errors
#[derive(Debug, Display, PartialEq)]
pub enum ParseError {
    /// Unrecognized extension in '{0}'
    UnrecognizedExtension(PathBuf),

    /// Invalid pub_key value: {0}
    InvalidPubKeyValue(String),

    /// Failed to parse key: {0}
    Key(KeyError),

    /// I/O error: {0}
    Io(String),

    /// Failed to parse hexadecimal string: {0}
    Hex(FromHexError),

    /// Failed to parse PEM: {0}
    Pem(PemError),

    /// Invalid PEM tag: {0}
    InvalidPemTag(String),

    /// Failed to parse TOML: {0}
    Toml(String),

    /// Failed to parse JSON: {0}
    Json(String),

    /// Validation of the metadata in the config file failed: {0}
    Validation(String),
}

impl From<KeyError> for ParseError {
    fn from(src: KeyError) -> Self {
        Self::Key(src)
    }
}

impl From<IoError> for ParseError {
    fn from(src: IoError) -> Self {
        Self::Io(src.to_string())
    }
}

impl From<FromHexError> for ParseError {
    fn from(src: FromHexError) -> Self {
        Self::Hex(src)
    }
}

impl From<PemError> for ParseError {
    fn from(src: PemError) -> Self {
        Self::Pem(src)
    }
}

impl From<FromTomlError> for ParseError {
    fn from(src: FromTomlError) -> Self {
        Self::Toml(src.to_string())
    }
}

impl From<JsonError> for ParseError {
    fn from(src: JsonError) -> Self {
        Self::Json(src.to_string())
    }
}

impl From<ValidationError> for ParseError {
    fn from(src: ValidationError) -> Self {
        Self::Validation(src.to_string())
    }
}
