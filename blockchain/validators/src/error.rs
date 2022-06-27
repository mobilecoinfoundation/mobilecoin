// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Validator errors.

use displaydoc::Display;
use hex::FromHexError;
use mc_crypto_keys::{KeyError, SignatureError};
use pem::PemError;
use serde_json::Error as JsonError;
use std::{io::Error as IoError, path::PathBuf};
use toml::de::Error as FromTomlError;

/// Validator errors.
#[derive(Debug, Display, Eq, PartialEq)]
pub enum ValidationError {
    /// Unrecognized public key.
    UnknownPubKey,

    /// Expired/Invalid public key.
    InvalidPubKey,

    /// Signature error: {0}
    Signature(String),
}

impl From<SignatureError> for ValidationError {
    fn from(src: SignatureError) -> Self {
        Self::Signature(src.to_string())
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
