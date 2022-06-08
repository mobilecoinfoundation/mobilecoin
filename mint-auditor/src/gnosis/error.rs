// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Error data type for Gnosis-related functionality.

use displaydoc::Display;
use serde_json::Error as JsonError;
use std::io::Error as IoError;
use toml::de::Error as TomlError;

/// Error data type for Gnosis-related functionality.
#[derive(Debug, Display)]
pub enum Error {
    /// Cannot figure out file extension
    PathExtension,

    /// Unrecognized file extension {0}
    UnrecognizedExtension(String),

    /// JSON: {0}
    Json(JsonError),

    /// TOML: {0}
    Toml(TomlError),

    /// IO: {0}
    Io(IoError),

    /// Invalid address: {0}
    InvalidAddress(String),
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

impl From<IoError> for Error {
    fn from(src: IoError) -> Self {
        Self::Io(src)
    }
}
