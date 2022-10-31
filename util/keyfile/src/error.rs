// Copyright (c) 2018-2022 The MobileCoin Foundation

//! This module contains the error type which methods of the `keyfile` crate can
//! generate.

use crate::mnemonic_acct::Error as MnemonicAccountError;
use displaydoc::Display;
use mc_account_keys::Error as AccountKeyError;
use prost::{DecodeError as ProstDecodeError, EncodeError as ProstEncodeError};
use serde_json::Error as JsonError;
use std::io::Error as IoError;

/// There was an error while working with key files.
#[derive(Clone, Debug, Display, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum Error {
    /// Account error: {0}
    AccountKey(AccountKeyError),
    /// Protobuf encoding error: {0}
    Encode(String),
    /// Protobuf decoding error: {0}
    Decode(String),
    /// IO error: {0}
    Io(String),
    /// JSON error: {0}
    Json(String),
    /// Mnemonic account error: {0}
    MnemonicAccount(MnemonicAccountError),
    /// The entropy provided was not the correct size for BIP-39
    MnemonicSize,
    /// Fog details are all or nothing, some were missing
    MissingFogDetails,
}

impl From<AccountKeyError> for Error {
    fn from(src: AccountKeyError) -> Error {
        Error::AccountKey(src)
    }
}

impl From<ProstEncodeError> for Error {
    fn from(src: ProstEncodeError) -> Error {
        Error::Encode(format!("{}", src))
    }
}

impl From<ProstDecodeError> for Error {
    fn from(src: ProstDecodeError) -> Error {
        Error::Encode(format!("{}", src))
    }
}

impl From<IoError> for Error {
    fn from(src: IoError) -> Error {
        Error::Io(format!("{}", src))
    }
}

impl From<JsonError> for Error {
    fn from(src: JsonError) -> Error {
        Error::Json(format!("{}", src))
    }
}

impl From<MnemonicAccountError> for Error {
    fn from(src: MnemonicAccountError) -> Error {
        Error::MnemonicAccount(src)
    }
}
