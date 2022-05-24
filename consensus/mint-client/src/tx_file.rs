// Copyright (c) 2018-2022 The MobileCoin Foundation

//! A file format for serializing/deserializing objects used by by the mint
//! client. This is used instead of serializing/deserializing the actual objects
//! so that if the users confuses one file type with another we are guaranteed
//! to get a deserialization error.

use displaydoc::Display;
use mc_transaction_core::mint::{MintConfigTx, MintTx};
use serde::{Deserialize, Serialize};
use serde_json::Error as JsonError;
use std::{
    fs,
    io::Error as IoError,
    path::{Path, PathBuf},
};

/// An enum for holding all possible objects the mint client needs to store in a
/// file.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub enum TxFile {
    MintConfigTx(MintConfigTx),
    MintTx(MintTx),
}

impl From<MintConfigTx> for TxFile {
    fn from(tx: MintConfigTx) -> Self {
        Self::MintConfigTx(tx)
    }
}

impl TryFrom<TxFile> for MintConfigTx {
    type Error = TxFileError;

    fn try_from(tx_file: TxFile) -> Result<Self, Self::Error> {
        match tx_file {
            TxFile::MintConfigTx(tx) => Ok(tx),
            TxFile::MintTx(_) => Err(TxFileError::WrongFileContents("MintConfigTx", "MintTx")),
        }
    }
}

impl From<MintTx> for TxFile {
    fn from(tx: MintTx) -> Self {
        Self::MintTx(tx)
    }
}

impl TryFrom<TxFile> for MintTx {
    type Error = TxFileError;

    fn try_from(tx_file: TxFile) -> Result<MintTx, Self::Error> {
        match tx_file {
            TxFile::MintTx(tx) => Ok(tx),
            TxFile::MintConfigTx(_) => {
                Err(TxFileError::WrongFileContents("MintTx", "MintConfigTx"))
            }
        }
    }
}

impl TxFile {
    /// Write the contents of this object to the given file.
    pub fn write_json(&self, path: &impl AsRef<Path>) -> Result<(), TxFileError> {
        let json = serde_json::to_string_pretty(&self)?;
        fs::write(path, json)?;
        Ok(())
    }

    /// Load a [TxFile] from a JSON file.
    pub fn from_json_file<P: AsRef<Path>>(path: P) -> Result<Self, TxFileError> {
        let json = fs::read_to_string(path)?;
        let tx = serde_json::from_str(&json)?;
        Ok(tx)
    }

    /// Attempt to load multiple files where all files contain a specific object
    /// type.
    pub fn load_multiple<T>(filenames: &[PathBuf]) -> Result<Vec<T>, TxFileError>
    where
        T: TryFrom<TxFile, Error = TxFileError>,
    {
        filenames
            .iter()
            .map(|filename| T::try_from(TxFile::from_json_file(filename)?))
            .collect::<Result<Vec<T>, TxFileError>>()
    }
}

/// Error type for TxFile operations.
#[derive(Debug, Display)]
pub enum TxFileError {
    /// IO error: {0}
    Io(IoError),

    /// JSON error: {0}
    Json(JsonError),

    /// Wrong file contents: Expected {0} but found {1}
    WrongFileContents(&'static str, &'static str),
}

impl From<IoError> for TxFileError {
    fn from(err: IoError) -> Self {
        Self::Io(err)
    }
}

impl From<JsonError> for TxFileError {
    fn from(err: JsonError) -> Self {
        Self::Json(err)
    }
}
