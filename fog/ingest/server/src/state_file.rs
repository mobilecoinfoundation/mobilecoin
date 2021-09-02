// Copyright (c) 2018-2021 The MobileCoin Foundation

//! State we want to keep between invocations of the ingest server.

use mc_fog_api::ingest_common::IngestStateFile;
use protobuf::Message;
use std::{
    fs,
    io::{Error, ErrorKind, Result, Write},
    path::PathBuf,
};

/// State file.
#[derive(Clone, Debug)]
pub struct StateFile {
    /// The state file's path.
    file_path: PathBuf,
}

impl StateFile {
    /// Create a state file object
    pub fn new(file_path: PathBuf) -> Self {
        Self { file_path }
    }

    /// Read the data from the state file on disk
    pub fn read(&self) -> Result<IngestStateFile> {
        let file_data = fs::read(&self.file_path)?;
        let state_data = IngestStateFile::parse_from_bytes(&file_data).map_err(|e| {
            Error::new(
                ErrorKind::Other,
                format!("Failed parsing state file {:?}: {}", self.file_path, e),
            )
        })?;
        Ok(state_data)
    }

    /// Write data to the state file on disk, and fsync it.
    ///
    /// FOG-360: Per discussion in ticket, the most sound way to write to a file
    /// to disk in linux is: (1) Write to a temporary file
    /// (2) fsync. If this fails we didn't corrupt the original
    /// (3) Move the temporary file over the old file
    /// (4) fsync the directory containing the old file, ensuring the move is
    /// written to disk.
    ///
    /// Unfortunately there's no way to do 4 in the rust stdlib, so we would
    /// need to use nix or something. https://github.com/rust-lang/rust/issues/32255#issuecomment-308296338
    pub fn write(&self, state_data: &IngestStateFile) -> Result<()> {
        let proto_data = state_data.write_to_bytes().map_err(|e| {
            Error::new(
                ErrorKind::Other,
                format!("failed serializing state data: {}", e),
            )
        })?;
        let mut file = fs::File::create(&self.file_path)?;
        file.write_all(&proto_data)?;
        file.sync_all()
    }
}
