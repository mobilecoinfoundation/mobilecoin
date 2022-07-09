// Copyright (c) 2018-2022 The MobileCoin Foundation

//! A [ProtoWriter] that writes to local files.

use crate::ProtoWriter;
use futures::Future;
use mc_ledger_streaming_api::{Error, Result};
use protobuf::Message;
use std::path::{Path, PathBuf};

/// A [ProtoWriter] that writes to local files.
#[derive(Clone, Debug)]
pub struct LocalFileProtoWriter {
    base_path: PathBuf,
}

impl LocalFileProtoWriter {
    /// Instantiate a writer that writes to files under the given path.
    pub fn new(base_path: PathBuf) -> Self {
        Self { base_path }
    }

    /// Get the base path for this writer.
    pub fn base_path(&self) -> &Path {
        &self.base_path
    }

    async fn write(&self, dest: PathBuf, bytes: protobuf::ProtobufResult<Vec<u8>>) -> Result<()> {
        let bytes = bytes?;
        let path = self.base_path.join(dest);
        let dir = path.parent().ok_or_else(|| {
            Error::IO(
                format!("Failed to get parent for {:?}", path),
                std::io::ErrorKind::NotFound,
            )
        })?;
        tokio::fs::create_dir_all(dir).await.map_err(|e| {
            Error::IO(
                format!("Failed to create parent dir {:?}: {}", dir, e),
                e.kind(),
            )
        })?;
        tokio::fs::write(&path, bytes)
            .await
            .map_err(|e| Error::IO(format!("Failed to write to {:?}: {}", path, e), e.kind()))
    }
}

impl ProtoWriter for LocalFileProtoWriter {
    fn upload<'up, M: Message>(&'up self, proto: &'up M, dest: &'up Path) -> Self::Future<'up> {
        let dest = self.base_path.join(dest);
        self.write(dest, proto.write_to_bytes())
    }

    type Future<'u> = impl Future<Output = Result<()>> + 'u;
}
