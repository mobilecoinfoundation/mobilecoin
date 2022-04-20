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
    root: PathBuf,
}

impl LocalFileProtoWriter {
    /// Instantiate a writer that writes to files under the given path.
    pub fn new(root: PathBuf) -> Self {
        Self { root }
    }

    async fn write(&self, dest: PathBuf, bytes: protobuf::ProtobufResult<Vec<u8>>) -> Result<()> {
        let bytes = bytes?;
        let path = self.root.join(dest);
        tokio::fs::write(&path, bytes).await.map_err(|e| {
            Error::IO(
                format!("Failed to write to {}: {}", path.display(), e),
                e.kind(),
            )
        })
    }
}

impl ProtoWriter for LocalFileProtoWriter {
    fn upload<'up, M: Message>(&'up mut self, proto: &'up M, dest: &'up Path) -> Self::Future<'up> {
        let dest = self.root.join(dest);
        self.write(dest, proto.write_to_bytes())
    }

    type Future<'u> = impl Future<Output = Result<()>> + 'u;
}
