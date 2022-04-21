// Copyright (c) 2018-2022 The MobileCoin Foundation

//! A [ProtoWriter] that uploads to S3.

pub use aws_sdk_s3::{Config, Region};

use crate::ProtoWriter;
use aws_sdk_s3::Client;
use futures::Future;
use mc_ledger_streaming_api::{Error, Result};
use protobuf::Message;
use std::path::{Path, PathBuf};

/// A [ProtoWriter] using an S3 [Client].
#[derive(Clone, Debug)]
pub struct S3ClientProtoWriter {
    client: Client,
    root: PathBuf,
}

impl S3ClientProtoWriter {
    /// Instantiate an writer with the given [Region].
    pub fn new(region: Region, root: PathBuf) -> Self {
        let config = Config::builder().region(region).build();
        Self::from_config(config, root)
    }

    /// Instantiate an writer with the given [Config].
    pub fn from_config(config: Config, root: PathBuf) -> Self {
        let client = Client::from_conf(config);
        Self { client, root }
    }

    async fn write_to_s3(
        &self,
        dest: &Path,
        bytes: protobuf::ProtobufResult<Vec<u8>>,
    ) -> Result<()> {
        let bytes = bytes?;
        let dest = self.root.join(dest);
        let bucket = dest
            .parent()
            .ok_or_else(|| {
                Error::Other(format!(
                    "Failed to get parent dir from path {}",
                    dest.display()
                ))
            })?
            .to_str()
            .unwrap();
        let key = dest
            .file_name()
            .ok_or_else(|| {
                Error::Other(format!(
                    "Failed to get base name from path {}",
                    dest.display()
                ))
            })?
            .to_str()
            .unwrap();

        self.client
            .put_object()
            .bucket(bucket)
            .key(key)
            .body(bytes.into())
            .send()
            .await
            .map_err(|e| Error::Other(format!("Failed to upload to S3: {}", e)))
            .map(|_| ())
    }
}

impl ProtoWriter for S3ClientProtoWriter {
    fn upload<'up, M: Message>(&'up self, proto: &'up M, dest: &'up Path) -> Self::Future<'up> {
        self.write_to_s3(dest, proto.write_to_bytes())
    }

    type Future<'u> = impl Future<Output = Result<()>> + 'u;
}
