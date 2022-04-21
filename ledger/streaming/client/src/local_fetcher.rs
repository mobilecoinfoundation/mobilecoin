// Copyright (c) 2018-2022 The MobileCoin Foundation

//! A [Fetcher] that reads [ArchiveBlock]s from local files.

use futures::{Future, Stream, StreamExt};
use mc_api::block_num_to_s3block_path;
use mc_ledger_streaming_api::{ArchiveBlock, BlockData, BlockIndex, Error, Fetcher, Result};
use protobuf::Message;
use std::{ops::Range, path::PathBuf};

/// A [Fetcher] that reads [ArchiveBlock]s from local files.
pub struct LocalBlockFetcher {
    base: PathBuf,
}

impl LocalBlockFetcher {
    /// Instantiate a [LocalBlockFetcher] with the given base path.
    pub fn new(base: impl Into<PathBuf>) -> Self {
        Self { base: base.into() }
    }

    /// Fetch a block by index.
    pub async fn get_block(&self, block_index: BlockIndex) -> Result<BlockData> {
        let path = self.base.join(block_num_to_s3block_path(block_index));
        let bytes = tokio::fs::read(&path)
            .await
            .map_err(|err| Error::IO(format!("Failed to read {:?}: {}", path, err), err.kind()))?;
        let archive_block = ArchiveBlock::parse_from_bytes(&bytes[..])?;
        Ok(BlockData::try_from(&archive_block)?)
    }
}

impl Fetcher<Result<BlockData>, BlockIndex, Range<BlockIndex>> for LocalBlockFetcher {
    type Single<'s> = impl Future<Output = Result<BlockData>> + 's;
    type Multiple<'s> = impl Stream<Item = Result<BlockData>> + 's;

    fn fetch_single(&self, index: BlockIndex) -> Self::Single<'_> {
        self.get_block(index)
    }

    fn fetch_multiple(&self, indexes: Range<BlockIndex>) -> Self::Multiple<'_> {
        futures::stream::iter(indexes).then(move |idx| self.fetch_single(idx))
    }
}
