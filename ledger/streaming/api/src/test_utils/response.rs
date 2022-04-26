// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Response helper.

use super::make_blocks;
use crate::{ArchiveBlock, Error, Result};
use grpcio::WriteFlags;

/// Generate the requested number of [Responses].
pub fn make_responses(num_responses: usize) -> Responses {
    make_blocks(num_responses)
        .into_iter()
        .map(|block_data| ArchiveBlock::from(&block_data).into())
        .collect()
}

/// Helper for a pre-configured [Result<ArchiveBlock>] repsonse.
#[derive(Clone, Debug)]
pub struct Response(pub Result<ArchiveBlock>);

/// Helper for a list of [Response]s.
pub type Responses = Vec<Response>;

impl Response {
    /// Maps this [Response] to a tuple with the given [WriteFlags]
    pub fn with_write_flags(self, flags: WriteFlags) -> grpcio::Result<(ArchiveBlock, WriteFlags)> {
        grpcio::Result::<ArchiveBlock>::from(self).map(|r| (r, flags))
    }
}

impl AsRef<Result<ArchiveBlock>> for Response {
    fn as_ref(&self) -> &Result<ArchiveBlock> {
        &self.0
    }
}

impl From<ArchiveBlock> for Response {
    fn from(src: ArchiveBlock) -> Self {
        Self(Ok(src))
    }
}

impl From<Error> for Response {
    fn from(src: Error) -> Self {
        Self(Err(src))
    }
}

impl From<Result<ArchiveBlock>> for Response {
    fn from(src: Result<ArchiveBlock>) -> Self {
        Self(src)
    }
}

impl From<Response> for grpcio::Result<ArchiveBlock> {
    fn from(src: Response) -> grpcio::Result<ArchiveBlock> {
        src.0.map_err(|err| grpcio::Error::Codec(err.into()))
    }
}
