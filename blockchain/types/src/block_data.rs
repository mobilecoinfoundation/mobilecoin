// Copyright (c) 2018-2022 The MobileCoin Foundation

use crate::{Block, BlockContents, BlockMetadata, BlockSignature};
use prost::Message;
use serde::{Deserialize, Serialize};

/// An object that holds all data included in and associated with a block.
#[derive(Clone, Deserialize, Eq, Message, PartialEq, Serialize)]
pub struct BlockData {
    /// The block header.
    #[prost(message, required, tag = 1)]
    block: Block,

    /// The block contents.
    #[prost(message, required, tag = 2)]
    contents: BlockContents,

    /// A signature over the [Block].
    #[prost(message, optional, tag = 3)]
    signature: Option<BlockSignature>,

    /// Block metadata.
    #[prost(message, optional, tag = 4)]
    metadata: Option<BlockMetadata>,
}

impl BlockData {
    /// Create new block data:
    ///
    /// Arguments:
    /// `block`: The block header
    /// `contents`: The block contents
    /// `signature`: An optional signature over the block.
    ///     Supports passing `signature`, `Some(signature)`, `None`.
    /// `metadata`: Optional metadata for the block.
    ///     Supports passing `metadata`, `Some(metadata)`, `None`.
    ///     This will become required with a future BlockVersion.
    pub fn new(
        block: Block,
        contents: BlockContents,
        signature: impl Into<Option<BlockSignature>>,
        metadata: impl Into<Option<BlockMetadata>>,
    ) -> Self {
        Self {
            block,
            contents,
            signature: signature.into(),
            metadata: metadata.into(),
        }
    }

    /// Get the block.
    pub fn block(&self) -> &Block {
        &self.block
    }

    /// Get the contents.
    pub fn contents(&self) -> &BlockContents {
        &self.contents
    }

    /// Get the signature.
    pub fn signature(&self) -> Option<&BlockSignature> {
        self.signature.as_ref()
    }

    /// Get the metadata.
    pub fn metadata(&self) -> Option<&BlockMetadata> {
        self.metadata.as_ref()
    }

    /// Map this [BlockData] to another, after applying the given mutation.
    pub fn mutate(
        mut self,
        mutate: impl FnOnce(
            &mut Block,
            &mut BlockContents,
            &mut Option<BlockSignature>,
            &mut Option<BlockMetadata>,
        ),
    ) -> Self {
        mutate(
            &mut self.block,
            &mut self.contents,
            &mut self.signature,
            &mut self.metadata,
        );
        self
    }
}
