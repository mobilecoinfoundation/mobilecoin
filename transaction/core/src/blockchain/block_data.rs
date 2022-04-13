// Copyright (c) 2018-2022 The MobileCoin Foundation

use crate::{Block, BlockContents, BlockSignature, SignedBlockMetadata};
use mc_crypto_digestible::Digestible;
use serde::{Deserialize, Serialize};

/// An object that holds all data included in and associated with a block.
#[derive(Clone, Debug, Deserialize, Digestible, Eq, PartialEq, Serialize)]
pub struct BlockData {
    block: Block,

    contents: BlockContents,

    signature: Option<BlockSignature>,

    metadata: Option<SignedBlockMetadata>,
}

impl BlockData {
    /// Create new block data:
    ///
    /// Arguments:
    /// `block`: The block header
    /// `contents`: The block contents
    /// `signature`: A signature over the block
    // TODO: Replace this with `new_with_metadata`
    pub fn new(block: Block, contents: BlockContents, signature: Option<BlockSignature>) -> Self {
        Self {
            block,
            contents,
            signature,
            metadata: None,
        }
    }

    // TODO: Replace new() with this variant.
    /// Create new block data:
    ///
    /// Arguments:
    /// `block`: The block header
    /// `contents`: The block contents
    /// `signature`: A signature over the block
    /// `metadata`: Signed metadata for the block
    pub fn new_with_metadata(
        block: Block,
        contents: BlockContents,
        signature: Option<BlockSignature>,
        // Allows passing `Some(metadata)`, `metadata`, `None`.
        metadata: impl Into<Option<SignedBlockMetadata>>,
    ) -> Self {
        Self {
            block,
            contents,
            signature,
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
    pub fn signature(&self) -> &Option<BlockSignature> {
        &self.signature
    }

    /// Get the metadata.
    pub fn metadata(&self) -> &Option<SignedBlockMetadata> {
        &self.metadata
    }
}
