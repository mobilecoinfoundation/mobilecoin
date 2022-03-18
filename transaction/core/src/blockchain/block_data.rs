// Copyright (c) 2018-2021 The MobileCoin Foundation

use crate::{Block, BlockContents, BlockSignature};
use prost::Message;
use serde::{Deserialize, Serialize};

/// An object that holds all data included in and associated with a block.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Message)]
pub struct BlockData {
    #[prost(message, required, tag = "1")]
    block: Block,

    #[prost(message, required, tag = "2")]
    contents: BlockContents,

    #[prost(message, tag = "3")]
    signature: Option<BlockSignature>,
}

impl BlockData {
    /// Create new block data:
    ///
    /// Arguments:
    /// `block`: The block header
    /// `contents`: The block contents
    /// `signature`: A signature over the block
    pub fn new(block: Block, contents: BlockContents, signature: Option<BlockSignature>) -> Self {
        Self {
            block,
            contents,
            signature,
        }
    }

    /// Get the block
    pub fn block(&self) -> &Block {
        &self.block
    }

    /// Get the contents
    pub fn contents(&self) -> &BlockContents {
        &self.contents
    }

    /// Get the signature
    pub fn signature(&self) -> &Option<BlockSignature> {
        &self.signature
    }
}
