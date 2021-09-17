// Copyright (c) 2018-2021 The MobileCoin Foundation

pub use mc_attest_core::VerificationReport;
use mc_transaction_core::{Block, BlockContents, BlockSignature};
use prost::Message;
use serde::{Deserialize, Serialize};

/// An object that holds all data included in and associated with an archived
/// block.
///
/// This should be convertible to blockchain::ArchiveBlock
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Message)]
pub struct ArchiveBlock {
    #[prost(message, required, tag = "1")]
    block: Block,

    #[prost(message, required, tag = "2")]
    contents: BlockContents,

    #[prost(message, tag = "3")]
    signature: Option<BlockSignature>,

    #[prost(message, tag = "4")]
    verification_report: Option<VerificationReport>,
}

impl ArchiveBlock {
    pub fn new(
        block: Block,
        contents: BlockContents,
        signature: Option<BlockSignature>,
        verification_report: Option<VerificationReport>,
    ) -> Self {
        Self {
            block,
            contents,
            signature,
            verification_report,
        }
    }

    pub fn block(&self) -> &Block {
        &self.block
    }

    pub fn contents(&self) -> &BlockContents {
        &self.contents
    }

    pub fn signature(&self) -> &Option<BlockSignature> {
        &self.signature
    }

    pub fn verification_report(&self) -> &Option<VerificationReport> {
        &self.verification_report
    }
}
