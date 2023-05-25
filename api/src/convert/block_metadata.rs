// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Convert to/from blockchain::BlockMetadataContents.

use crate::{blockchain, ConversionError};
use mc_blockchain_types::{BlockMetadata, BlockMetadataContents};
use mc_common::ResponderId;
use std::str::FromStr;

impl From<&BlockMetadataContents> for blockchain::BlockMetadataContents {
    fn from(src: &BlockMetadataContents) -> Self {
        let mut proto = Self::new();
        proto.set_block_id(src.block_id().into());
        proto.set_quorum_set(src.quorum_set().into());
        proto.set_verification_report(src.verification_report().into());
        proto.set_responder_id(src.responder_id().to_string());
        proto
    }
}

impl TryFrom<&blockchain::BlockMetadataContents> for BlockMetadataContents {
    type Error = ConversionError;

    fn try_from(src: &blockchain::BlockMetadataContents) -> Result<Self, Self::Error> {
        let block_id = src.get_block_id().try_into()?;
        let quorum_set = src.get_quorum_set().try_into()?;
        let report = src.get_verification_report().try_into()?;
        let responder_id = ResponderId::from_str(&src.responder_id)
            .map_err(|_| ConversionError::InvalidContents)?;
        Ok(BlockMetadataContents::new(
            block_id,
            quorum_set,
            report,
            responder_id,
        ))
    }
}

impl From<&BlockMetadata> for blockchain::BlockMetadata {
    fn from(src: &BlockMetadata) -> Self {
        let mut proto = Self::new();
        proto.set_contents(src.contents().into());
        proto.set_node_key(src.node_key().into());
        proto.set_signature(src.signature().into());
        proto
    }
}

impl TryFrom<&blockchain::BlockMetadata> for BlockMetadata {
    type Error = ConversionError;

    fn try_from(src: &blockchain::BlockMetadata) -> Result<Self, Self::Error> {
        let contents = src.get_contents().try_into()?;
        let node_key = src.get_node_key().try_into()?;
        let signature = src.get_signature().try_into()?;
        let metadata = BlockMetadata::new(contents, node_key, signature);
        metadata.verify()?;
        Ok(metadata)
    }
}
