// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Convert to/from blockchain::BlockMetadataContents.

use crate::{blockchain, ConversionError};
use mc_blockchain_types::{BlockMetadata, BlockMetadataContents};
use mc_common::ResponderId;
use std::str::FromStr;

impl From<&BlockMetadataContents> for blockchain::BlockMetadataContents {
    fn from(src: &BlockMetadataContents) -> Self {
        Self {
            block_id: Some(src.block_id().into()),
            quorum_set: Some(src.quorum_set().into()),
            verification_report: Some(src.verification_report().into()),
            responder_id: src.responder_id().to_string(),
        }
    }
}

impl TryFrom<&blockchain::BlockMetadataContents> for BlockMetadataContents {
    type Error = ConversionError;

    fn try_from(src: &blockchain::BlockMetadataContents) -> Result<Self, Self::Error> {
        let block_id = src
            .block_id
            .as_ref()
            .ok_or(ConversionError::ObjectMissing)?
            .try_into()?;

        let quorum_set = src
            .quorum_set
            .as_ref()
            .ok_or(ConversionError::ObjectMissing)?
            .try_into()?;

        let report = src
            .verification_report
            .as_ref()
            .ok_or(ConversionError::ObjectMissing)?
            .try_into()?;

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
        Self {
            contents: Some(src.contents().into()),
            node_key: Some(src.node_key().into()),
            signature: Some(src.signature().into()),
        }
    }
}

impl TryFrom<&blockchain::BlockMetadata> for BlockMetadata {
    type Error = ConversionError;

    fn try_from(src: &blockchain::BlockMetadata) -> Result<Self, Self::Error> {
        let contents = src
            .contents
            .as_ref()
            .ok_or(ConversionError::ObjectMissing)?
            .try_into()?;
        let node_key = src
            .node_key
            .as_ref()
            .ok_or(ConversionError::ObjectMissing)?
            .try_into()?;
        let signature = src
            .signature
            .as_ref()
            .ok_or(ConversionError::ObjectMissing)?
            .try_into()?;

        let metadata = BlockMetadata::new(contents, node_key, signature);
        metadata.verify()?;
        Ok(metadata)
    }
}
