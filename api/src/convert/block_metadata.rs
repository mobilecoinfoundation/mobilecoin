// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Convert to/from blockchain::BlockMetadataContents.

use crate::{blockchain, blockchain::block_metadata_contents, ConversionError};
use mc_blockchain_types::{AttestationEvidence, BlockMetadata, BlockMetadataContents};
use mc_common::ResponderId;
use std::str::FromStr;

impl From<&BlockMetadataContents> for blockchain::BlockMetadataContents {
    fn from(src: &BlockMetadataContents) -> Self {
        let attesetation_evidence = match src.attestation_evidence() {
            AttestationEvidence::DcapEvidence(evidence) => {
                block_metadata_contents::AttestationEvidence::DcapEvidence(evidence.into())
            }
            AttestationEvidence::VerificationReport(report) => {
                block_metadata_contents::AttestationEvidence::VerificationReport(report.into())
            }
        };
        Self {
            block_id: Some(src.block_id().into()),
            quorum_set: Some(src.quorum_set().into()),
            responder_id: src.responder_id().to_string(),
            attestation_evidence: Some(attesetation_evidence),
        }
    }
}

impl TryFrom<&blockchain::BlockMetadataContents> for BlockMetadataContents {
    type Error = ConversionError;

    fn try_from(src: &blockchain::BlockMetadataContents) -> Result<Self, Self::Error> {
        let block_id = src
            .block_id
            .as_ref()
            .unwrap_or(&Default::default())
            .try_into()?;
        let quorum_set = src
            .quorum_set
            .as_ref()
            .unwrap_or(&Default::default())
            .try_into()?;
        let attestation_evidence = match &src.attestation_evidence {
            Some(block_metadata_contents::AttestationEvidence::DcapEvidence(evidence)) => {
                let evidence = evidence.into();
                AttestationEvidence::DcapEvidence(evidence)
            }
            Some(block_metadata_contents::AttestationEvidence::VerificationReport(report)) => {
                let report = report.into();
                AttestationEvidence::VerificationReport(report)
            }
            None => {
                return Err(ConversionError::MissingField(
                    "attestation_evidence".to_string(),
                ))
            }
        };
        let responder_id = ResponderId::from_str(&src.responder_id)
            .map_err(|_| ConversionError::InvalidContents)?;
        Ok(BlockMetadataContents::new(
            block_id,
            quorum_set,
            attestation_evidence,
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
            .unwrap_or(&Default::default())
            .try_into()?;
        let node_key = src
            .node_key
            .as_ref()
            .unwrap_or(&Default::default())
            .try_into()?;
        let signature = src
            .signature
            .as_ref()
            .unwrap_or(&Default::default())
            .try_into()?;
        let metadata = BlockMetadata::new(contents, node_key, signature);
        metadata.verify()?;
        Ok(metadata)
    }
}
