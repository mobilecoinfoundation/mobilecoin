// Copyright (c) 2018-2022 The MobileCoin Foundation

use crate::{
    crypto::metadata::{MetadataSigner, MetadataVerifier},
    BlockID, QuorumSet, VerificationReport,
};
use displaydoc::Display;
use mc_attest_verifier_types::DcapEvidence;
use mc_common::ResponderId;
use mc_crypto_digestible::Digestible;
use mc_crypto_keys::{Ed25519Pair, Ed25519Public, Ed25519Signature, SignatureError};
use prost::Message;
use serde::{Deserialize, Serialize};

/// The attestation evidence variants for a block.
#[derive(Clone, prost::Oneof, Deserialize, Display, Eq, PartialEq, Serialize, Digestible)]
#[digestible(transparent)]
pub enum AttestationEvidence {
    /// The attestation evidence is a [VerificationReport].
    #[prost(message, tag = 3)]
    VerificationReport(VerificationReport),
    /// DCAP evidence
    #[prost(message, tag = 5)]
    DcapEvidence(DcapEvidence),
}

impl From<VerificationReport> for AttestationEvidence {
    fn from(report: VerificationReport) -> Self {
        Self::VerificationReport(report)
    }
}

impl From<DcapEvidence> for AttestationEvidence {
    fn from(evidence: DcapEvidence) -> Self {
        Self::DcapEvidence(evidence)
    }
}

/// Metadata for a block.
#[derive(Clone, Deserialize, Digestible, Display, Eq, Message, PartialEq, Serialize)]
pub struct BlockMetadataContents {
    /// The Block ID.
    #[prost(message, required, tag = 1)]
    block_id: BlockID,

    /// Quorum set configuration at the time of externalization.
    #[prost(message, required, tag = 2)]
    quorum_set: QuorumSet,

    /// Attestation evidence for the enclave which generated the signature.
    #[prost(oneof = "AttestationEvidence", tags = "3, 5")]
    #[digestible(name = "verification_report")]
    attestation_evidence: Option<AttestationEvidence>,

    /// Responder ID of the consensus node that externalized this block.
    #[prost(message, required, tag = 4)]
    responder_id: ResponderId,
}

impl BlockMetadataContents {
    /// Instantiate a [BlockMetadataContents] with the given data.
    pub fn new(
        block_id: BlockID,
        quorum_set: QuorumSet,
        attestation_evidence: AttestationEvidence,
        responder_id: ResponderId,
    ) -> Self {
        Self {
            block_id,
            quorum_set,
            attestation_evidence: Some(attestation_evidence),
            responder_id,
        }
    }

    /// Get the [BlockID].
    pub fn block_id(&self) -> &BlockID {
        &self.block_id
    }

    /// Get the [QuorumSet].
    pub fn quorum_set(&self) -> &QuorumSet {
        &self.quorum_set
    }

    /// Get the Attestation evidence.
    pub fn attestation_evidence(&self) -> &AttestationEvidence {
        self.attestation_evidence
            .as_ref()
            .expect("Attestation evidence is always set")
    }

    /// Get the [ResponderId].
    pub fn responder_id(&self) -> &ResponderId {
        &self.responder_id
    }
}

/// Signed metadata for a block.
#[derive(Clone, Deserialize, Digestible, Display, Eq, Message, PartialEq, Serialize)]
pub struct BlockMetadata {
    /// Metadata signed by the consensus node.
    #[prost(message, required, tag = 1)]
    contents: BlockMetadataContents,

    /// Message signing key (signer).
    #[prost(message, required, tag = 2)]
    node_key: Ed25519Public,

    /// Signature using `node_key` over the Digestible encoding of `contents`.
    #[prost(message, required, tag = 3)]
    signature: Ed25519Signature,
}

impl BlockMetadata {
    /// Instantiate a [BlockMetadata] with the given data.
    pub fn new(
        contents: BlockMetadataContents,
        node_key: Ed25519Public,
        signature: Ed25519Signature,
    ) -> Self {
        Self {
            contents,
            node_key,
            signature,
        }
    }

    /// Instantiate a [BlockMetadata] by signing the given
    /// [BlockMetadataContents] with the given [Ed25519Pair].
    pub fn from_contents_and_keypair(
        contents: BlockMetadataContents,
        key_pair: &Ed25519Pair,
    ) -> Result<Self, SignatureError> {
        let signature = key_pair.sign_metadata(&contents)?;
        Ok(Self::new(contents, key_pair.public_key(), signature))
    }

    /// Verify that this signature is over a given block.
    pub fn verify(&self) -> Result<(), SignatureError> {
        self.node_key
            .verify_metadata(&self.contents, &self.signature)
    }

    /// Get the [BlockMetadataContents].
    pub fn contents(&self) -> &BlockMetadataContents {
        &self.contents
    }

    /// Get the signing key.
    pub fn node_key(&self) -> &Ed25519Public {
        &self.node_key
    }

    /// Get the signature.
    pub fn signature(&self) -> &Ed25519Signature {
        &self.signature
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::QuorumSetMember;
    use alloc::vec;
    use mc_blockchain_test_utils::test_node_id;
    use mc_crypto_digestible::MerlinTranscript;

    /// Metadata contents used in block version 3
    #[derive(Clone, Deserialize, Digestible, Display, Eq, Message, PartialEq, Serialize)]
    #[digestible(name = "BlockMetadataContents")]
    struct BlockMetadataContentsV3 {
        /// The Block ID.
        #[prost(message, required, tag = 1)]
        block_id: BlockID,

        /// Quorum set configuration at the time of externalization.
        #[prost(message, required, tag = 2)]
        quorum_set: QuorumSet,

        /// IAS report for the enclave which generated the signature.
        #[prost(message, required, tag = 3)]
        verification_report: VerificationReport,

        /// Responder ID of the consensus node that externalized this block.
        #[prost(message, required, tag = 4)]
        responder_id: ResponderId,
    }

    #[test]
    fn metadata_contents_version_3_works_with_version_4() {
        let quorum_set = QuorumSet::new(
            2,
            vec![
                QuorumSetMember::Node(test_node_id(9)),
                QuorumSetMember::Node(test_node_id(8)),
                QuorumSetMember::Node(test_node_id(7)),
            ],
        );

        let block_v3 = BlockMetadataContentsV3 {
            block_id: BlockID([1; 32]),
            quorum_set: quorum_set.clone(),
            verification_report: VerificationReport::default(),
            responder_id: ResponderId("hello".into()),
        };

        let bytes = mc_util_serial::encode(&block_v3);

        let block_v4: BlockMetadataContents = mc_util_serial::decode(&bytes).unwrap();

        assert_eq!(block_v4.block_id(), &BlockID([1; 32]));
        assert_eq!(block_v4.quorum_set(), &quorum_set);
        assert_eq!(block_v4.responder_id(), &ResponderId("hello".into()));
        assert_eq!(
            block_v4.attestation_evidence,
            Some(AttestationEvidence::VerificationReport(
                VerificationReport::default()
            ))
        );

        let block_v3_digest = block_v3.digest32::<MerlinTranscript>(b"");
        let block_v4_digest = block_v4.digest32::<MerlinTranscript>(b"");
        assert_eq!(block_v3_digest, block_v4_digest);
    }
}
