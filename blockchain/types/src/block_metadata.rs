// Copyright (c) 2018-2022 The MobileCoin Foundation

use crate::{
    crypto::metadata::{MetadataSigner, MetadataVerifier},
    BlockID, QuorumSet, VerificationReport,
};
use displaydoc::Display;
use mc_common::ResponderId;
use mc_crypto_digestible::Digestible;
use mc_crypto_keys::{Ed25519Pair, Ed25519Public, Ed25519Signature, SignatureError};
use prost::Message;
use serde::{Deserialize, Serialize};

/// Metadata for a block.
#[derive(Clone, Deserialize, Digestible, Display, Eq, Message, PartialEq, Serialize)]
pub struct BlockMetadataContents {
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

impl BlockMetadataContents {
    /// Instantiate a [BlockMetadataContents] with the given data.
    pub fn new(
        block_id: BlockID,
        quorum_set: QuorumSet,
        verification_report: VerificationReport,
        responder_id: ResponderId,
    ) -> Self {
        Self {
            block_id,
            quorum_set,
            verification_report,
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

    /// Get the Attested [VerificationReport].
    pub fn verification_report(&self) -> &VerificationReport {
        &self.verification_report
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
