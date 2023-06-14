// Copyright (c) 2018-2023 The MobileCoin Foundation

use crate::Error;
use mc_blockchain_types::{BlockID, BlockMetadata};
use mc_common::NodeID;
use mc_consensus_scp_types::{QuorumSet, QuorumSetMember};
use std::collections::HashSet;

/// A trusted validator set consists of:
/// * A quorum set, which is an SCP concept representing recursive k-of-n sets
///   of validators identified by responder id
/// * Implicit in the quorum set, an association of responder id's to node
///   signing keys.
///
/// A trusted validator set can verify a set of BlockMetadata, producing a
/// validated BlockID.
///
/// A block id is considered valid if:
/// * It appeared in BlockMetadataContents corresponding to a quorum of nodes
/// * The message signing key signatures of those nodes are valid
/// * The message signing key signatures were made using the expected keys for
///   that responder id.
#[derive(Clone, Debug)]
pub struct TrustedValidatorSet {
    /// A quorum set of validator nodes that this light client will trust
    pub quorum_set: QuorumSet,
}

impl TrustedValidatorSet {
    /// Validate that a collection of BlockMetadata signing a particular block
    /// ID constitutes a quorum of signatures.
    ///
    /// Arguments:
    /// * block_metadata - A collection of block metadata signatures, obtained
    ///   from ArchiveBlock of several validator nodes.
    pub fn validate_block_id_signatures(
        &self,
        block_metadata: &[BlockMetadata],
    ) -> Result<BlockID, Error> {
        if block_metadata.is_empty() {
            return Err(Error::NoBlockMetadata);
        }
        let block_id = block_metadata[0].contents().block_id().clone();

        for meta in block_metadata.iter() {
            // All block metadata should be signing the same Block Id.
            if meta.contents().block_id() != &block_id {
                return Err(Error::BlockIdMismatch);
            }

            // All block metadata should have valid signatures
            if meta.verify().is_err() {
                return Err(Error::BlockSignature);
            }
        }

        // These node id's have been validated. We need to check if these constitute a
        // quorum according to our quorum set.
        let node_ids: HashSet<_> = block_metadata
            .iter()
            .map(|meta| NodeID {
                responder_id: meta.contents().responder_id().clone(),
                public_key: meta.node_key().clone(),
            })
            .collect();

        if !Self::validate_quorum_helper(&node_ids, &self.quorum_set) {
            return Err(Error::NotAQuorum);
        }
        Ok(block_id)
    }

    // Check whether a threshold of elements of this quorum set are satisfied,
    // recursing if necessary.
    fn validate_quorum_helper(signing_node_ids: &HashSet<NodeID>, quorum_set: &QuorumSet) -> bool {
        let mut satisfied_members = 0;
        for member in quorum_set.members.iter() {
            match &member.member {
                None => continue,
                // Note: We could try to log warnings if signing_node_id mismatches in responder id
                // or public key, to make this easier to debug
                Some(QuorumSetMember::Node(id)) => {
                    if signing_node_ids.contains(id) {
                        satisfied_members += 1;
                    }
                }
                Some(QuorumSetMember::InnerSet(inner_set)) => {
                    if Self::validate_quorum_helper(signing_node_ids, &inner_set) {
                        satisfied_members += 1;
                    }
                }
            }
        }

        satisfied_members >= quorum_set.threshold
    }
}
