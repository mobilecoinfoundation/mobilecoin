// Copyright (c) 2018-2023 The MobileCoin Foundation

use crate::Error;
use mc_blockchain_types::{BlockID, BlockMetadata};
use mc_common::NodeID;
use mc_consensus_scp_types::{QuorumSet, QuorumSetMember};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

/// A trusted validator set consists of:
/// * A quorum set, which is an SCP concept representing recursive k-of-n sets
///   of validators identified by responder id
/// * Implicit in the quorum set, an association of responder id's to node
///   signing keys.
///
/// A trusted validator set can verify a BlockID, given a set of BlockMetadata.
///
/// A block id is considered valid if:
/// * It appeared in BlockMetadataContents corresponding to a quorum of nodes
/// * The message signing key signatures of those nodes are valid
/// * The message signing key signatures were made using the expected keys for
///   that responder id.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct TrustedValidatorSet {
    /// A quorum set of validator nodes that this light client will trust
    pub quorum_set: QuorumSet,
}

impl TrustedValidatorSet {
    /// Validate that a collection of BlockMetadata signing a particular block
    /// ID constitutes a quorum of signatures.
    ///
    /// Arguments:
    /// * block_id - The id of the block that we are verifying
    /// * block_metadata - A collection of block metadata signatures, obtained
    ///   from ArchiveBlock of several validator nodes.
    pub fn verify_block_id_signatures(
        &self,
        block_id: &BlockID,
        block_metadata: &[BlockMetadata],
    ) -> Result<(), Error> {
        for meta in block_metadata.iter() {
            // All block metadata should be signing the expected Block Id.
            if meta.contents().block_id() != block_id {
                return Err(Error::BlockIdMismatch(meta.contents().block_id().clone()));
            }

            // All block metadata should have valid signatures
            if meta.verify().is_err() {
                return Err(Error::BlockMetadataSignature);
            }
        }

        // These node id's have been validated. We need to check if these constitute a
        // quorum according to our quorum set.
        let node_ids: HashSet<_> = block_metadata
            .iter()
            .map(|meta| NodeID {
                responder_id: meta.contents().responder_id().clone(),
                public_key: *meta.node_key(),
            })
            .collect();

        if !Self::verify_quorum_helper(&node_ids, &self.quorum_set) {
            return Err(Error::NotAQuorum);
        }
        Ok(())
    }

    // Check whether a threshold of members of this quorum set are satisfied,
    // recursing if necessary.
    fn verify_quorum_helper(signing_node_ids: &HashSet<NodeID>, quorum_set: &QuorumSet) -> bool {
        let mut satisfied_members = 0;
        for member in quorum_set.members.iter() {
            match &member.member {
                None => continue,
                Some(QuorumSetMember::Node(id)) => {
                    // Note: We could try to log warnings if signing_node_id mismatches in responder
                    // id or public key, to make this easier to debug
                    if signing_node_ids.contains(id) {
                        satisfied_members += 1;
                    }
                }
                Some(QuorumSetMember::InnerSet(inner_set)) => {
                    if Self::verify_quorum_helper(signing_node_ids, inner_set) {
                        satisfied_members += 1;
                    }
                }
            }
        }

        satisfied_members >= quorum_set.threshold
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use core::assert_matches::assert_matches;
    use mc_blockchain_types::{BlockMetadata, BlockMetadataContents};
    use mc_consensus_scp_types::test_utils::{test_node_id, test_node_id_and_signer};

    #[test]
    fn test_verify_quorum_helper_3_of_5() {
        let qs = QuorumSet::new(
            3,
            vec![
                QuorumSetMember::Node(test_node_id(1)),
                QuorumSetMember::Node(test_node_id(2)),
                QuorumSetMember::Node(test_node_id(3)),
                QuorumSetMember::Node(test_node_id(4)),
                QuorumSetMember::Node(test_node_id(5)),
            ],
        );

        assert!(TrustedValidatorSet::verify_quorum_helper(
            &HashSet::from([test_node_id(1), test_node_id(2), test_node_id(3)]),
            &qs
        ));
        assert!(TrustedValidatorSet::verify_quorum_helper(
            &HashSet::from([test_node_id(1), test_node_id(2), test_node_id(5)]),
            &qs
        ));
        assert!(TrustedValidatorSet::verify_quorum_helper(
            &HashSet::from([test_node_id(4), test_node_id(3), test_node_id(5)]),
            &qs
        ));
        assert!(TrustedValidatorSet::verify_quorum_helper(
            &HashSet::from([
                test_node_id(4),
                test_node_id(3),
                test_node_id(5),
                test_node_id(1)
            ]),
            &qs
        ));
        assert!(TrustedValidatorSet::verify_quorum_helper(
            &HashSet::from([
                test_node_id(4),
                test_node_id(3),
                test_node_id(5),
                test_node_id(17)
            ]),
            &qs
        ));
        assert!(TrustedValidatorSet::verify_quorum_helper(
            &HashSet::from([
                test_node_id(0),
                test_node_id(1),
                test_node_id(2),
                test_node_id(3)
            ]),
            &qs
        ));

        assert!(!TrustedValidatorSet::verify_quorum_helper(
            &HashSet::from([test_node_id(1)]),
            &qs
        ));
        assert!(!TrustedValidatorSet::verify_quorum_helper(
            &HashSet::from([test_node_id(1), test_node_id(2)]),
            &qs
        ));
        assert!(!TrustedValidatorSet::verify_quorum_helper(
            &HashSet::from([test_node_id(3), test_node_id(2)]),
            &qs
        ));
        assert!(!TrustedValidatorSet::verify_quorum_helper(
            &HashSet::from([test_node_id(1), test_node_id(2), test_node_id(0)]),
            &qs
        ));
        assert!(!TrustedValidatorSet::verify_quorum_helper(
            &HashSet::from([test_node_id(1), test_node_id(2), test_node_id(6)]),
            &qs
        ));
        assert!(!TrustedValidatorSet::verify_quorum_helper(
            &HashSet::from([test_node_id(1), test_node_id(7), test_node_id(6)]),
            &qs
        ));
    }

    #[test]
    fn test_verify_quorum_helper_complex() {
        let qs = QuorumSet::new(
            2,
            vec![
                QuorumSetMember::Node(test_node_id(1)),
                QuorumSetMember::InnerSet(QuorumSet::new(
                    2,
                    vec![
                        QuorumSetMember::Node(test_node_id(3)),
                        QuorumSetMember::Node(test_node_id(2)),
                        QuorumSetMember::InnerSet(QuorumSet::new_with_node_ids(
                            2,
                            vec![test_node_id(5), test_node_id(7), test_node_id(6)],
                        )),
                    ],
                )),
                QuorumSetMember::Node(test_node_id(0)),
            ],
        );

        assert!(TrustedValidatorSet::verify_quorum_helper(
            &HashSet::from([test_node_id(1), test_node_id(0)]),
            &qs
        ));
        assert!(TrustedValidatorSet::verify_quorum_helper(
            &HashSet::from([test_node_id(1), test_node_id(2), test_node_id(3)]),
            &qs
        ));
        assert!(!TrustedValidatorSet::verify_quorum_helper(
            &HashSet::from([test_node_id(1), test_node_id(2), test_node_id(5)]),
            &qs
        ));
        assert!(!TrustedValidatorSet::verify_quorum_helper(
            &HashSet::from([test_node_id(4), test_node_id(3), test_node_id(5)]),
            &qs
        ));
        assert!(!TrustedValidatorSet::verify_quorum_helper(
            &HashSet::from([
                test_node_id(4),
                test_node_id(3),
                test_node_id(5),
                test_node_id(1)
            ]),
            &qs
        ));
        assert!(TrustedValidatorSet::verify_quorum_helper(
            &HashSet::from([
                test_node_id(6),
                test_node_id(3),
                test_node_id(5),
                test_node_id(1)
            ]),
            &qs
        ));
        assert!(!TrustedValidatorSet::verify_quorum_helper(
            &HashSet::from([
                test_node_id(4),
                test_node_id(3),
                test_node_id(5),
                test_node_id(17)
            ]),
            &qs
        ));
        assert!(TrustedValidatorSet::verify_quorum_helper(
            &HashSet::from([
                test_node_id(0),
                test_node_id(1),
                test_node_id(2),
                test_node_id(3)
            ]),
            &qs
        ));
        assert!(!TrustedValidatorSet::verify_quorum_helper(
            &HashSet::from([test_node_id(1)]),
            &qs
        ));
        assert!(!TrustedValidatorSet::verify_quorum_helper(
            &HashSet::from([test_node_id(1), test_node_id(2)]),
            &qs
        ));
        assert!(!TrustedValidatorSet::verify_quorum_helper(
            &HashSet::from([test_node_id(3), test_node_id(2)]),
            &qs
        ));
        assert!(TrustedValidatorSet::verify_quorum_helper(
            &HashSet::from([test_node_id(1), test_node_id(2), test_node_id(0)]),
            &qs
        ));
        assert!(!TrustedValidatorSet::verify_quorum_helper(
            &HashSet::from([test_node_id(1), test_node_id(2), test_node_id(6)]),
            &qs
        ));
        assert!(!TrustedValidatorSet::verify_quorum_helper(
            &HashSet::from([test_node_id(1), test_node_id(7), test_node_id(6)]),
            &qs
        ));
        assert!(TrustedValidatorSet::verify_quorum_helper(
            &HashSet::from([
                test_node_id(1),
                test_node_id(7),
                test_node_id(6),
                test_node_id(3)
            ]),
            &qs
        ));
    }

    fn sign_block_id_for_test_node_id(block_id: &BlockID, id: u32) -> BlockMetadata {
        let (_, keypair) = test_node_id_and_signer(id);
        let bmc = BlockMetadataContents::new(
            block_id.clone(),
            Default::default(),
            Default::default(),
            Default::default(),
        );
        BlockMetadata::from_contents_and_keypair(bmc, &keypair).unwrap()
    }

    pub fn sign_block_id_for_test_node_ids(block_id: &BlockID, ids: &[u32]) -> Vec<BlockMetadata> {
        ids.iter()
            .map(|node_id: &u32| sign_block_id_for_test_node_id(&block_id, *node_id))
            .collect()
    }

    #[test]
    fn test_verify_block_id_signatures_3_of_5() {
        let qs = QuorumSet::new(
            3,
            vec![
                QuorumSetMember::Node(test_node_id(1)),
                QuorumSetMember::Node(test_node_id(2)),
                QuorumSetMember::Node(test_node_id(3)),
                QuorumSetMember::Node(test_node_id(4)),
                QuorumSetMember::Node(test_node_id(5)),
            ],
        );
        let tvs = TrustedValidatorSet { quorum_set: qs };

        let block_id1 = BlockID([1u8; 32]);
        let block_id2 = BlockID([2u8; 32]);

        let mut metadata = sign_block_id_for_test_node_ids(&block_id1, &[1, 2, 3]);

        // Test that when a quorum signs the right block id, we have success
        tvs.verify_block_id_signatures(&block_id1, &metadata)
            .unwrap();
        // Test that when asked about a different block id, but with same sigs, we have
        // an error
        assert_matches!(
            tvs.verify_block_id_signatures(&block_id2, &metadata),
            Err(Error::BlockIdMismatch(_))
        );

        let old_contents = metadata[0].contents().clone();
        let old_node_key = metadata[0].node_key().clone();

        // Test that if the first metadata is changed to sign a different block id from
        // the others, we have an error.
        metadata[0] = sign_block_id_for_test_node_id(&block_id2, 1);
        assert_matches!(
            tvs.verify_block_id_signatures(&block_id1, &metadata),
            Err(Error::BlockIdMismatch(_))
        );
        assert_matches!(
            tvs.verify_block_id_signatures(&block_id2, &metadata),
            Err(Error::BlockIdMismatch(_))
        );

        // Test that if the first metadata has the old (correct) contents and node key,
        // but the new signature, we have an error.
        let new_sig = metadata[0].signature().clone();
        metadata[0] = BlockMetadata::new(old_contents, old_node_key, new_sig);
        assert_matches!(
            tvs.verify_block_id_signatures(&block_id1, &metadata),
            Err(Error::BlockMetadataSignature)
        );
        assert_matches!(
            tvs.verify_block_id_signatures(&block_id2, &metadata),
            Err(Error::BlockIdMismatch(_))
        );

        // Test that when we don't actually have a quorum, we get an error
        let metadata = sign_block_id_for_test_node_ids(&block_id1, &[1, 2]);
        assert_matches!(
            tvs.verify_block_id_signatures(&block_id1, &metadata),
            Err(Error::NotAQuorum)
        );
        assert_matches!(
            tvs.verify_block_id_signatures(&block_id2, &metadata),
            Err(Error::BlockIdMismatch(_))
        );
    }
}
