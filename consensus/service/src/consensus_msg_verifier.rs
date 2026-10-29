// Copyright (c) 2026 The MobileCoin Foundation

//! Check configured issuer keys while preserving transitive SCP participants.

use displaydoc::Display;
use mc_common::{HashMap, NodeID, ResponderId};
use mc_peers::{ConsensusMsg, ConsensusMsgError, VerifiedConsensusMsg};

pub struct ConsensusMsgVerifier {
    known_nodes: HashMap<ResponderId, NodeID>,
}

#[derive(Debug, Display)]
pub enum ConsensusMsgVerificationError {
    /// Consensus message signing key does not match configuration for {0}
    PublicKeyMismatch(ResponderId),
    /// Invalid consensus message signature: {0}
    InvalidSignature(ConsensusMsgError),
}

impl ConsensusMsgVerifier {
    pub fn new(known_nodes: impl IntoIterator<Item = NodeID>) -> Self {
        Self {
            known_nodes: known_nodes
                .into_iter()
                .map(|node| (node.responder_id.clone(), node))
                .collect(),
        }
    }

    pub fn verify(
        &self,
        msg: ConsensusMsg,
    ) -> Result<VerifiedConsensusMsg, ConsensusMsgVerificationError> {
        let issuer = msg.issuer_node_id();
        // NodeID equality compares only public keys. Resolve the claimed responder
        // first so a key configured for a different responder cannot impersonate it.
        if let Some(expected) = self.known_nodes.get(&issuer.responder_id) {
            if issuer.public_key != expected.public_key {
                return Err(ConsensusMsgVerificationError::PublicKeyMismatch(
                    issuer.responder_id.clone(),
                ));
            }
        }

        // Unconfigured participants may be referenced by other nodes' signed
        // quorum sets. Their signatures are checked here; SCP matches their keys
        // against those references before counting their votes.
        msg.try_into()
            .map_err(ConsensusMsgVerificationError::InvalidSignature)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mc_consensus_scp::{
        predicates::FuncPredicate, quorum_set_ext::QuorumSetExt, Msg, QuorumSet,
    };
    use mc_crypto_keys::Ed25519Pair;
    use mc_ledger_db::test_utils::get_mock_ledger;
    use mc_peers::ConsensusValue;
    use mc_peers_test_utils::{create_consensus_msg, test_node_id_and_signer};

    fn message(node_id: NodeID, signer: &Ed25519Pair) -> ConsensusMsg {
        create_consensus_msg(
            &get_mock_ledger(1),
            node_id,
            QuorumSet::empty(),
            1,
            "value",
            signer,
        )
    }

    #[test]
    fn accepts_configured_issuer() {
        let (node, signer) = test_node_id_and_signer(22);
        let verifier = ConsensusMsgVerifier::new([node.clone()]);
        let msg = message(node, &signer);
        assert_eq!(verifier.verify(msg.clone()).unwrap().as_ref(), &msg);
    }

    #[test]
    fn rejects_self_signed_impersonation() {
        let (node, _) = test_node_id_and_signer(22);
        let (attacker, attacker_signer) = test_node_id_and_signer(33);
        let verifier = ConsensusMsgVerifier::new([node.clone()]);
        let forged = message(
            NodeID {
                responder_id: node.responder_id,
                public_key: attacker.public_key,
            },
            &attacker_signer,
        );
        forged.verify_signature().unwrap();
        assert!(matches!(
            verifier.verify(forged),
            Err(ConsensusMsgVerificationError::PublicKeyMismatch(_))
        ));
    }

    #[test]
    fn rejects_key_configured_for_another_responder() {
        let (node_a, _) = test_node_id_and_signer(22);
        let (node_b, signer_b) = test_node_id_and_signer(33);
        let verifier = ConsensusMsgVerifier::new([node_a.clone(), node_b.clone()]);
        let forged = message(
            NodeID {
                responder_id: node_a.responder_id,
                public_key: node_b.public_key,
            },
            &signer_b,
        );
        forged.verify_signature().unwrap();
        assert!(matches!(
            verifier.verify(forged),
            Err(ConsensusMsgVerificationError::PublicKeyMismatch(_))
        ));
    }

    #[test]
    fn accepts_unconfigured_issuer_for_transitive_quorums() {
        let (node, signer) = test_node_id_and_signer(22);
        let verifier = ConsensusMsgVerifier::new([]);
        let msg = message(node, &signer);
        assert_eq!(verifier.verify(msg.clone()).unwrap().as_ref(), &msg);
    }

    #[test]
    fn rejects_invalid_signature_for_configured_issuer() {
        let (node, _) = test_node_id_and_signer(22);
        let (_, wrong_signer) = test_node_id_and_signer(33);
        let verifier = ConsensusMsgVerifier::new([node.clone()]);
        assert!(matches!(
            verifier.verify(message(node, &wrong_signer)),
            Err(ConsensusMsgVerificationError::InvalidSignature(_))
        ));
    }

    #[test]
    fn transitive_quorum_requires_the_referenced_public_key() {
        let (local, _) = test_node_id_and_signer(0);
        let (node_1, signer_1) = test_node_id_and_signer(1);
        let (node_2, signer_2) = test_node_id_and_signer(2);
        let (node_3, _) = test_node_id_and_signer(3);
        let (node_4, signer_4) = test_node_id_and_signer(4);
        let (node_5, signer_5) = test_node_id_and_signer(5);
        let (attacker, attacker_signer) = test_node_id_and_signer(99);
        let local_quorum =
            QuorumSet::new_with_node_ids(2, vec![node_1.clone(), node_2.clone(), node_3.clone()]);
        // Only direct participants are locally configured.
        let verifier = ConsensusMsgVerifier::new([node_1.clone(), node_2.clone(), node_3]);
        let mut msgs: HashMap<NodeID, Msg<ConsensusValue>> = Default::default();
        let node_2_msg = create_consensus_msg(
            &get_mock_ledger(1),
            node_2,
            QuorumSet::new_with_node_ids(1, vec![node_4.clone(), node_5.clone()]),
            1,
            "value",
            &signer_2,
        );
        for msg in [message(node_1, &signer_1), node_2_msg] {
            let verified = verifier.verify(msg).unwrap();
            msgs.insert(
                verified.scp_msg().sender_id.clone(),
                verified.scp_msg().clone(),
            );
        }
        let find_quorum = |msgs: &HashMap<NodeID, Msg<ConsensusValue>>| {
            local_quorum
                .findQuorum(
                    &local,
                    msgs,
                    FuncPredicate {
                        test_fn: &|_: &Msg<ConsensusValue>| true,
                    },
                )
                .0
        };
        assert!(find_quorum(&msgs).is_empty());

        let forged_node_4 = NodeID {
            responder_id: node_4.responder_id.clone(),
            public_key: attacker.public_key,
        };
        let forged = verifier
            .verify(message(forged_node_4.clone(), &attacker_signer))
            .unwrap();
        msgs.insert(forged_node_4.clone(), forged.scp_msg().clone());
        assert!(find_quorum(&msgs).is_empty());

        // Either genuine transitive participant completes node 2's quorum.
        for (node, signer) in [(node_4, signer_4), (node_5, signer_5)] {
            let mut msgs = msgs.clone();
            let verified = verifier.verify(message(node.clone(), &signer)).unwrap();
            msgs.insert(node.clone(), verified.scp_msg().clone());
            let quorum = find_quorum(&msgs);
            assert!(!quorum.is_empty());
            assert!(quorum.contains(&node));
            assert!(!quorum.contains(&forged_node_4));
        }
    }
}
