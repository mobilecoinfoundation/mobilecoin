// Copyright (c) 2018-2021 The MobileCoin Foundation

//! Messages used in Consensus by Peers

use displaydoc::Display;
use ed25519::signature::Error as SignatureError;
use mc_common::{NodeID, ResponderId};
use mc_consensus_scp::Msg;
use mc_crypto_digestible::{DigestTranscript, Digestible, MerlinTranscript};
use mc_crypto_keys::{Ed25519Pair, Ed25519Signature, KeyError, Signer, Verifier};
use mc_ledger_db::Ledger;
use mc_transaction_core::{tx::TxHash, BlockID};
use serde::{Deserialize, Serialize};
use std::{convert::TryFrom, result::Result as StdResult};

/// A consensus message holds the data that is exchanged by consensus service
/// nodes as part of the process of reaching agreement on the contents of the
/// next block.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, Digestible)]
pub struct ConsensusMsg {
    /// An SCP message, used to reach agreement on the set of values the next
    /// block will contain.
    pub scp_msg: Msg<TxHash>,

    /// The block ID of the block the message is trying to append values to.
    pub prev_block_id: BlockID,

    /// The signature of the scp_msg.
    pub signature: Ed25519Signature,
}

/// A consensus message that has passed signature validation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct VerifiedConsensusMsg {
    inner: ConsensusMsg,
}

impl VerifiedConsensusMsg {
    pub fn scp_msg(&self) -> &Msg<TxHash> {
        &self.inner.scp_msg
    }

    pub fn prev_block_id(&self) -> &BlockID {
        &self.inner.prev_block_id
    }

    pub fn signature(&self) -> &Ed25519Signature {
        &self.inner.signature
    }
}

impl TryFrom<ConsensusMsg> for VerifiedConsensusMsg {
    type Error = ConsensusMsgError;
    fn try_from(src: ConsensusMsg) -> Result<Self, Self::Error> {
        src.verify_signature()?;

        Ok(Self { inner: src })
    }
}

impl AsRef<ConsensusMsg> for VerifiedConsensusMsg {
    fn as_ref(&self) -> &ConsensusMsg {
        &self.inner
    }
}

/// The AAD included in a tx_propose call to a remote peer.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct TxProposeAAD {
    /// Node ID the transaction was originally submitted to (by a client).
    pub origin_node: NodeID,

    /// Node ID that relayed the transaction.
    pub relayed_by: ResponderId,
}

#[derive(Debug, Display)]
pub enum ConsensusMsgError {
    /// ZeroSlot
    ZeroSlot,

    /// Ledger db error: {0}
    LedgerDbError(mc_ledger_db::Error),

    /// Serialization
    Serialization,

    /// Key error: {0}
    KeyError(KeyError),

    /// Signature error: {0}
    SignatureError(SignatureError),
}

impl From<mc_ledger_db::Error> for ConsensusMsgError {
    fn from(src: mc_ledger_db::Error) -> Self {
        ConsensusMsgError::LedgerDbError(src)
    }
}

impl From<mc_util_serial::encode::Error> for ConsensusMsgError {
    fn from(_src: mc_util_serial::encode::Error) -> Self {
        ConsensusMsgError::Serialization
    }
}

impl From<KeyError> for ConsensusMsgError {
    fn from(src: KeyError) -> Self {
        ConsensusMsgError::KeyError(src)
    }
}

impl From<SignatureError> for ConsensusMsgError {
    fn from(src: SignatureError) -> Self {
        ConsensusMsgError::SignatureError(src)
    }
}

impl ConsensusMsg {
    pub fn from_scp_msg(
        ledger: &impl Ledger,
        scp_msg: Msg<TxHash>,
        signer_key: &Ed25519Pair,
    ) -> StdResult<Self, ConsensusMsgError> {
        if scp_msg.slot_index == 0 {
            return Err(ConsensusMsgError::ZeroSlot);
        }

        let prev_block = ledger.get_block(scp_msg.slot_index - 1)?;

        let mut contents_hash = [0u8; 32];
        {
            let mut transcript = MerlinTranscript::new(b"peer-message");
            scp_msg.append_to_transcript(b"scp_msg", &mut transcript);
            prev_block
                .id
                .append_to_transcript(b"prev_block_id", &mut transcript);
            transcript.extract_digest(&mut contents_hash);
        }

        let signature = signer_key.try_sign(&contents_hash)?;

        Ok(Self {
            scp_msg,
            prev_block_id: prev_block.id,
            signature,
        })
    }

    /// Get the node id that had issued this message.
    pub fn issuer_node_id(&self) -> &NodeID {
        &self.scp_msg.sender_id
    }

    /// Get the responder id for the node that issued this message.
    pub fn issuer_responder_id(&self) -> &ResponderId {
        &self.scp_msg.sender_id.responder_id
    }

    pub fn verify_signature(&self) -> StdResult<(), ConsensusMsgError> {
        let mut contents_hash = [0u8; 32];
        {
            let mut transcript = MerlinTranscript::new(b"peer-message");
            self.scp_msg
                .append_to_transcript(b"scp_msg", &mut transcript);
            self.prev_block_id
                .append_to_transcript(b"prev_block_id", &mut transcript);
            transcript.extract_digest(&mut contents_hash);
        }

        Ok(self
            .scp_msg
            .sender_id
            .public_key
            .verify(&contents_hash, &self.signature)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mc_consensus_scp::{core_types::Ballot, msg::*, QuorumSet, SlotIndex};
    use mc_ledger_db::test_utils::get_mock_ledger;
    use mc_peers_test_utils::test_node_id_and_signer;
    use std::convert::TryFrom;

    // Create a minimal ConsensusMsg for testing
    fn create_msg_node_a() -> ConsensusMsg {
        let (local_node_id, local_signer_key) = test_node_id_and_signer(22);
        let local_quorum_set = QuorumSet::empty();

        let hash_tx = TxHash::default();

        let num_blocks = 10;
        let ledger = get_mock_ledger(num_blocks);

        let msg = ConsensusMsg::from_scp_msg(
            &ledger,
            Msg::new(
                local_node_id,
                local_quorum_set,
                num_blocks as u64,
                Topic::Commit(CommitPayload {
                    B: Ballot::new(100, &[hash_tx]),
                    PN: 77,
                    CN: 55,
                    HN: 66,
                }),
            ),
            &local_signer_key,
        )
        .unwrap();
        msg
    }

    // Correctly-constructed signature should verify.
    #[test]
    fn test_correct_scp_message_signature() {
        let msg = create_msg_node_a();
        assert!(msg.verify_signature().is_ok())
    }

    // Signature verification should fail if message contents changed.
    #[test]
    fn test_signature_fails_if_contents_changed() {
        let mut msg = create_msg_node_a();
        msg.scp_msg.slot_index = 4;
        match msg.verify_signature() {
            Ok(_) => panic!("Signature verification should fail"),
            Err(ConsensusMsgError::SignatureError(_)) => {}
            Err(e) => panic!("Sigature failed with unexpected error {:?}", e),
        }
    }

    // ConsensusMsg should serialize and deserialize corrctly
    #[test]
    fn test_serialization() {
        let msg = create_msg_node_a();

        let ser = mc_util_serial::serialize(&msg.scp_msg.sender_id).unwrap();
        let m: NodeID = mc_util_serial::deserialize(&ser).unwrap();
        assert_eq!(msg.scp_msg.sender_id, m);

        let ser = mc_util_serial::serialize(&msg.scp_msg.slot_index).unwrap();
        let m: SlotIndex = mc_util_serial::deserialize(&ser).unwrap();
        assert_eq!(msg.scp_msg.slot_index, m);

        let ser = mc_util_serial::serialize(&msg.scp_msg.quorum_set).unwrap();
        let m: QuorumSet = mc_util_serial::deserialize(&ser).unwrap();
        assert_eq!(msg.scp_msg.quorum_set, m);

        let ser = mc_util_serial::serialize(&msg.scp_msg.topic).unwrap();
        let m: Topic<TxHash> = mc_util_serial::deserialize(&ser).unwrap();
        assert_eq!(msg.scp_msg.topic, m);

        let ser = mc_util_serial::serialize(&msg.scp_msg).unwrap();
        let m: Msg<TxHash> = mc_util_serial::deserialize(&ser).unwrap();
        assert_eq!(msg.scp_msg, m);

        let ser = mc_util_serial::serialize(&msg.prev_block_id).unwrap();
        let b: BlockID = mc_util_serial::deserialize(&ser).unwrap();
        assert_eq!(msg.prev_block_id, b);

        let ser = mc_util_serial::serialize(&msg.signature).unwrap();
        let s: Ed25519Signature = mc_util_serial::deserialize(&ser).unwrap();
        assert_eq!(msg.signature, s);

        let serialized = mc_util_serial::serialize(&msg).unwrap();
        let m: ConsensusMsg = mc_util_serial::deserialize(&serialized).unwrap();
        assert_eq!(msg, m);
    }

    // VerifiedConsensusMsg cannot be created with invalid data.
    #[test]
    fn test_verified_consensus_msg_fails_if_contents_changed() {
        let mut msg = create_msg_node_a();
        msg.scp_msg.slot_index = 4;
        match VerifiedConsensusMsg::try_from(msg) {
            Ok(_) => panic!("Signature verification should fail"),
            Err(ConsensusMsgError::SignatureError(_)) => {}
            Err(e) => panic!("Sigature failed with unexpected error {:?}", e),
        }
    }
}
