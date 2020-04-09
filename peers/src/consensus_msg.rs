// Copyright (c) 2018-2020 MobileCoin Inc.

//! Messages used in Consensus by Peers

use common::{NodeID, ResponderId};
use ed25519::signature::Error as SignatureError;
use failure::Fail;
use keys::{Ed25519Pair, Ed25519Signature, KeyError, Signer, Verifier};
use ledger_db::Ledger;
use scp::Msg;
use serde::{Deserialize, Serialize};
use sha2::{digest::Digest, Sha256};
use std::{convert::TryFrom, result::Result as StdResult};
use transaction::{tx::TxHash, BlockID};

/// A consensus message holds the data that is exchanged by consensus service nodes as part of the
/// process of reaching agreement on the contents of the next block.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ConsensusMsg {
    /// An SCP message, used to reach agreement on the set of values the next block will contain.
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

#[derive(Debug, Fail)]
pub enum ConsensusMsgError {
    #[fail(display = "ZeroSlot")]
    ZeroSlot,

    #[fail(display = "Ledger db error: {}", _0)]
    LedgerDbError(ledger_db::Error),

    #[fail(display = "Serialization")]
    Serialization,

    #[fail(display = "Key error: {}", _0)]
    KeyError(KeyError),

    #[fail(display = "Signature error: {}", _0)]
    SignatureError(SignatureError),
}

impl From<ledger_db::Error> for ConsensusMsgError {
    fn from(src: ledger_db::Error) -> Self {
        ConsensusMsgError::LedgerDbError(src)
    }
}

impl From<mcserial::encode::Error> for ConsensusMsgError {
    fn from(_src: mcserial::encode::Error) -> Self {
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

        let contents_hash = Sha256::digest(
            &[
                mcserial::serialize(&scp_msg)?,
                mcserial::serialize(&prev_block.id)?,
            ]
            .concat(),
        );

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
        let contents_hash = Sha256::digest(
            &[
                mcserial::serialize(&self.scp_msg)?,
                mcserial::serialize(&self.prev_block_id)?,
            ]
            .concat(),
        );
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
    use ledger_db::test_utils::get_mock_ledger;
    use peers_tests::test_node_id_and_signer;
    use scp::{core_types::Ballot, msg::*, QuorumSet, SlotIndex};
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

        let ser = mcserial::serialize(&msg.scp_msg.sender_id).unwrap();
        let m: NodeID = mcserial::deserialize(&ser).unwrap();
        assert_eq!(msg.scp_msg.sender_id, m);

        let ser = mcserial::serialize(&msg.scp_msg.slot_index).unwrap();
        let m: SlotIndex = mcserial::deserialize(&ser).unwrap();
        assert_eq!(msg.scp_msg.slot_index, m);

        let ser = mcserial::serialize(&msg.scp_msg.quorum_set).unwrap();
        let m: QuorumSet = mcserial::deserialize(&ser).unwrap();
        assert_eq!(msg.scp_msg.quorum_set, m);

        let ser = mcserial::serialize(&msg.scp_msg.topic).unwrap();
        let m: Topic<TxHash> = mcserial::deserialize(&ser).unwrap();
        assert_eq!(msg.scp_msg.topic, m);

        let ser = mcserial::serialize(&msg.scp_msg).unwrap();
        let m: Msg<TxHash> = mcserial::deserialize(&ser).unwrap();
        assert_eq!(msg.scp_msg, m);

        let ser = mcserial::serialize(&msg.prev_block_id).unwrap();
        let b: BlockID = mcserial::deserialize(&ser).unwrap();
        assert_eq!(msg.prev_block_id, b);

        let ser = mcserial::serialize(&msg.signature).unwrap();
        let s: Ed25519Signature = mcserial::deserialize(&ser).unwrap();
        assert_eq!(msg.signature, s);

        let serialized = mcserial::serialize(&msg).unwrap();
        let m: ConsensusMsg = mcserial::deserialize(&serialized).unwrap();
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
