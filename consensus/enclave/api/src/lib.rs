// Copyright (c) 2018-2021 The MobileCoin Foundation

//! APIs for MobileCoin Consensus Node Enclaves

#![no_std]

extern crate alloc;

mod error;
mod messages;

pub use crate::{error::Error, messages::EnclaveCall};

use alloc::{string::String, vec::Vec};
use core::{cmp::Ordering, hash::Hash, result::Result as StdResult};
use mc_attest_core::VerificationReport;
use mc_attest_enclave_api::{
    ClientAuthRequest, ClientAuthResponse, ClientSession, EnclaveMessage, PeerAuthRequest,
    PeerAuthResponse, PeerSession,
};
use mc_common::ResponderId;
use mc_crypto_keys::{CompressedRistrettoPublic, Ed25519Public, RistrettoPublic, X25519Public};
use mc_sgx_report_cache_api::ReportableEnclave;
use mc_transaction_core::{
    ring_signature::KeyImage,
    tx::{Tx, TxHash, TxOutMembershipProof},
    Block, BlockContents, BlockSignature,
};
use serde::{Deserialize, Serialize};

/// A generic result type for enclave calls
pub type Result<T> = StdResult<T, Error>;

/// A `mc_transaction_core::Tx` that has been encrypted for the local enclave,
/// to be used during the two-step is-wellformed check.
#[derive(Clone, Debug, Default, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub struct LocallyEncryptedTx(pub Vec<u8>);

/// A `WellFormedTx` encrypted for the current enclave.
#[derive(Clone, Debug, Default, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub struct WellFormedEncryptedTx(pub Vec<u8>);

/// Tx data we wish to expose to untrusted from well-formed Txs.
#[derive(Clone, Debug, Default, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct WellFormedTxContext {
    /// Fee included in the tx.
    fee: u64,

    /// Tx hash.
    tx_hash: TxHash,

    /// Tombstone block.
    tombstone_block: u64,

    /// Key images.
    key_images: Vec<KeyImage>,

    /// Highest membership proofs indices.
    highest_indices: Vec<u64>,

    /// Output public keys.
    output_public_keys: Vec<CompressedRistrettoPublic>,
}

impl WellFormedTxContext {
    /// Create a new WellFormedTxContext.
    pub fn new(
        fee: u64,
        tx_hash: TxHash,
        tombstone_block: u64,
        key_images: Vec<KeyImage>,
        highest_indices: Vec<u64>,
        output_public_keys: Vec<CompressedRistrettoPublic>,
    ) -> Self {
        Self {
            fee,
            tx_hash,
            tombstone_block,
            key_images,
            highest_indices,
            output_public_keys,
        }
    }

    pub fn tx_hash(&self) -> &TxHash {
        &self.tx_hash
    }

    pub fn fee(&self) -> u64 {
        self.fee
    }

    pub fn tombstone_block(&self) -> u64 {
        self.tombstone_block
    }

    pub fn key_images(&self) -> &Vec<KeyImage> {
        &self.key_images
    }

    pub fn highest_indices(&self) -> &Vec<u64> {
        &self.highest_indices
    }

    pub fn output_public_keys(&self) -> &Vec<CompressedRistrettoPublic> {
        &self.output_public_keys
    }
}

impl From<&Tx> for WellFormedTxContext {
    fn from(tx: &Tx) -> Self {
        Self {
            fee: tx.prefix.fee,
            tx_hash: tx.tx_hash(),
            tombstone_block: tx.prefix.tombstone_block,
            key_images: tx.key_images(),
            highest_indices: tx.get_membership_proof_highest_indices(),
            output_public_keys: tx.output_public_keys(),
        }
    }
}

/// Defines a sort order for transactions in a block.
/// Transactions are sorted by fee (high to low), then by transaction hash and
/// any other fields.
impl Ord for WellFormedTxContext {
    fn cmp(&self, other: &Self) -> Ordering {
        if self.fee != other.fee {
            // Sort by fee, descending.
            other.fee.cmp(&self.fee)
        } else {
            // Sort by remaining fields in lexicographic order.
            (
                &self.tx_hash,
                &self.tombstone_block,
                &self.key_images,
                &self.highest_indices,
                &self.output_public_keys,
            )
                .cmp(&(
                    &other.tx_hash,
                    &other.tombstone_block,
                    &other.key_images,
                    &other.highest_indices,
                    &other.output_public_keys,
                ))
        }
    }
}

impl PartialOrd for WellFormedTxContext {
    fn partial_cmp(&self, other: &WellFormedTxContext) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

#[cfg(test)]
mod well_formed_tx_context_tests {
    use crate::WellFormedTxContext;
    use alloc::{vec, vec::Vec};

    #[test]
    /// WellFormedTxContext should be sorted by fee, descending.
    fn test_ordering() {
        let a = WellFormedTxContext::new(100, Default::default(), 0, vec![], vec![], vec![]);
        let b = WellFormedTxContext::new(557, Default::default(), 0, vec![], vec![], vec![]);
        let c = WellFormedTxContext::new(88, Default::default(), 0, vec![], vec![], vec![]);

        let mut contexts = vec![a, b, c];
        contexts.sort();

        let fees: Vec<_> = contexts.iter().map(|context| context.fee).collect();
        let expected = vec![557, 100, 88];
        assert_eq!(fees, expected);
    }
}

/// An intermediate struct for holding data required to perform the two-step
/// is-well-formed test. This is returned by `txs_propose` and allows untrusted
/// to gather data required for the in-enclave well-formedness test that takes
/// place in `tx_is_well_formed`.
#[derive(Clone, Debug, Default, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub struct TxContext {
    pub locally_encrypted_tx: LocallyEncryptedTx,
    pub tx_hash: TxHash,
    pub highest_indices: Vec<u64>,
    pub key_images: Vec<KeyImage>,
    pub output_public_keys: Vec<CompressedRistrettoPublic>,
}

pub type SealedBlockSigningKey = Vec<u8>;

/// PublicAddress is not serializable with serde currently, and rather than
/// pollute dependencies, we simply pass the View and Spend public keys as
/// RistrettoPublic.
#[derive(Clone, Debug, Default, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub struct FeePublicKey {
    pub spend_public_key: RistrettoPublic,
    pub view_public_key: RistrettoPublic,
}

/// The API for interacting with a consensus node's enclave.
pub trait ConsensusEnclave: ReportableEnclave {
    // UTILITY METHODS

    /// Perform one-time initialization upon enclave startup.
    fn enclave_init(
        &self,
        self_peer_id: &ResponderId,
        self_client_id: &ResponderId,
        sealed_key: &Option<SealedBlockSigningKey>,
        minimum_fee: Option<u64>,
    ) -> Result<(SealedBlockSigningKey, Vec<String>)>;

    /// Retrieve the current minimum fee
    fn get_minimum_fee(&self) -> Result<u64>;

    /// Retrieve the public identity of the enclave.
    fn get_identity(&self) -> Result<X25519Public>;

    /// Retrieve the block signing public key from the enclave.
    fn get_signer(&self) -> Result<Ed25519Public>;

    /// Retrieve the fee public key from the enclave
    fn get_fee_recipient(&self) -> Result<FeePublicKey>;

    // CLIENT-FACING METHODS

    /// Accept an inbound authentication request
    fn client_accept(&self, req: ClientAuthRequest) -> Result<(ClientAuthResponse, ClientSession)>;

    /// Destroy a peer association
    fn client_close(&self, channel_id: ClientSession) -> Result<()>;

    /// Decrypts a message from a client and then immediately discard it. This
    /// is useful when we want to skip processing an incoming message, but
    /// still properly maintain our AKE state in sync with the client.
    fn client_discard_message(&self, msg: EnclaveMessage<ClientSession>) -> Result<()>;

    // NODE-FACING METHODS

    /// Start a new outbound connection.
    fn peer_init(&self, peer_id: &ResponderId) -> Result<PeerAuthRequest>;

    /// Accept an inbound authentication request
    fn peer_accept(&self, req: PeerAuthRequest) -> Result<(PeerAuthResponse, PeerSession)>;

    /// Complete the connection
    fn peer_connect(
        &self,
        peer_id: &ResponderId,
        res: PeerAuthResponse,
    ) -> Result<(PeerSession, VerificationReport)>;

    /// Destroy a peer association
    fn peer_close(&self, channel_id: &PeerSession) -> Result<()>;

    // TRANSACTION-HANDLING API

    /// Performs the first steps in accepting transactions from a remote client:
    /// 1) Re-encrypt all txs for the local enclave
    /// 2) Extract context data to be handed back to untrusted so that it could
    /// collect the    information required by `tx_is_well_formed`.
    fn client_tx_propose(&self, msg: EnclaveMessage<ClientSession>) -> Result<TxContext>;

    /// Performs the first steps in accepting transactions from a remote peer:
    /// 1) Re-encrypt all txs for the local enclave
    /// 2) Extract context data to be handed back to untrusted so that it could
    /// collect the    information required by `tx_is_well_formed`.
    /// TODO: rename to txs_propose since this operates on multiple txs?
    fn peer_tx_propose(&self, msg: EnclaveMessage<PeerSession>) -> Result<Vec<TxContext>>;

    /// Checks a LocallyEncryptedTx for well-formedness using the given
    /// membership proofs and current block index.
    fn tx_is_well_formed(
        &self,
        locally_encrypted_tx: LocallyEncryptedTx,
        block_index: u64,
        proofs: Vec<TxOutMembershipProof>,
    ) -> Result<(WellFormedEncryptedTx, WellFormedTxContext)>;

    /// Re-encrypt sealed transactions for the given peer session, using the
    /// given authenticated data for the peer.
    fn txs_for_peer(
        &self,
        encrypted_txs: &[WellFormedEncryptedTx],
        aad: &[u8],
        peer: &PeerSession,
    ) -> Result<EnclaveMessage<PeerSession>>;

    /// Redact txs in order to form a new block.
    /// Returns a block, the block contents, and a signature over the block's
    /// digest.
    fn form_block(
        &self,
        parent_block: &Block,
        txs: &[(WellFormedEncryptedTx, Vec<TxOutMembershipProof>)],
    ) -> Result<(Block, BlockContents, BlockSignature)>;
}

/// Helper trait which reduces boiler-plate in untrusted side
/// The trusted object which implements consensus_enclave usually cannot
/// implement Clone, Send, Sync, etc., but the untrusted side can and usually
/// having a "handle to an enclave" is what is most useful for a webserver.
/// This marker trait can be implemented for the untrusted-side representation
/// of the enclave.
pub trait ConsensusEnclaveProxy: ConsensusEnclave + Clone + Send + Sync + 'static {}
