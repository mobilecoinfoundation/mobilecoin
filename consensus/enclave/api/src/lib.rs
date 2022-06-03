// Copyright (c) 2018-2022 The MobileCoin Foundation

//! APIs for MobileCoin Consensus Node Enclaves

#![no_std]
#![deny(missing_docs)]

extern crate alloc;

mod config;
mod error;
mod fee_map;
mod governors_map;
mod governors_sig;
mod messages;

pub use crate::{
    config::{BlockchainConfig, BlockchainConfigWithDigest},
    error::Error,
    fee_map::{Error as FeeMapError, FeeMap, SMALLEST_MINIMUM_FEE_LOG2},
    governors_map::{Error as GovernorsMapError, GovernorsMap},
    governors_sig::{
        context as governors_signing_context, Signer as GovernorsSigner,
        Verifier as GovernorsVerifier,
    },
    messages::EnclaveCall,
};

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
    mint::{MintConfig, MintConfigTx, MintTx},
    ring_signature::KeyImage,
    tx::{Tx, TxHash, TxOutMembershipElement, TxOutMembershipProof},
    Block, BlockContents, BlockSignature, TokenId,
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
    /// Priority assigned to this tx, based on the fee.
    priority: u64,

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
        priority: u64,
        tx_hash: TxHash,
        tombstone_block: u64,
        key_images: Vec<KeyImage>,
        highest_indices: Vec<u64>,
        output_public_keys: Vec<CompressedRistrettoPublic>,
    ) -> Self {
        Self {
            priority,
            tx_hash,
            tombstone_block,
            key_images,
            highest_indices,
            output_public_keys,
        }
    }

    /// Create a new WellFormedTxContext, from a Tx and its priority.
    pub fn from_tx(tx: &Tx, priority: u64) -> Self {
        Self {
            priority,
            tx_hash: tx.tx_hash(),
            tombstone_block: tx.prefix.tombstone_block,
            key_images: tx.key_images(),
            highest_indices: tx.get_membership_proof_highest_indices(),
            output_public_keys: tx.output_public_keys(),
        }
    }

    /// Get the tx_hash
    pub fn tx_hash(&self) -> &TxHash {
        &self.tx_hash
    }

    /// Get the priority
    pub fn priority(&self) -> u64 {
        self.priority
    }

    /// Get the tombstone block
    pub fn tombstone_block(&self) -> u64 {
        self.tombstone_block
    }

    /// Get the key images
    pub fn key_images(&self) -> &Vec<KeyImage> {
        &self.key_images
    }

    /// Get the highest indices
    pub fn highest_indices(&self) -> &Vec<u64> {
        &self.highest_indices
    }

    /// Get the output public keys
    pub fn output_public_keys(&self) -> &Vec<CompressedRistrettoPublic> {
        &self.output_public_keys
    }
}

/// Defines a sort order for transactions in a block.
/// Transactions are sorted by priority(high to low), then by transaction hash
/// and any other fields.
///
/// Priority is a proxy for fee which is normalized across token ids.
impl Ord for WellFormedTxContext {
    fn cmp(&self, other: &Self) -> Ordering {
        if self.priority != other.priority {
            // Sort by priority, descending.
            other.priority.cmp(&self.priority)
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
    /// WellFormedTxContext should be sorted by priority, descending.
    fn test_ordering() {
        let a = WellFormedTxContext::new(100, Default::default(), 0, vec![], vec![], vec![]);
        let b = WellFormedTxContext::new(557, Default::default(), 0, vec![], vec![], vec![]);
        let c = WellFormedTxContext::new(88, Default::default(), 0, vec![], vec![], vec![]);

        let mut contexts = vec![a, b, c];
        contexts.sort();

        let priorities: Vec<_> = contexts.iter().map(|context| context.priority).collect();
        let expected = vec![557, 100, 88];
        assert_eq!(priorities, expected);
    }
}

/// An intermediate struct for holding data required to perform the two-step
/// is-well-formed test. This is returned by `txs_propose` and allows untrusted
/// to gather data required for the in-enclave well-formedness test that takes
/// place in `tx_is_well_formed`.
#[derive(Clone, Debug, Default, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub struct TxContext {
    /// The Tx encrypted for the local enclave
    pub locally_encrypted_tx: LocallyEncryptedTx,
    /// The hash of the (unencrypted) Tx
    pub tx_hash: TxHash,
    /// The highest indices in the Tx merkle proof
    pub highest_indices: Vec<u64>,
    /// The key images appearing in the Tx
    pub key_images: Vec<KeyImage>,
    /// The output public keys appearing in the Tx
    pub output_public_keys: Vec<CompressedRistrettoPublic>,
}

/// A type alias for the SGX sealed version of the block signing key of the
/// local enclave
pub type SealedBlockSigningKey = Vec<u8>;

/// PublicAddress is not serializable with serde currently, and rather than
/// pollute dependencies, we simply pass the View and Spend public keys as
/// RistrettoPublic.
#[derive(Clone, Debug, Default, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub struct FeePublicKey {
    /// The spend public key of the fee address
    pub spend_public_key: RistrettoPublic,
    /// The view public key of the fee address
    pub view_public_key: RistrettoPublic,
}

/// The collection of transaction types we form blocks from.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct FormBlockInputs {
    /// The original transactions (the ones that are used to move tokens)
    pub well_formed_encrypted_txs_with_proofs:
        Vec<(WellFormedEncryptedTx, Vec<TxOutMembershipProof>)>,

    /// Updating minting configuration transactions
    pub mint_config_txs: Vec<MintConfigTx>,

    /// Minting transactions coupled with configuration information.
    pub mint_txs_with_config: Vec<(MintTx, MintConfigTx, MintConfig)>,
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
        blockchain_config: BlockchainConfig,
    ) -> Result<(SealedBlockSigningKey, Vec<String>)>;

    /// Retrieve the current minimum fee for a given token id.
    /// Returns None if the token ID is not configured to have a minimum fee.
    fn get_minimum_fee(&self, token_id: &TokenId) -> Result<Option<u64>>;

    /// Retrieve the public identity of the enclave.
    fn get_identity(&self) -> Result<X25519Public>;

    /// Retrieve the block signing public key from the enclave.
    fn get_signer(&self) -> Result<Ed25519Public>;

    /// Retrieve the fee public key from the enclave.
    fn get_fee_recipient(&self) -> Result<FeePublicKey>;

    /// Retrieve the minting trust root public key from the enclave.
    fn get_minting_trust_root(&self) -> Result<Ed25519Public>;

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
        inputs: FormBlockInputs,
        root_element: &TxOutMembershipElement,
    ) -> Result<(Block, BlockContents, BlockSignature)>;
}

/// Helper trait which reduces boiler-plate in untrusted side
/// The trusted object which implements consensus_enclave usually cannot
/// implement Clone, Send, Sync, etc., but the untrusted side can and usually
/// having a "handle to an enclave" is what is most useful for a webserver.
/// This marker trait can be implemented for the untrusted-side representation
/// of the enclave.
pub trait ConsensusEnclaveProxy: ConsensusEnclave + Clone + Send + Sync + 'static {}
