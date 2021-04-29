// Copyright (c) 2018-2021 The MobileCoin Foundation

//! The message types used by the consensus_enclave_api.

use crate::{LocallyEncryptedTx, ResponderId, SealedBlockSigningKey, WellFormedEncryptedTx};
use alloc::vec::Vec;
use mc_attest_core::{Quote, Report, TargetInfo, VerificationReport};
use mc_attest_enclave_api::{
    ClientAuthRequest, ClientSession, EnclaveMessage, PeerAuthRequest, PeerAuthResponse,
    PeerSession,
};
use mc_transaction_core::{tx::TxOutMembershipProof, Block};
use serde::{Deserialize, Serialize};

/// An enumeration of API calls and their arguments for use across serialization
/// boundaries.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum EnclaveCall {
    /// The [ConsensusEnclave::enclave_init()] method.
    EnclaveInit(
        ResponderId,
        ResponderId,
        Option<SealedBlockSigningKey>,
        Option<u64>,
    ),

    /// The [PeerableEnclave::peer_init()] method.
    ///
    /// Starts an outbound connection.
    PeerInit(ResponderId),

    /// The [PeerableEnclave::peer_accept()] method.
    ///
    /// Process a new inbound peer connection.
    PeerAccept(PeerAuthRequest),

    /// The [PeerableEnclave::peer_connect()] method.
    ///
    /// Completes an outbound connection using the peer's response.
    PeerConnect(ResponderId, PeerAuthResponse),

    /// The [PeerableEnclave::peer_close()] method.
    ///
    /// Tears down any in-enclave state about a peer association.
    PeerClose(PeerSession),

    /// The [ConsensusEnclave::client_accept()] method.
    ///
    /// Process a new inbound client connection.
    ClientAccept(ClientAuthRequest),

    /// The [ConsensusEnclave::client_close()] method.
    ///
    /// Tears down any in-enclave state about a client association.
    ClientClose(ClientSession),

    /// The [ConsensusEnclave::get_identity()] method.
    ///
    /// Retrieves the public identity (X25519 public key) of an enclave.
    GetIdentity,

    /// The [ConsensusEnclave::get_signer()] method.
    ///
    /// Retrieves the block signer (Ed25519 public key) of an enclave.
    GetSigner,

    /// The [ConsensusEnclave::get_fee_recipient()] method.
    ///
    /// Retrieves the fee recipient (FeePublicKey) for the enclave.
    GetFeeRecipient,

    /// The [ConsensusEnclave::new_ereport()] method.
    ///
    /// Creates a new report for the enclave with the provided target info.
    NewEreport(TargetInfo),

    /// The [ConsensusEnclave::verify_quote()] method.
    ///
    /// * Verifies that the Quoting Enclave is sane,
    /// * Verifies that the Quote matches the previously generated report.
    /// * Caches the quote.
    VerifyQuote(Quote, Report),

    /// The [ConsensusEnclave::verify_ias_report()] method.
    ///
    /// * Verifies the signed report from IAS matches the previously received
    ///   quote,
    /// * Caches the signed report. This cached report may be overwritten by
    ///   later calls.
    VerifyReport(VerificationReport),

    /// The [ConsensusEnclave::get_ias_report()] method.
    ///
    /// Retrieves a previously cached report, if any.
    GetReport,

    /// The [ConsensusEnclave::client_tx_propose()] method.
    ///
    /// Start a new transaction proposal given the encrypted message from a
    /// client.
    ClientTxPropose(EnclaveMessage<ClientSession>),

    /// The [ConsensusEnclave::client_discard_message()] method.
    ///
    /// Decrypts an incoming message and discard the data.
    ClientDiscardMessage(EnclaveMessage<ClientSession>),

    /// The [ConsensusEnclave::client_tx_propose()] method.
    ///
    /// Start a new transaction proposal given the encrypted message from a
    /// peer.
    PeerTxPropose(EnclaveMessage<PeerSession>),

    /// The [ConsensusEnclave::tx_is_well_formed()] method.
    ///
    /// Provide the missing proofs required to check if a given sealed
    /// transaction is well-formed.
    TxIsWellFormed(LocallyEncryptedTx, u64, Vec<TxOutMembershipProof>),

    /// The [ConsensusEnclave::txs_for_peer()] method.
    ///
    /// Re-encrypt the given transactions for transmission to a peer.
    TxsForPeer(Vec<WellFormedEncryptedTx>, Vec<u8>, PeerSession),

    /// The [ConsensusEnclave::form_block()] method.
    ///
    /// Converts a list of well-formed, encrypted txs + proofs into a block,
    /// block contents (key images + tx outs) and a signature.
    FormBlock(
        Block,
        Vec<(WellFormedEncryptedTx, Vec<TxOutMembershipProof>)>,
    ),

    /// The [ConsensusEnclave::get_minimum_fee()] method.
    ///
    /// Retrieves the minimum fee, as initialized.
    GetMinimumFee,
}
