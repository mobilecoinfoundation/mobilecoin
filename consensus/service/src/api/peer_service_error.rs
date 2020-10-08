use displaydoc::Display;
use mc_transaction_core::tx::TxHash;

/// Errors experienced when handling PeerAPI requests.
#[derive(Debug, Display)]
pub enum PeerServiceError {
    /// Unknown peer `{0}`.
    UnknownPeer(String),

    /// The ConsensusMsg's signature is invalid.
    ConsensusMsgInvalidSignature,

    /// Unknown transactions `{0:?}`.
    UnknownTransactions(Vec<TxHash>),

    /// Enclave-related error `{0}`.
    Enclave(mc_consensus_enclave::Error),

    /// Something went wrong...
    InternalError,
}
