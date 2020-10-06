use failure::Fail;
use mc_transaction_core::tx::TxHash;

/// Errors experienced when handling PeerAPI requests.
#[derive(Debug, Fail)]
pub enum PeerServiceError {
    /// Unknown peer.
    #[fail(display = "Unknown peer: {}", _0)]
    UnknownPeer(String),

    /// The ConsensusMsg's signature is invalid.
    #[fail(display = "ConsensusMsgInvalidSignature")]
    ConsensusMsgInvalidSignature,

    /// Unknown transactions
    #[fail(display = "Unknown transactions")]
    UnknownTransactions(Vec<TxHash>),

    /// Enclave-related error.
    #[fail(display = "Enclave error: {}", _0)]
    Enclave(mc_consensus_enclave::Error),

    /// Something went wrong...
    #[fail(display = "Internal error")]
    InternalError,
}
