use failure::Fail;

/// Errors experienced when handling PeerAPI requests.
#[derive(Debug, Fail)]
pub enum PeerServiceError {
    /// Invalid argument.
    #[fail(display = "Invalid argument: {}", _0)]
    InvalidArgument(String),

    /// Unknown peer.
    #[fail(display = "Unknown peer: {}", _0)]
    UnknownPeer(String),

    /// The ConsensusMsg's signature is invalid.
    #[fail(display = "ConsensusMsgInvalidSignature")]
    ConsensusMsgInvalidSignature,

    /// Something went wrong...
    #[fail(display = "Internal error")]
    InternalError,
}
