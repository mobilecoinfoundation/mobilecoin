use alloc::string::String;
use displaydoc::Display;
use mc_crypto_keys::KeyError;
use mc_crypto_ring_signature::{Error as RingSignatureError};
use serde::{Deserialize, Serialize};

/// An error that can occur when using an abstract account keys object
#[derive(Clone, Debug, Deserialize, Display, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub enum Error {
    /// True input not owned by this subaddress
    TrueInputNotOwned,
    /// Connection failed: {0}
    ConnectionFailed(String),
    /// Invalid Ristretto key in TxOut: {0}
    Keys(KeyError),
    /// Real input index out of bounds
    RealInputIndexOutOfBounds,
    /// Ring Signature: {0}
    RingSignature(RingSignatureError),
    /// No path to spend key (logic error)
    NoPathToSpendKey,
}

impl From<KeyError> for Error {
    fn from(src: KeyError) -> Self {
        Self::Keys(src)
    }
}

impl From<RingSignatureError> for Error {
    fn from(src: RingSignatureError) -> Self {
        Self::RingSignature(src)
    }
}
