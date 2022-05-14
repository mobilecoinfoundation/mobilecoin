use crate::ring_signature::{CryptoRngCore, MLSAGError, RingMLSAG, Scalar, SignableInputRing};
use alloc::string::String;
use displaydoc::Display;
use mc_crypto_keys::KeyError;
use serde::{Deserialize, Serialize};

/// An abstraction over a set of private spend keys. This is intended to
/// represent either "local" keys or keys living on a remote device.
///
/// A transaction builder can be built around this.
pub trait RingSigner {
    /// Create an MLSAG signature. This is a signature that confers spending
    /// authority of a TxOut.
    ///
    /// Arguments:
    /// * message: The digest of transaction context to sign
    /// * signable_ring: The ring which we are signing, as well as amounts and
    ///   blinding factor of true input
    /// * output_blinding: The desired blinding factor of the resulting
    ///   pseudo-output.
    /// * rng: This is needed to create randomness during signing. For the case
    ///   of a remote device, it should ignore this parameter, and on the other
    ///   side of bridge supply its own rng.
    ///
    /// Returns:
    /// * A signed RingMLSAG, or an error. RingMLSAG signing itself is
    ///   infallible but the error can occur if there is a logic error
    ///   (input_secret did not have a onetime private key, but this tx signer
    ///   has no way to derive it) or a connection error e.g. to hardware device
    //
    // FIXME: Should there be versioning here, in case we want to make changes to
    // MLSAG scheme independently of the block version number? The main point of
    // that would be that we could make breaking changes in a higher level of Tx
    // without impacting hardware wallets, while still having a version number
    // that hardware wallets could observe and respect if we do actually have to
    // make changes to the MLSAG part. FIXME: Message argument should probably
    // be a &[u8; 32] after block version < 2 has been deprecated
    fn sign(
        &self,
        message: &[u8],
        signable_ring: &SignableInputRing,
        output_blinding: Scalar,
        rng: &mut dyn CryptoRngCore,
    ) -> Result<RingMLSAG, Error>;
}

/// An error that can occur when using an abstract TxSigner
#[derive(Clone, Debug, Deserialize, Display, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub enum Error {
    /// True input not owned by this key
    TrueInputNotOwned,
    /// Connection failed: {0}
    ConnectionFailed(String),
    /// Invalid Ristretto in TxOut: {0}
    Keys(KeyError),
    /// Real input index out of bounds
    RealInputIndexOutOfBounds,
    /// MLSAG: {0}
    MLSAG(MLSAGError),
}

impl From<KeyError> for Error {
    fn from(src: KeyError) -> Self {
        Self::Keys(src)
    }
}

impl From<MLSAGError> for Error {
    fn from(src: MLSAGError) -> Self {
        Self::MLSAG(src)
    }
}
