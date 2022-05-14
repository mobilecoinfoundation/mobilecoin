use crate::{
    ring_signature::{CryptoRngCore, MLSAGError, ReducedTxOut, RingMLSAG, Scalar},
    Amount,
};
use alloc::{string::String, vec::Vec};
use displaydoc::Display;
use mc_crypto_keys::{KeyError, RistrettoPrivate};
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

/// A representation of the part of the input ring needed to create an MLSAG
#[derive(Clone, Debug)]
pub struct SignableInputRing {
    /// A reduced representation of the TxOut's in the ring. For each ring
    /// member we have only:
    /// * The onetime-address (tx_out.target_key)
    /// * The compressed commitment (tx_out.amount.commitment)
    pub members: Vec<ReducedTxOut>,

    /// The index of the real input among these ring members
    pub real_input_index: usize,

    /// The secrets needed to sign that input
    pub input_secret: InputSecret,
}

/// The secrets needed to create a signature that spends an existing output as
/// an input
#[derive(Clone, Debug, Zeroize)]
#[zeroize(drop)]
pub struct InputSecret {
    /// Represents either the one-time private key, or an alternative route to
    /// this
    pub onetime_key_or_alternative: OneTimeKeyOrAlternative,
    /// The amount of the output
    pub amount: Amount,
    /// The blinding factor of the output we are trying to spend
    pub blinding: Scalar,
}

/// To spend an input, we need to be able to derive the one-time private key.
/// For off-line signing, we can't have this on the online machine. So in that
/// case, we provide only the subaddress index, and the RingSigner (off-line
/// machine) must use the account private keys to derive the one-time private
/// key.
///
/// However, in e.g. the gift code flow, we must include the one-time
/// private key from the gift code sender and we cannot possibly derive it
/// ourselves.
///
/// This enum selects which path to the one-time private key is taken.
#[derive(Clone, Debug, Zeroize)]
#[zeroize(drop)]
pub enum OneTimeKeyOrAlternative {
    /// The one-time private key for the output
    OneTimeKey(RistrettoPrivate),
    /// The subaddress index which owns the output
    SubaddressIndex(u64),
}

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

/// An error that can occur when using an abstract RingSigner
#[derive(Clone, Debug, Deserialize, Display, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub enum Error {
    /// True input not owned by this subaddress
    TrueInputNotOwned,
    /// Connection failed: {0}
    ConnectionFailed(String),
    /// Invalid Ristretto in TxOut: {0}
    Keys(KeyError),
    /// Real input index out of bounds
    RealInputIndexOutOfBounds,
    /// MLSAG: {0}
    MLSAG(MLSAGError),
    /// No path to spend key (logic error)
    NoPathToSpendKey,
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
