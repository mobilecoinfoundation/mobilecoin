// Copyright (c) 2018-2022 The MobileCoin Foundation

//! MobileCoin ring signatures

#![allow(non_snake_case)]

pub use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::{
    constants::{RISTRETTO_BASEPOINT_COMPRESSED, RISTRETTO_BASEPOINT_POINT},
    ristretto::RistrettoPoint,
};

#[cfg(feature = "alloc")]
use curve25519_dalek::traits::MultiscalarMul;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

mod curve_scalar;
mod error;
mod key_image;
mod mlsag_sign;
mod mlsag_verify;

#[cfg(feature = "alloc")]
mod mlsag;

#[cfg(feature = "alloc")]
pub use self::mlsag::RingMLSAG;

pub use self::{curve_scalar::CurveScalar, error::Error, key_image::KeyImage};

use crate::{
    domain_separators::{HASH_TO_POINT_DOMAIN_TAG, RING_MLSAG_CHALLENGE_DOMAIN_TAG},
    Commitment, CompressedCommitment,
};

#[cfg(feature = "internals")]
pub use self::{
    mlsag_sign::{MlsagSignCtx, MlsagSignParams},
    mlsag_verify::MlsagVerify,
};

use mc_crypto_hashes::{Blake2b512, Digest};
use mc_crypto_keys::{CompressedRistrettoPublic, RistrettoPublic};

/// The base point for blinding factors used with all amount commitments
pub const B_BLINDING: RistrettoPoint = RISTRETTO_BASEPOINT_POINT;

/// This is a structure which contains a pair of orthogonal generators for
/// Pedersen commitments.
/// This tracks `bulletproofs::PedersenGens`, but we do not import it, to avoid
/// creating a dependency on the `bulletproofs` crate.
#[derive(Clone, Copy, Debug)]
pub struct PedersenGens {
    /// Base point corresponding to the value of a Pedersen commitment
    pub B: RistrettoPoint,
    /// Base point corresponding to the blinding factor of a Pedersen commitment
    pub B_blinding: RistrettoPoint,
}

impl PedersenGens {
    /// Creates a Pedersen commitment using the value scalar and a blinding
    /// factor.
    pub fn commit(&self, value: Scalar, blinding: Scalar) -> RistrettoPoint {
        // Use optimised Straus' method if alloc is available
        #[cfg(feature = "alloc")]
        return RistrettoPoint::multiscalar_mul(&[value, blinding], &[self.B, self.B_blinding]);

        // Otherwise fallback to naive method
        #[cfg(not(feature = "alloc"))]
        return value * self.B + blinding * self.B_blinding;
    }
}

/// Generators (base points) for Pedersen commitments to amounts.
///
/// For commitment to amount 'v' with blinding 'b', we want 'C = v*H + b*G'
/// so commitments to zero are signed on G, where G is the ristretto basepoint.
///
/// Note: our H is not the same point as the dalek library's default version
///
/// For amounts, H varies based on the token id.
pub fn generators(token_id: u64) -> PedersenGens {
    let mut hasher = Blake2b512::new();
    hasher.update(HASH_TO_POINT_DOMAIN_TAG);

    // This step xors the token id bytes on top of the "base point" bytes
    // used prior to the introduction of token ids.
    //
    // This ensures:
    // * The function is constant-time with respect to token id
    // * The behavior for id 0 is the same as before
    // * For different id values, the set of B points are orthogonal.
    {
        let id_bytes = token_id.to_le_bytes();
        let mut buf: [u8; 32] = RISTRETTO_BASEPOINT_COMPRESSED.to_bytes();
        buf[0] ^= id_bytes[0];
        buf[1] ^= id_bytes[1];
        buf[2] ^= id_bytes[2];
        buf[3] ^= id_bytes[3];
        buf[4] ^= id_bytes[4];
        buf[5] ^= id_bytes[5];
        buf[6] ^= id_bytes[6];
        buf[7] ^= id_bytes[7];
        hasher.update(buf);
    }

    PedersenGens {
        B: RistrettoPoint::from_hash(hasher),
        B_blinding: B_BLINDING,
    }
}

/// Applies a hash function and returns a RistrettoPoint.
pub fn hash_to_point(ristretto_public: &RistrettoPublic) -> RistrettoPoint {
    let mut hasher = Blake2b512::new();
    hasher.update(HASH_TO_POINT_DOMAIN_TAG);
    hasher.update(ristretto_public.to_bytes());
    RistrettoPoint::from_hash(hasher)
}

// Compute the ring "challenge" H( message | key_image | L0 | R0 | L1 ).
pub(crate) fn challenge(
    message: &[u8],
    key_image: &KeyImage,
    L0: &RistrettoPoint,
    R0: &RistrettoPoint,
    L1: &RistrettoPoint,
) -> Scalar {
    let mut hasher = Blake2b512::new();
    hasher.update(&RING_MLSAG_CHALLENGE_DOMAIN_TAG);
    hasher.update(message);
    hasher.update(key_image);
    hasher.update(L0.compress().as_bytes());
    hasher.update(R0.compress().as_bytes());
    hasher.update(L1.compress().as_bytes());
    Scalar::from_hash(hasher)
}

/// A reduced representation of a TxOut, appropriate for making MLSAG
#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct ReducedTxOut {
    /// The tx_out.public_key field
    pub public_key: CompressedRistrettoPublic,
    /// The tx_out.target_key field
    pub target_key: CompressedRistrettoPublic,
    /// The tx_out.masked_amount.commitment field
    pub commitment: CompressedCommitment,
}

/// Expand a [`ReducedTxOut`] to `(RistrettoPublic, Commitment)` for MLSAG use
impl TryFrom<&ReducedTxOut> for (RistrettoPublic, Commitment) {
    type Error = Error;

    fn try_from(r: &ReducedTxOut) -> Result<(RistrettoPublic, Commitment), Self::Error> {
        let ristretto_public =
            RistrettoPublic::try_from(&r.target_key).map_err(|_e| Error::InvalidCurvePoint)?;
        let commitment = Commitment::try_from(&r.commitment)?;

        Ok((ristretto_public, commitment))
    }
}

/// [`Ring`] trait allows implementations to be generic over rings for
/// performance (pre-decompressed) or space (decompress-on-access)
pub trait Ring {
    /// Return size of ring
    ///
    /// (a-la `slice::len`, except we don't have a trait for this)
    fn size(&self) -> usize;

    /// Access a decompressed ring element by index
    ///
    /// (a-la `core::ops::Index`, defined here to avoid orphan rules)
    fn index(&self, index: usize) -> Result<(RistrettoPublic, Commitment), Error>;

    /// Ensure ring decompresses (no-op for pre-decompressed rings)
    fn check(&self) -> Result<(), Error>;
}

/// [`Ring`] implementation for pre-decompressed slices
impl Ring for &[(RistrettoPublic, Commitment)] {
    /// Fetch ring size
    fn size(&self) -> usize {
        self.as_ref().len()
    }

    /// Access a pre-decompressed ring element by index
    fn index(&self, index: usize) -> Result<(RistrettoPublic, Commitment), Error> {
        match self.as_ref().get(index) {
            Some(v) => Ok(*v),
            None => Err(Error::IndexOutOfBounds),
        }
    }

    /// Pre-decompressed ring always decompresses...
    fn check(&self) -> Result<(), Error> {
        Ok(())
    }
}

/// [`Ring`] implementation for reduced slices
impl Ring for &[ReducedTxOut] {
    /// Fetch ring size
    fn size(&self) -> usize {
        self.as_ref().len()
    }

    /// Decompress and access a ring element by index
    fn index(&self, index: usize) -> Result<(RistrettoPublic, Commitment), Error> {
        let tx_out = match self.as_ref().get(index) {
            Some(v) => v,
            None => return Err(Error::IndexOutOfBounds),
        };

        let decompressed: (RistrettoPublic, Commitment) = tx_out.try_into()?;

        Ok(decompressed)
    }

    /// Decompress each entry to check ring
    fn check(&self) -> Result<(), Error> {
        // Ring must decompress.
        for i in 0..self.size() {
            let _tx_out = self.index(i)?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_generator0() {
        assert_eq!(
            generators(0).B,
            hash_to_point(&RistrettoPublic::from(RISTRETTO_BASEPOINT_POINT))
        )
    }
}
