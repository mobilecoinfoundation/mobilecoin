// Copyright (c) 2018-2022 The MobileCoin Foundation

//! MobileCoin ring signatures

#![allow(non_snake_case)]

pub use curve25519_dalek::{ristretto::RistrettoPoint, scalar::Scalar};

mod curve_scalar;
mod error;
mod generator_cache;
mod key_image;
mod mlsag;

pub use self::{
    curve_scalar::CurveScalar,
    error::Error,
    generator_cache::GeneratorCache,
    key_image::KeyImage,
    mlsag::{CryptoRngCore, ReducedTxOut, RingMLSAG},
};

use crate::domain_separators::HASH_TO_POINT_DOMAIN_TAG;
use curve25519_dalek::{
    constants::{RISTRETTO_BASEPOINT_COMPRESSED, RISTRETTO_BASEPOINT_POINT},
    traits::MultiscalarMul,
};
use mc_crypto_hashes::{Blake2b512, Digest};
use mc_crypto_keys::RistrettoPublic;

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
        RistrettoPoint::multiscalar_mul(&[value, blinding], &[self.B, self.B_blinding])
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
    hasher.update(&HASH_TO_POINT_DOMAIN_TAG);

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
    hasher.update(&HASH_TO_POINT_DOMAIN_TAG);
    hasher.update(&ristretto_public.to_bytes());
    RistrettoPoint::from_hash(hasher)
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
