// Copyright (c) 2018-2022 The MobileCoin Foundation

//! MobileCoin ring signatures

#![allow(non_snake_case)]

pub use bulletproofs_og::{BulletproofGens, PedersenGens};
pub use curve25519_dalek::{ristretto::RistrettoPoint, scalar::Scalar};

use crate::domain_separators::HASH_TO_POINT_DOMAIN_TAG;
use curve25519_dalek::constants::{RISTRETTO_BASEPOINT_COMPRESSED, RISTRETTO_BASEPOINT_POINT};
use mc_crypto_hashes::{Blake2b512, Digest};
use mc_crypto_keys::RistrettoPublic;

mod curve_scalar;
mod error;
mod generator_cache;
mod key_image;
mod mlsag;
mod rct_bulletproofs;

pub use curve_scalar::*;
pub use error::Error;
pub use generator_cache::*;
pub use key_image::*;
pub use mlsag::*;
pub use rct_bulletproofs::*;

/// The base point for blinding factors used with all amount commitments
pub const B_BLINDING: RistrettoPoint = RISTRETTO_BASEPOINT_POINT;

lazy_static! {
    /// Generators (base points) for Bulletproofs.
    /// The `party_capacity` is the maximum number of values in one proof. It should
    /// be at least 2 * MAX_INPUTS + MAX_OUTPUTS, which allows for inputs, pseudo outputs, and outputs.
    pub static ref BP_GENERATORS: BulletproofGens =
        BulletproofGens::new(64, 64);
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
