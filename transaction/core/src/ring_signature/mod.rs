// Copyright (c) 2018-2021 The MobileCoin Foundation

#![allow(non_snake_case)]
#![macro_use]
extern crate alloc;

use crate::domain_separators::HASH_TO_POINT_DOMAIN_TAG;
use blake2::{Blake2b, Digest};
use bulletproofs::{BulletproofGens, PedersenGens};
pub use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::{constants::RISTRETTO_BASEPOINT_POINT, ristretto::RistrettoPoint};
pub use curve_scalar::*;
pub use error::Error;
pub use key_image::*;
use mc_crypto_keys::RistrettoPublic;
pub use mlsag::*;
pub use rct_bulletproofs::*;

mod curve_scalar;
mod error;
mod key_image;
mod mlsag;
mod rct_bulletproofs;

lazy_static! {
    /// Generators (base points) for Pedersen commitments.
    /// For commitment to amount 'v' with blinding 'b', we want 'C = v*H + b*G' so commitments to zero are signed on G.
    /// Note: our H is not the same point as the dalek library's default version
    pub static ref GENERATORS: PedersenGens = PedersenGens {
            B: hash_to_point(&RistrettoPublic::from(RISTRETTO_BASEPOINT_POINT)),
            B_blinding: RISTRETTO_BASEPOINT_POINT
    };

    /// Generators (base points) for Bulletproofs.
    /// The `party_capacity` is the maximum number of values in one proof. It should
    /// be at least 2 * MAX_INPUTS + MAX_OUTPUTS, which allows for inputs, pseudo outputs, and outputs.
    pub static ref BP_GENERATORS: BulletproofGens =
        BulletproofGens::new(64, 64);
}

/// Applies a hash function and returns a RistrettoPoint.
pub fn hash_to_point(ristretto_public: &RistrettoPublic) -> RistrettoPoint {
    let mut hasher = Blake2b::new();
    hasher.update(&HASH_TO_POINT_DOMAIN_TAG);
    hasher.update(&ristretto_public.to_bytes());
    RistrettoPoint::from_hash(hasher)
}
