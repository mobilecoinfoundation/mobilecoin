// Copyright (c) 2018-2020 MobileCoin Inc.

#![allow(non_snake_case)]
#![macro_use]
extern crate alloc;

use bulletproofs::{BulletproofGens, PedersenGens};
pub use curve25519_dalek::scalar::Scalar;
pub use curve_scalar::*;
pub use error::Error;
pub use key_image::*;
pub use mlsag::*;
pub use rct_bulletproofs::*;

mod curve_scalar;
mod error;
mod key_image;
mod mlsag;
mod rct_bulletproofs;

lazy_static! {
    /// Generators (base points) for Pedersen commitments.
    pub static ref GENERATORS: PedersenGens = PedersenGens::default();

    /// Generators (base points) for Bulletproofs.
    /// The `party_capacity` is the maximum number of values in one proof. It should
    /// be at least 2 * MAX_INPUTS + MAX_OUTPUTS, which allows for inputs, pseudo outputs, and outputs.
    pub static ref BP_GENERATORS: BulletproofGens =
        BulletproofGens::new(64, 64);
}
