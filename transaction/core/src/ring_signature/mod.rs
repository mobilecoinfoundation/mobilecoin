// Copyright (c) 2018-2020 MobileCoin Inc.

#![allow(non_snake_case)]
#![macro_use]
extern crate alloc;

use alloc::{vec, vec::Vec};
use bulletproofs::{BulletproofGens, PedersenGens};
use core::convert::TryFrom;
use curve25519_dalek::ristretto::CompressedRistretto;
pub use curve25519_dalek::scalar::Scalar;
pub use curve_point::*;
pub use curve_scalar::*;
pub use error::Error;
pub use key_image::*;
use keys::RistrettoPublic;
pub use mlsag::*;
pub use rct_bulletproofs::*;

use crate::{
    constants::{MAX_INPUTS, MAX_OUTPUTS},
    tx::TxIn,
};

mod curve_point;
mod curve_scalar;
mod error;
mod key_image;
mod mlsag;
mod rct_bulletproofs;

lazy_static! {
    /// Generators (base points) for Pedersen commitments.
    pub static ref GENERATORS: PedersenGens = PedersenGens::default();

    /// Generators (base points) for Bulletproofs.
    pub static ref BP_GENERATORS: BulletproofGens =
        BulletproofGens::new(64, MAX_INPUTS as usize + MAX_OUTPUTS as usize);
}

// The "blinding factor" in a Pedersen commitment.
pub type Blinding = CurveScalar;

/// An output's one-time public address.
pub type Address = RistrettoPublic;
