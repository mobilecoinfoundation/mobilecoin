// Copyright (c) 2018-2020 MobileCoin Inc.

#![allow(non_snake_case)]
#![macro_use]
extern crate alloc;

use crate::constants::{MAX_INPUTS, MAX_OUTPUTS};
use bulletproofs::{BulletproofGens, PedersenGens};
use curve25519_dalek::ristretto::CompressedRistretto;
pub use curve25519_dalek::scalar::Scalar;
use keys::RistrettoPublic;

mod curve_point;
mod curve_scalar;
mod error;
mod key_image;
mod mlsag;
mod rct_bulletproofs;
mod rct_type_full;

use crate::tx::TxIn;
use alloc::{vec, vec::Vec};
use core::convert::TryFrom;
pub use curve_point::*;
pub use curve_scalar::*;
pub use error::Error;
pub use key_image::*;
pub use rct_bulletproofs::*;
pub use rct_type_full::*;

lazy_static! {
    /// Generators (base points) for Pedersen commitments.
    pub static ref GENERATORS: PedersenGens = PedersenGens::default();

    /// Generators (base points) for Bulletproofs.
    pub static ref BP_GENERATORS: BulletproofGens =
        BulletproofGens::new(64, MAX_INPUTS as usize + MAX_OUTPUTS as usize);
}

/// A Pedersen commitment.
pub type Commitment = CurvePoint;

// The "blinding factor" in a Pedersen commitment.
pub type Blinding = CurveScalar;

/// An output's one-time public address.
pub type Address = RistrettoPublic;

/// Collects one-time public keys and commitments into a matrix where each column is a ring.
pub fn get_input_rows(inputs: &[TxIn]) -> Result<Vec<Vec<(Address, Commitment)>>, keys::KeyError> {
    let m = inputs.len(); // number of inputs, e.g. 2
    let n = inputs[0].ring.len(); // ring size, e.g. 11

    // Each ring is a column. input_rows[i] is the i^th row.
    let mut input_rows: Vec<Vec<(Address, Commitment)>> =
        vec![vec![(Address::default(), Commitment::default()); m]; n];

    // Populate input_rows. Each column is a ring.
    // This assumes that the rings have already been checked to have equal length.
    for (column_index, tx_in) in inputs.iter().enumerate() {
        for (row_index, ring_element) in tx_in.ring.iter().enumerate() {
            let address = RistrettoPublic::try_from(&ring_element.target_key)?;
            let commitment: Commitment = ring_element.amount.commitment;
            input_rows[row_index][column_index] = (address, commitment);
        }
    }

    Ok(input_rows)
}
