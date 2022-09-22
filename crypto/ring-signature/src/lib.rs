// Copyright (c) 2018-2022 The MobileCoin Foundation

//! MobileCoin implementation of amount commitments and MLSAG ring signatures,
//! as well as some related functions (see one-time keys module)

#![no_std]
#![deny(missing_docs)]

extern crate alloc;

use crate::onetime_keys::create_shared_secret;
use mc_crypto_keys::{RistrettoPrivate, RistrettoPublic};

mod amount;
mod domain_separators;
mod ring_signature;

pub mod onetime_keys;
#[cfg(any(test, feature = "proptest"))]
pub mod proptest_fixtures;

pub use amount::{Commitment, CompressedCommitment};
pub use ring_signature::{
    generators, CurveScalar, Error, KeyImage, PedersenGens, ReducedTxOut, RingMLSAG,
    Scalar,
};

/// Get the shared secret for a transaction output.
///
/// # Arguments
/// * `view_key` - The recipient's private View key.
/// * `tx_public_key` - The public key of the transaction.
pub fn get_tx_out_shared_secret(
    view_key: &RistrettoPrivate,
    tx_public_key: &RistrettoPublic,
) -> RistrettoPublic {
    create_shared_secret(tx_public_key, view_key)
}
