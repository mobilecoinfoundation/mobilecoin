// Copyright (c) 2018-2020 MobileCoin Inc.

#![no_std]
// #![deny(missing_docs)]
#![allow(unused_imports)] // During development...

extern crate alloc;

#[cfg(test)]
#[macro_use]
extern crate std;

#[macro_use]
extern crate lazy_static;

use crate::onetime_keys::compute_shared_secret;
use keys::{RistrettoPrivate, RistrettoPublic};

pub mod account_keys;
pub mod amount;
pub mod blake2b_256;
mod block;
pub mod constants;
pub mod encoders;
pub mod encrypted_fog_hint;
pub mod fog_hint;
pub mod membership_proofs;
pub mod onetime_keys;
pub mod range;
pub mod range_proofs;
mod redacted_tx;
pub mod ring_signature;
pub mod tx;
pub mod validation;
pub mod view_key;

#[cfg(test)]
pub mod proptest_fixtures;

pub use block::*;
pub use redacted_tx::RedactedTx;

/// Get the shared secret for a transaction output.
///
/// # Arguments
/// * `view_key` - The recipient's private View key.
/// * `tx_public_key` - The public key of the transaction.
pub fn get_tx_out_shared_secret(
    view_key: &RistrettoPrivate,
    tx_public_key: &RistrettoPublic,
) -> RistrettoPublic {
    compute_shared_secret(tx_public_key, &view_key)
}
