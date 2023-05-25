// Copyright (c) 2018-2022 The MobileCoin Foundation

//! A commitment to an output's amount. This commitment is always specific to
//! a token id, and the value is in the smallest representable units.
//!
//! Amounts are implemented as Pedersen commitments. The associated private keys
//! are "masked" using a shared secret.

mod commitment;
mod compressed_commitment;

pub use commitment::Commitment;
pub use compressed_commitment::CompressedCommitment;
