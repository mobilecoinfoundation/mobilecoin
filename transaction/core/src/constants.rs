// Copyright (c) 2018-2021 The MobileCoin Foundation

//! MobileCoin Transaction Constants.

use crate::ring_signature::Scalar;

/// Maximum number of transactions that may be included in a Block.
pub const MAX_TRANSACTIONS_PER_BLOCK: usize = 5000;

/// Each input ring must contain this many elements.
pub const RING_SIZE: usize = 11;

/// Each transaction must contain no more than this many inputs (rings).
pub const MAX_INPUTS: u64 = 16;

/// Each transaction must contain no more than this many outputs.
pub const MAX_OUTPUTS: u64 = 16;

/// Maximum number of blocks in the future a transaction's tombstone block can
/// be set to.
pub const MAX_TOMBSTONE_BLOCKS: u64 = 100;

/// The MobileCoin network will contain a fixed supply of 250 million
/// mobilecoins (MOB).
pub const TOTAL_MOB: u64 = 250_000_000;

/// one microMOB = 1e6 picoMOB
pub const MICROMOB_TO_PICOMOB: u64 = 1_000_000;

/// one milliMOB = 1e9 picoMOB
pub const MILLIMOB_TO_PICOMOB: u64 = 1_000_000_000;

/// Minimum allowed fee, denominated in picoMOB.
pub const MINIMUM_FEE: u64 = 400 * MICROMOB_TO_PICOMOB;

lazy_static! {
    // Blinding for the implicit fee outputs.
    pub static ref FEE_BLINDING: Scalar = Scalar::zero();
}
