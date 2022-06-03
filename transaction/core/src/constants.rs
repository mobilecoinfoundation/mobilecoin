// Copyright (c) 2018-2022 The MobileCoin Foundation

//! MobileCoin Transaction Constants.

use mc_crypto_ring_signature::Scalar;

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
///
/// This is the limit enforced in the enclave as part of transaction
/// validation rules. However, untrusted may decide to evict pending
/// transactions from the queue before this point, so this is only a maximum on
/// how long a Tx can actually be pending.
///
/// Note that clients are still in charge of setting the actual tombstone value.
/// For normal transactions, clients at time of writing are defaulting to
/// something like current block height + 100, so that they can know quickly if
/// a Tx succeeded or failed.
///
/// Rationale for this number is, at a rate of 2 blocks / minute, this is 7
/// days, which eases operations for minting agents which must perform a
/// multi-sig.
pub const MAX_TOMBSTONE_BLOCKS: u64 = 20160;

/// The MobileCoin network will contain a fixed supply of 250 million
/// mobilecoins (MOB).
pub const TOTAL_MOB: u64 = 250_000_000;

/// one microMOB = 1e6 picoMOB
pub const MICROMOB_TO_PICOMOB: u64 = 1_000_000;

/// one milliMOB = 1e9 picoMOB
pub const MILLIMOB_TO_PICOMOB: u64 = 1_000_000_000;

lazy_static! {
    /// Blinding for the implicit fee outputs.
    pub static ref FEE_BLINDING: Scalar = Scalar::zero();
}
