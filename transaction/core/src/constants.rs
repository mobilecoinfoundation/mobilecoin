// Copyright (c) 2018-2020 MobileCoin Inc.

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

/// Maximum number of blocks in the future a transaction's tombstone block can be set to.
pub const MAX_TOMBSTONE_BLOCKS: u64 = 100;

/// The MobileCoin network will contain a fixed supply of 250 million mobilecoins (MOB).
pub const TOTAL_MOB: u64 = 250_000_000;

/// one milliMOB = 1e9 picoMOB
pub const MILLIMOB_TO_PICOMOB: u64 = 1_000_000_000;

/// Minimum allowed fee, denominated in picoMOB.
pub const MINIMUM_FEE: u64 = 10 * MILLIMOB_TO_PICOMOB;

lazy_static! {
    // Blinding for the implicit fee outputs.
    pub static ref FEE_BLINDING: Scalar = Scalar::zero();
}

/*
cfg_if::cfg_if! {
    if #[cfg(any(test, feature="test-net-fee-keys"))] {
        /// Internal TestNet fee recipient account, generated via
        ///
        ///   let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);
        ///   let foundation_account_key = AccountKey::random(&mut rng);
        pub const FEE_SPEND_PUBLIC_KEY: [u8; 32] = [38, 181, 7, 198, 49, 36, 162, 245, 233, 64, 180, 251, 137, 228, 178, 187, 10, 32, 120, 237, 12, 142, 85, 26, 213, 146, 104, 185, 100, 110, 194, 65];

        /// TestNet fee recipient view public key.
        pub const FEE_VIEW_PUBLIC_KEY: [u8; 32] = [82, 34, 161, 233, 174, 50, 210, 28, 35, 17, 74, 92, 230, 187, 57, 224, 203, 86, 174, 163, 80, 212, 97, 157, 67, 177, 32, 112, 97, 177, 3, 70];

        /// The private key is only used by tests. This does not need to be specified for main net.
        pub const FEE_VIEW_PRIVATE_KEY: [u8; 32] = [21, 152, 99, 251, 140, 2, 50, 154, 2, 171, 188, 60, 163, 243, 204, 195, 241, 78, 204, 85, 202, 52, 250, 242, 215, 247, 175, 59, 121, 185, 111, 8];

    } else if #[cfg(feature="main-net-fee-keys")] {
        /// BetaNet Fee Account Key
        /// Generated with mc-util-keyfile/sample-keys on an airgapped machine, then pubkey copied
        /// and read with mc-util-keyfile/read-pubfile.
        pub const FEE_SPEND_PUBLIC_KEY: [u8; 32] = [68, 53, 73, 223, 240, 207, 203, 209, 138, 92, 5, 107, 179, 135, 234, 177, 251, 188, 157, 48, 75, 160, 226, 198, 191, 125, 70, 138, 18, 7, 159, 68];

        /// BetaNet fee recipient view public key
        pub const FEE_VIEW_PUBLIC_KEY: [u8; 32] = [126, 55, 144, 45, 119, 126, 43, 192, 109, 216, 110, 115, 15, 234, 184, 168, 39, 186, 136, 98, 62, 77, 236, 177, 65, 6, 157, 147, 134, 249, 96, 4];
    } else {
        compile_error!("must specify either main-net-fee-keys or test-net-fee-keys feature");
    }
}
*/
