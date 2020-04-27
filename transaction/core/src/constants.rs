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

/// Minimum allowed fee, denominated in picoMOB.
pub const BASE_FEE: u64 = 10;

lazy_static! {
    // Blinding for the implicit fee outputs.
    pub static ref FEE_BLINDING: Scalar = Scalar::zero();
}

cfg_if::cfg_if! {
    if #[cfg(any(test, feature="test-net-fee-keys"))] {
        /// Internal testnet fee recipient account, generated via
        ///
        ///   let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);
        ///   let foundation_account_key = AccountKey::random(&mut rng);
        ///
        /// This is available in the `generate_test_foundation_key` utility.
        pub const FEE_SPEND_PUBLIC_KEY: [u8; 32] = [
            160, 79, 78, 17, 132, 143, 209, 245, 178, 242, 129, 141, 206, 68, 64, 194, 71, 138, 167, 101,
            214, 0, 76, 82, 159, 44, 114, 209, 83, 142, 35, 50,
        ];

        /// Testnet fee recipient view public key.
        pub const FEE_VIEW_PUBLIC_KEY: [u8; 32] = [
            124, 128, 84, 41, 33, 74, 220, 50, 187, 243, 190, 2, 147, 221, 217, 118, 201, 40, 132, 194,
            244, 55, 11, 0, 45, 196, 155, 137, 102, 68, 154, 84,
        ];

        /// The private key is only used by tests. This does not need to be specified for main net.
        pub const FEE_VIEW_PRIVATE_KEY: [u8; 32] = [
            21, 152, 99, 251, 140, 2, 50, 154, 2, 171, 188, 60, 163, 243, 204, 195, 241, 78, 204, 85, 202,
            52, 250, 242, 215, 247, 175, 59, 121, 185, 111, 8,
        ];
    } else if #[cfg(feature="main-net-fee-keys")] {
        compile_error!("main net keys are not available yet");
    } else {
        compile_error!("must specify either main-net-fee-keys or test-net-fee-keys feature");
    }
}
