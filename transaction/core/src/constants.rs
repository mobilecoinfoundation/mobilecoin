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
        pub const FEE_SPEND_PUBLIC_KEY: [u8; 32] = [148, 59, 218, 190, 201, 192, 223, 42, 109, 112, 217, 83, 6, 121, 195, 4, 17, 136, 18, 30, 159, 4, 177, 12, 119, 238, 54, 220, 167, 212, 4, 117];

        /// Testnet fee recipient view public key.
        pub const FEE_VIEW_PUBLIC_KEY: [u8; 32] = [150, 99, 44, 152, 218, 46, 166, 167, 51, 163, 9, 41, 171, 78, 145, 80, 231, 248, 163, 94, 17, 238, 231, 161, 238, 11, 105, 177, 104, 12, 236, 18];

        /// The private key is only used by tests. This does not need to be specified for main net.
        pub const FEE_VIEW_PRIVATE_KEY: [u8; 32] = [202, 221, 141, 9, 53, 168, 1, 178, 106, 217, 81, 136, 44, 237, 27, 116, 156, 245, 154, 71, 174, 175, 0, 33, 84, 68, 77, 24, 214, 13, 92, 9];

    } else if #[cfg(feature="main-net-fee-keys")] {
        compile_error!("main net keys are not available yet");
    } else {
        compile_error!("must specify either main-net-fee-keys or test-net-fee-keys feature");
    }
}

#[cfg(test)]
mod tests {
    use super::{FEE_SPEND_PUBLIC_KEY, FEE_VIEW_PRIVATE_KEY, FEE_VIEW_PUBLIC_KEY};
    use crate::account_keys::AccountKey;
    use rand::{rngs::StdRng, SeedableRng};

    #[test]
    /// The fee keys should be correctly derived.
    fn generate_fee_view_key() {
        let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);

        // Fees are sent to the default subaddress of the Fee account.
        let fee_account = AccountKey::random(&mut rng);
        let fee_subaddress = fee_account.default_subaddress();

        let spend_public_key_bytes: [u8; 32] = fee_subaddress.spend_public_key().to_bytes();
        let view_public_key_bytes: [u8; 32] = fee_subaddress.view_public_key().to_bytes();
        let view_private_key_bytes: [u8; 32] = fee_account.view_private_key().to_bytes();

        // println!(
        //     "pub const FEE_SPEND_PUBLIC_KEY: [u8; 32] = {:?};",
        //     spend_public_key_bytes
        // );
        //
        // println!(
        //     "pub const FEE_VIEW_PUBLIC_KEY: [u8; 32] = {:?};",
        //     view_public_key_bytes
        // );
        //
        // println!(
        //     "pub const FEE_VIEW_PRIVATE_KEY: [u8; 32] = {:?};",
        //     view_private_key_bytes
        // );

        assert_eq!(view_private_key_bytes, FEE_VIEW_PRIVATE_KEY);
        assert_eq!(view_public_key_bytes, FEE_VIEW_PUBLIC_KEY);
        assert_eq!(spend_public_key_bytes, FEE_SPEND_PUBLIC_KEY);
    }
}
