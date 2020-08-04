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

cfg_if::cfg_if! {
    if #[cfg(any(test, feature="test-net-fee-keys"))] {
        /// Internal testnet fee recipient account, generated via
        ///
        ///   let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);
        ///   let foundation_account_key = AccountKey::random(&mut rng);
        pub const FEE_SPEND_PUBLIC_KEY: [u8; 32] = [38, 181, 7, 198, 49, 36, 162, 245, 233, 64, 180, 251, 137, 228, 178, 187, 10, 32, 120, 237, 12, 142, 85, 26, 213, 146, 104, 185, 100, 110, 194, 65];

        /// Testnet fee recipient view public key.
        pub const FEE_VIEW_PUBLIC_KEY: [u8; 32] = [82, 34, 161, 233, 174, 50, 210, 28, 35, 17, 74, 92, 230, 187, 57, 224, 203, 86, 174, 163, 80, 212, 97, 157, 67, 177, 32, 112, 97, 177, 3, 70];

        /// The private key is only used by tests. This does not need to be specified for main net.
        pub const FEE_VIEW_PRIVATE_KEY: [u8; 32] = [21, 152, 99, 251, 140, 2, 50, 154, 2, 171, 188, 60, 163, 243, 204, 195, 241, 78, 204, 85, 202, 52, 250, 242, 215, 247, 175, 59, 121, 185, 111, 8];

    } else if #[cfg(feature="main-net-fee-keys")] {
        compile_error!("main net keys are not available yet");
    } else {
        compile_error!("must specify either main-net-fee-keys or test-net-fee-keys feature");
    }
}

#[cfg(test)]
mod tests {
    use super::{FEE_SPEND_PUBLIC_KEY, FEE_VIEW_PRIVATE_KEY, FEE_VIEW_PUBLIC_KEY};
    use mc_account_keys::AccountKey;
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
