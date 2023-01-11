// Copyright (c) 2018-2022 The MobileCoin Foundation

//! A newtype representing a standard hash of a MobileCoin public address
//! (re-exported from mc_core). This is used in certain memos, as a compact
//! representation of the address.

use crate::account_keys::PublicAddress;
pub use mc_core::account::ShortAddressHash;
use mc_crypto_digestible::{Digestible, MerlinTranscript};

/// Compute [ShortAddressHash] from [PublicAddress]
impl From<&PublicAddress> for ShortAddressHash {
    fn from(src: &PublicAddress) -> Self {
        let digest = src.digest32::<MerlinTranscript>(b"mc-address");
        let b: [u8; 16] = digest[0..16].try_into().expect("arithmetic error");
        ShortAddressHash::from(b)
    }
}
