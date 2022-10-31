// Copyright (c) 2018-2022 The MobileCoin Foundation

use mc_crypto_keys::RistrettoPublic;

/// An object which represents a subaddress, and has RingCT-style
/// view and spend public keys.
// TODO: replace with typed `mc_core::account::RingCTAddress`
pub trait RingCtAddress {
    /// Get the subaddress' view public key
    fn view_public_key(&self) -> &RistrettoPublic;
    /// Get the subaddress' spend public key
    fn spend_public_key(&self) -> &RistrettoPublic;
}
