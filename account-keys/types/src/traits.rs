use mc_crypto_keys::RistrettoPublic;

/// An object which has represents a subaddress, and has RingCT-style
/// view and spend public keys.
pub trait RingCtAddress {
    /// Get the subaddress' view public key
    fn view_public_key(&self) -> &RistrettoPublic;
    /// Get the subaddress' spend public key
    fn spend_public_key(&self) -> &RistrettoPublic;
}
