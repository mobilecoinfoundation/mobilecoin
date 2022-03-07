//! A canonical burn address for the auditable burning of funds
//!
//! The requirements here are:
//! * The canonical burn address is a public address that anyone can send funds
//!   to
//! * Those funds are not spendable by anyone
//! * The address is derived in a transparent way
//! * Anyone can view-key scan this address and find all the TxOut's that have
//!   been burned, and their amounts.
//!
//! The basic idea here is that:
//! * The spend public key should be derived by a hash to curve operation, so
//!   that it is infeasible for anyone to find the spend private key.
//! * The view private key should be a known constant.
//!
//! However, there are challenges with this idea:
//!
//! In MobileCoin, unlike in cryptonote, all public addresses are subaddresses,
//! and the transaction builder uses the subaddress math rather than the
//! "vanilla" cryptonote math. To avoid the need to create a custom transaction
//! builder for burning, we would like the derivation of the burn address to
//! follow the pattern for subaddresses. (If we were in the cryptonote model
//! still, we could simply convert the view private key to a ristretto point to
//! get the view public key. But this requires "bringing back" the code for
//! sending to old-style public addresses.)
//!
//! The main difficulty here is that normally, deriving a subaddress from an
//! account key requires the use of the spend private key. However, no one can
//! know the spend private key of the burn address, or they would be able to
//! spend the funds. So we cannot use the normal subaddress derivation.
//!
//! The main idea is to adapt the math for subaddress derivation.
//! It turns out that the subaddress view public key is always equal to
//! the account view private key times the subaddress spend public key.
//! So, we can derive it using that identity without knowing any of the spend
//! private keys.

use crate::PublicAddress;
use blake2::{Blake2b, Digest};
use curve25519_dalek::{ristretto::RistrettoPoint, scalar::Scalar};
use mc_crypto_keys::{RistrettoPrivate, RistrettoPublic};

/// The constant chosen for the burn address view private key.
/// This is arbitrary but we decided to make it nonzero.
pub const BURN_ADDRESS_VIEW_PRIVATE: Scalar = Scalar::from_bits([1u8; 32]);

/// The burn address view private key in the keys-crate wrapper type
pub fn burn_address_view_private() -> RistrettoPrivate {
    RistrettoPrivate::from(BURN_ADDRESS_VIEW_PRIVATE)
}

/// The public address for burning funds transparently.
/// It is not configured as a fog address.
pub fn burn_address() -> PublicAddress {
    PublicAddress::new(
        &RistrettoPublic::from(burn_address_spend_public()),
        &RistrettoPublic::from(burn_address_view_public()),
    )
}

// The burn address spend public key, in the curve25519-dalek ristretto point
// type
fn burn_address_spend_public() -> RistrettoPoint {
    let mut hasher = Blake2b::new();
    hasher.update(b"MC_BURN_ADDRESS_SPEND_PUBLIC");
    RistrettoPoint::from_hash(hasher)
}

// The burn address view public key, in the curve25519-dalek ristretto point
// type
fn burn_address_view_public() -> RistrettoPoint {
    BURN_ADDRESS_VIEW_PRIVATE * burn_address_spend_public()
}
