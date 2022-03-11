// Copyright (c) 2018-2022 The MobileCoin Foundation

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

use crate::{domain_separators::BURN_ADDRESS_DOMAIN_SEPARATOR, PublicAddress};
use curve25519_dalek::{ristretto::RistrettoPoint, scalar::Scalar};
use mc_crypto_hashes::{Blake2b512, Digest};
use mc_crypto_keys::{RistrettoPrivate, RistrettoPublic};

/// The constant chosen for the burn address view private key.
/// This is arbitrary but we decided to make it nonzero, because we are using
/// this number to multiply, and multiplying by zero can lead to degeneracies.
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
//
// This is meant to be a nothing-up-my-sleeve number hashed to the elliptic
// curve, so that it is infeasible for anyone to know the root of this curve
// point.
//
// Following the approach used for other such curve points in
// mc-transaction-core, we hash a string descriptor using blake2b and then use
// this to hash-to-curve.
fn burn_address_spend_public() -> RistrettoPoint {
    let mut hasher = Blake2b512::new();
    hasher.update(BURN_ADDRESS_DOMAIN_SEPARATOR);
    RistrettoPoint::from_hash(hasher)
}

// The burn address view public key, in the curve25519-dalek ristretto point
// type.
//
// This needs to be chosen in such a way that it corresponds to a sub-address
// view public key, so that sending to the burn address (as a sub-address) will
// work and view key scanning with burn_address_view_private will also work.
//
// To achieve this, we use the identity for subaddress derivations:
//
// `subaddress_view_public = account_view_private * subaddress_spend_public`
//
// For reference, see Mechanics of MobileCoin section on subaddresses, or,
// refer to the `AccountKey` struct defined in this crate, which defines
//
// `subaddress_view_private = account_view_private * subaddress_spend_private`
//
// This implies the identity that we need here -- simply multiply both sides
// by RISTRETTO_BASEPOINT.
//
// Because of this identity, as long as we know `account_view_private` for the
// burn address (defined above as a known constant), and we know
// `subaddress_spend_public` for the burn address (defined above as a hash to
// curve), we can use the identity to derive `subaddress_view_public`.
//
// This is the last key we need to get a complete
// subaddress for the burn address, and at no point do we need any of the spend
// private keys for the burn address to complete this derivation.
//
// A more naive idea would be to just take
// `RistrettoPublic::from(BURN_ADDRESS_VIEW_PRIVATE)`. Under the hood that's the
// same as `BURN_ADDRESS_VIEW_PRIVATE * RISTRETTO_BASEPOINT`. That would be
// correct if we were not producing a subaddress here. But, if we do that,
// then view key matching with `BURN_ADDRESS_VIEW_PRIVATE`
// will not work, because the transaction builder only supports
// sending to subaddresses (and not "regular" cryptonote addresses). We could
// bring back the (deprecated and deleted code) from before we made the decision
// that all addresses in MobileCoin are subaddresses, but it's simpler not to
// have to do that.
fn burn_address_view_public() -> RistrettoPoint {
    BURN_ADDRESS_VIEW_PRIVATE * burn_address_spend_public()
}
