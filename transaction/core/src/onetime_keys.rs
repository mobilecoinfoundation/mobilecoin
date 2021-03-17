// Copyright (c) 2018-2021 The MobileCoin Foundation

//! # MobileCoin transactions use CryptoNote-style `onetime keys` to protect
//! recipient privacy.
//!
//! When creating a transaction, the sender computes a onetime public key for
//! each output in such a way that only the sender and the recipient know who
//! the recipient is, and only the recipient is able to compute the
//! corresponding onetime private key that is required to spend the output.
//!
//! To further protect recipient privacy, an output's onetime key is computed
//! for a `subaddress` that the recipient generated from their CryptoNote-style
//! address. This makes it easy for a recipient to use different subaddresses
//! for different purposes and keep track of how much MobileCoin was sent to
//! each subaddress.
//!
//! ## User account keys (a,b)
//! To begin, a user creates unique account keys `(a,b)`, where `a` is the
//! private view key and `b` is the private spend key. The corresponding public
//! keys are `A = a*G` and `B = b*G`, where `G` is the Ristretto base point. The
//! keys `a`, `b`, `A`, and `B` "stay in the user's wallet": they are not shared
//! with other users and they do not appear in the ledger.
//!
//! ## Creating the i^th subaddress (C_i, D_i)
//! Instead, when a user wishes to receive MobileCoin, they compute a pair of
//! public keys
//!
//!    `D_i = B + Hs( a | i ) * G`
//!    `C_i = a * D`
//!
//! where `Hs` denotes an appropriately domain-separated hash function that
//! returns a scalar. `C_i` is called the subaddress public view key; `D_i` is
//! the public subadress spend key. The `subaddress index` `i` allows the user
//! to generate many distinct subaddresses from a single address.
//!
//! See the `account_keys` crate for more about account keys and subaddresses.
//!
//! ## Sending MobileCoin to a subaddress (C,D)
//! To send MobileCoin to a recipient's subaddress (C,D), the sender generates a
//! unique random number `r`, and creates the following public keys and includes
//! them in a transaction output:
//!
//!    `onetime_public_key = Hs( r * C ) * G + D`
//!    `tx_public_key = r * D`
//!
//! The `onetime_public_key` is sometimes called `target_key`.
//!
//! ## Identifying an output sent to your subaddress (C_i, D_i).
//! If you are the recipient of an output, even though you don’t know the random
//! number `r` used in the output's tx_pub_key, you can use the fact that `a *
//! rD_i = r * aD_i = rC_i` and compute the value
//!
//!    `Hs( a * tx_public_key ) * G + D_i`.
//!
//! If this value equals the output's onetime_key, then the output was sent to
//! your i^th subaddress.
//!
//! ## Spending MobileCoin sent to your subaddress (C_i, D_i)
//! To spend an output sent to your i^th subaddress, compute the onetime private
//! key:
//!
//! ```text
//!     onetime_private_key = Hs(a * tx_public_key) + d
//!                         = Hs(a * tx_public_key) + b + Hs( a | i )
//! ```
//!
//! # References
//! * [CryptoNote Whitepaper, Sections 4.3 and 4.4](https://cryptonote.org/whitepaper.pdf)

#![allow(non_snake_case)]

use crate::domain_separators::HASH_TO_SCALAR_DOMAIN_TAG;
use blake2::{Blake2b, Digest};
use curve25519_dalek::{
    constants::RISTRETTO_BASEPOINT_POINT, ristretto::RistrettoPoint, scalar::Scalar,
};
use mc_account_keys::{PublicAddress, ViewKey};
use mc_crypto_keys::{RistrettoPrivate, RistrettoPublic};

const G: RistrettoPoint = RISTRETTO_BASEPOINT_POINT;

/// Hashes a curve point to a Scalar.
fn hash_to_scalar(point: RistrettoPoint) -> Scalar {
    let mut hasher = Blake2b::new();
    hasher.update(&HASH_TO_SCALAR_DOMAIN_TAG);
    hasher.update(point.compress().as_bytes());
    Scalar::from_hash::<Blake2b>(hasher)
}

/// Creates onetime_public_key `Hs( r * C ) * G + D` for an output sent to
/// subaddress (C, D).
///
/// # Arguments
/// * `tx_private_key` - The output's tx_private_key `r`. Must be unique for
///   each output.
/// * `recipient` - The recipient subaddress `(C,D)`.
pub fn create_onetime_public_key(
    tx_private_key: &RistrettoPrivate,
    recipient: &PublicAddress,
) -> RistrettoPublic {
    // `Hs( r * C)`
    let Hs: Scalar = {
        let r = tx_private_key.as_ref();
        let C = recipient.view_public_key().as_ref();
        hash_to_scalar(r * C)
    };

    let D = recipient.spend_public_key().as_ref();
    RistrettoPublic::from(Hs * G + D)
}

/// Creates the `tx_public_key = r * D` for an output sent to subaddress (C, D).
///
/// # Arguments
/// * `tx_private_key` - The transaction private key `r`. Must be unique for
///   each output.
/// * `recipient_spend_key` - The recipient's public subaddress spend key `D`.
pub fn create_tx_public_key(
    tx_private_key: &RistrettoPrivate,
    recipient_spend_key: &RistrettoPublic,
) -> RistrettoPublic {
    let r: &Scalar = tx_private_key.as_ref();
    let D = recipient_spend_key.as_ref();
    RistrettoPublic::from(r * D)
}

/// Recovers the subaddress spend key D_i that an output was sent to.
///
/// This computes `P - Hs( a * R ) * G`. If the output was sent to this
/// recipient, the returned value equals D_i for some subaddress index i. This
/// is helpful for checking an output against a set of subaddresses.
///
/// If the output was sent to a different recipient, the returned value is
/// meaningless.
///
/// # Arguments
/// * `view_private_key` - The recipient's view private key `a`.
/// * `onetime_public_key` - The output's onetime_public_key.
/// * `tx_public_key` - The output's tx_public_key.
pub fn recover_public_subaddress_spend_key(
    view_private_key: &RistrettoPrivate,
    onetime_public_key: &RistrettoPublic,
    tx_public_key: &RistrettoPublic,
) -> RistrettoPublic {
    // `Hs( a * R )`
    let Hs: Scalar = {
        let a = view_private_key.as_ref();
        let R = tx_public_key.as_ref();
        hash_to_scalar(a * R)
    };

    let P = onetime_public_key.as_ref();
    RistrettoPublic::from(P - Hs * G)
}

/// Returns true if the output was sent to the recipient's i^th subaddress.
///
/// If you are checking an output against multiple subadresses, it is more
/// efficient to use `recover_public_subaddress_spend_key` and compare the
/// result against a table of D_i keys.
///
/// # Arguments
/// * `view_key` - The recipient's private view key and public subaddress spend
///   key, `(a, D_i)`.
/// * `onetime_public_key` - The output's onetime_public_key
/// * `tx_public_key` - The output's tx_public_key `R`.
pub fn view_key_matches_output(
    view_key: &ViewKey,
    onetime_public_key: &RistrettoPublic,
    tx_public_key: &RistrettoPublic,
) -> bool {
    let D_prime = recover_public_subaddress_spend_key(
        &view_key.view_private_key,
        onetime_public_key,
        tx_public_key,
    );
    view_key.spend_public_key == D_prime
}

/// Computes the onetime private key `Hs( a * R ) + d`.
///
/// This assumes that the output belongs to the provided private keys.
///
/// # Arguments
/// * `tx_public_key` - The output's tx_public_key `R`.
/// * `view_private_key` - A private view key `a`.
/// * `subaddress_spend_private_key` - A private spend key `d = Hs(a || i) + b`.
pub fn recover_onetime_private_key(
    tx_public_key: &RistrettoPublic,
    view_private_key: &RistrettoPrivate,
    subaddress_spend_private_key: &RistrettoPrivate,
) -> RistrettoPrivate {
    // `Hs( a * R )`
    let Hs: Scalar = {
        let a = view_private_key.as_ref();
        let R = tx_public_key.as_ref();
        hash_to_scalar(a * R)
    };

    let d = subaddress_spend_private_key.as_ref();
    let x = Hs + d;
    RistrettoPrivate::from(x)
}

/// Returns the shared secret `xY` from a private key `x` and a public key `Y`.
///
/// # Arguments
/// * `public_key` - A public key `Y`.
/// * `private_key` - A private key `x`
pub fn create_shared_secret(
    public_key: &RistrettoPublic,
    private_key: &RistrettoPrivate,
) -> RistrettoPublic {
    let x = private_key.as_ref();
    let Y = public_key.as_ref();
    RistrettoPublic::from(x * Y)
}

#[cfg(test)]
mod tests {
    use super::*;
    use mc_account_keys::AccountKey;
    use mc_crypto_rand::McRng;
    use mc_util_from_random::FromRandom;

    // Returns (onetime_public_key, tx_public_key)
    fn get_output_public_keys(
        tx_private_key: &RistrettoPrivate,
        recipient: &PublicAddress,
    ) -> (RistrettoPublic, RistrettoPublic) {
        let onetime_public_key = create_onetime_public_key(&tx_private_key, recipient);
        let tx_public_key = create_tx_public_key(&tx_private_key, recipient.spend_public_key());
        (onetime_public_key, tx_public_key)
    }

    // Get the account's i^th subaddress.
    fn get_subaddress(
        account: &AccountKey,
        index: u64,
    ) -> (RistrettoPrivate, RistrettoPrivate, PublicAddress) {
        // (view, spend)
        let (c, d) = (
            account.subaddress_view_private(index),
            account.subaddress_spend_private(index),
        );

        // (View, Spend)
        let (C, D) = (RistrettoPublic::from(&c), RistrettoPublic::from(&d));
        // Look out! The argument ordering here is weird.
        let subaddress = PublicAddress::new(&D, &C);

        (c, d, subaddress)
    }

    #[test]
    // `create_onetime_public_key` should produce a public key that agrees with the
    // recipient's view key.
    fn test_create_onetime_public_key() {
        let mut rng = McRng::default();
        let account: AccountKey = AccountKey::random(&mut rng);
        let recipient = account.default_subaddress();

        let tx_private_key = RistrettoPrivate::from_random(&mut rng);
        let (onetime_public_key, tx_public_key) =
            get_output_public_keys(&tx_private_key, &recipient);

        assert!(view_key_matches_output(
            &account.view_key(), // (a, D_0)
            &onetime_public_key,
            &tx_public_key
        ));

        let other_account = AccountKey::random(&mut rng);
        let bad_view_key = other_account.view_key();
        assert_eq!(
            view_key_matches_output(&bad_view_key, &onetime_public_key, &tx_public_key),
            false,
            "The one-time public key should not match other view keys."
        );
    }

    #[test]
    // Should return `r * D`.
    fn test_create_tx_public_key() {
        let mut rng = McRng::default();
        let r = Scalar::random(&mut rng);
        let D = RistrettoPoint::random(&mut rng);

        let expected = RistrettoPublic::from(r * D);

        let tx_private_key = RistrettoPrivate::from(r);
        let recipient_spend_key = RistrettoPublic::from(D);
        assert_eq!(
            expected,
            create_tx_public_key(&tx_private_key, &recipient_spend_key)
        );
    }

    #[test]
    // Should recover the correct public subaddress spend key D_i when the output
    // belongs to the recipient.
    fn test_recover_public_subaddress_spend_key_ok() {
        let mut rng = McRng::default();
        let account: AccountKey = AccountKey::random(&mut rng);
        let (_c, _d, recipient) = get_subaddress(&account, 7);

        let tx_private_key = RistrettoPrivate::from_random(&mut rng);
        let (onetime_public_key, tx_public_key) =
            get_output_public_keys(&tx_private_key, &recipient);

        let D_prime = recover_public_subaddress_spend_key(
            account.view_private_key(),
            &onetime_public_key,
            &tx_public_key,
        );

        assert_eq!(D_prime, *recipient.spend_public_key()); // D_7

        // view_key_matches_output should return true.
        let view_key = ViewKey::new(
            account.view_private_key().clone(),   //a
            recipient.spend_public_key().clone(), // D_7
        );
        assert!(view_key_matches_output(
            &view_key,
            &onetime_public_key,
            &tx_public_key
        ));
    }

    #[test]
    // Should not panic if the output contains the wrong onetime_public_key.
    fn test_recover_public_subaddress_spend_key_wrong_onetime_public_key() {
        let mut rng = McRng::default();
        let account: AccountKey = AccountKey::random(&mut rng);
        let (_c, _d, recipient) = get_subaddress(&account, 7);

        let tx_private_key = RistrettoPrivate::from_random(&mut rng);
        let (_, tx_public_key) = get_output_public_keys(&tx_private_key, &recipient);
        let wrong_onetime_public_key = RistrettoPublic::from_random(&mut rng);

        // Should not panic.
        let D_prime = recover_public_subaddress_spend_key(
            account.view_private_key(),
            &wrong_onetime_public_key,
            &tx_public_key,
        );

        // Returns meaningless public key.
        assert!(D_prime != *recipient.spend_public_key());

        // view_key_matches_output should return false.
        let view_key = ViewKey::new(
            account.view_private_key().clone(),   // a
            recipient.spend_public_key().clone(), // D_7
        );
        assert!(!view_key_matches_output(
            &view_key,
            &wrong_onetime_public_key,
            &tx_public_key
        ));
    }

    #[test]
    // Should not panic if the output contains the wrong tx_public_key.
    fn test_recover_public_subaddress_spend_key_wrong_tx_public_key() {
        let mut rng = McRng::default();
        let account: AccountKey = AccountKey::random(&mut rng);
        let (_c, _d, recipient) = get_subaddress(&account, 7);

        let tx_private_key = RistrettoPrivate::from_random(&mut rng);
        let (onetime_public_key, _) = get_output_public_keys(&tx_private_key, &recipient);
        let wrong_tx_public_key = RistrettoPublic::from_random(&mut rng);

        // Should not panic.
        let D_prime = recover_public_subaddress_spend_key(
            account.view_private_key(),
            &onetime_public_key,
            &wrong_tx_public_key,
        );

        // Returns meaningless public key.
        assert!(D_prime != *recipient.spend_public_key());

        // view_key_matches_output should return false.
        let view_key = ViewKey::new(
            account.view_private_key().clone(),   // a
            recipient.spend_public_key().clone(), // D_7
        );
        assert!(!view_key_matches_output(
            &view_key,
            &onetime_public_key,
            &wrong_tx_public_key
        ));
    }

    #[test]
    // Returns the private key corresponding to `onetime_public_key`.
    fn test_recover_onetime_private_key_valid_keypair() {
        let mut rng = McRng::default();
        let account = AccountKey::random(&mut rng);
        let (_c, d, recipient) = get_subaddress(&account, 787);

        let tx_private_key = RistrettoPrivate::from_random(&mut rng);
        let (onetime_public_key, tx_public_key) =
            get_output_public_keys(&tx_private_key, &recipient);

        let onetime_private_key =
            recover_onetime_private_key(&tx_public_key, account.view_private_key(), &d);
        assert_eq!(
            onetime_public_key,
            RistrettoPublic::from(&onetime_private_key)
        );
    }

    #[test]
    // Returns meaningless data if the output contains the wrong onetime_public_key.
    fn test_recover_onetime_private_key_wrong_onetime_public_key() {
        let mut rng = McRng::default();
        let account = AccountKey::random(&mut rng);
        let (_c, d, recipient) = get_subaddress(&account, 787);

        let tx_private_key = RistrettoPrivate::from_random(&mut rng);
        let (_, tx_public_key) = get_output_public_keys(&tx_private_key, &recipient);

        let wrong_onetime_public_key = RistrettoPublic::from_random(&mut rng);

        let onetime_private_key =
            recover_onetime_private_key(&tx_public_key, account.view_private_key(), &d);

        assert!(wrong_onetime_public_key != RistrettoPublic::from(&onetime_private_key));
    }

    #[test]
    // Returns meaningless data if the output contains the wrong tx_public_key.
    fn test_recover_onetime_private_key_wrong_tx_public_key() {
        let mut rng = McRng::default();
        let account = AccountKey::random(&mut rng);
        let (_c, d, recipient) = get_subaddress(&account, 787);

        let tx_private_key = RistrettoPrivate::from_random(&mut rng);
        let (onetime_public_key, _) = get_output_public_keys(&tx_private_key, &recipient);

        let wrong_tx_public_key = RistrettoPublic::from_random(&mut rng);

        let onetime_private_key =
            recover_onetime_private_key(&wrong_tx_public_key, account.view_private_key(), &d);

        assert!(onetime_public_key != RistrettoPublic::from(&onetime_private_key));
    }

    #[test]
    // shared_secret(a,B) should equal shared_secret(b,A)
    fn test_create_shared_secret_is_symmetric() {
        let mut rng = McRng::default();
        let a = RistrettoPrivate::from_random(&mut rng);
        let A = RistrettoPublic::from(&a);

        let b = RistrettoPrivate::from_random(&mut rng);
        let B = RistrettoPublic::from(&b);

        let aB = create_shared_secret(&B, &a);
        let bA = create_shared_secret(&A, &b);

        assert_eq!(aB, bA);
    }
}
