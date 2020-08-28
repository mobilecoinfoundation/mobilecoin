// Copyright (c) 2018-2020 MobileCoin Inc.

//! # MobileCoin transactions use CryptoNote-style `onetime keys` to protect recipient privacy.
//!
//! When creating a transaction, the sender computes a onetime public key for each output in
//! such a way that only the sender and the recipient know who the recipient is, and only the
//! recipient is able to compute the corresponding onetime private key that is required to
//! spend the output.
//!
//! To further protect recipient privacy, an output's onetime key is computed for a `subaddress`
//! that the recipient generated from their CryptoNote-style address. This makes it easy for a
//! recipient to use different subaddresses for different purposes and keep track of how much
//! MobileCoin was sent to each subaddress.
//!
//! ## User account keys (a,b)
//! To begin, a user creates unique account keys `(a,b)`, where `a` is the private view key and
//! `b` is the private spend key. The corresponding public keys are `A = a*G` and `B = b*G`, where
//! `G` is the Ristretto base point. The keys `a`, `b`, `A`, and `B` "stay in the user's wallet":
//! they are not shared with other users and they do not appear in the ledger.
//!
//! ## Creating the i^th subaddress (C_i, D_i)
//! Instead, when a user wishes to receive MobileCoin, they compute a pair of public keys
//!
//!    `D_i = B + Hs( a | i ) * G`
//!    `C_i = a * D`
//!
//! where `Hs` denotes an appropriately domain-separated hash function that returns a scalar.
//! `C_i` is called the subaddress public view key; `D_i` is the public subadress spend key.
//! The `subaddress index` `i` allows the user to generate many distinct subaddresses from a single
//! address.
//!
//! See the `account_keys` crate for more about account keys and subaddresses.
//!
//! ## Sending MobileCoin to a subaddress (C,D)
//! To send MobileCoin to a recipient's subaddress (C,D), the sender generates a unique random
//! number `r`, and creates the following public keys and includes them in a transaction output:
//!
//!    `onetime_public_key = Hs( r * C ) * G + D`
//!    `tx_public_key = r * D`
//!
//! The `onetime_public_key` is sometimes called `target_key`.
//!
//! ## Identifying an output sent to your subaddress (C_i, D_i).
//! If you are the recipient of an output, even though you don’t know the random number `r`
//! used in the output's tx_pub_key, you can use the fact that `a * rD_i = r * aD_i = rC_i` and
//! compute the value
//!
//!    `Hs( a * tx_public_key ) * G + D_i`.
//!
//! If this value equals the output's onetime_key, then the output was sent to your i^th subaddress.
//!
//! ## Spending MobileCoin sent to your subaddress (C_i, D_i)
//! To spend an output sent to your i^th subaddress, compute the onetime private key:
//!
//!     `onetime_private_key = Hs(a * tx_public_key) + d`
//!                         `= Hs(a * tx_public_key) + b + Hs( a | i )`
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

/// Creates the onetime public key `Hs( r * C ) * G + D`.
///
/// # Arguments
/// * `tx_private_key` - The transaction private key `r`. Must be unique for each output.
/// * `recipient` - The recipient subaddress `(C,D)`.
///
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
/// * `tx_private_key` - The transaction private key `r`. Must be unique for each output.
/// * `recipient_spend_key` - The recipient's public subaddress spend key `D`.
///
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
/// This computes `P - Hs( a * R ) * G`. If the output was sent to this recipient, the returned
/// value equals D_i for some subaddress index i. This is helpful for checking an output against
/// a set of subaddresses.
///
/// If the output was sent to a different recipient, the returned value is meaningless.
///
/// # Arguments
/// * `view_private_key` - The recipient's view private key `a`.
/// * `onetime_public_key` - The output's onetime public key.
/// * `tx_public_key` - The output's tx_public_key.
///
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
/// # Arguments
/// * `recipient` - The recipient's i^th subaddress view key `(a, D_i)`.
/// * `onetime_public_key` - The output's onetime_key
/// * `tx_public_key` - The output's tx_public_key `R`.
///
pub fn view_key_matches_output(
    recipient: &ViewKey,
    onetime_public_key: &RistrettoPublic,
    tx_public_key: &RistrettoPublic,
) -> bool {
    let D_prime = recover_public_subaddress_spend_key(
        &recipient.view_private_key,
        onetime_public_key,
        tx_public_key,
    );
    recipient.spend_public_key == D_prime
}

/// Computes the onetime private key `Hs( a * R ) + d`.
///
/// This assumes that the output belongs to the provided private keys.
///
/// # Arguments
/// * `tx_public_key` - The output's tx_public_key `R`.
/// * `view_private_key` - A private view key `a`.
/// * `subaddress_spend_private_key` - A private spend key `d = Hs(a || i) + b`.
///
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

    #[test]
    // `create_onetime_public_key` should produce a public key that agrees with the recipient's view key.
    fn test_create_onetime_public_key() {
        let mut rng = McRng::default();
        let tx_private_key = RistrettoPrivate::from_random(&mut rng);

        let recipient: AccountKey = AccountKey::random(&mut rng);

        let onetime_public_key =
            create_onetime_public_key(&tx_private_key, &recipient.default_subaddress());
        let tx_pub_key = create_tx_public_key(
            &tx_private_key,
            recipient.default_subaddress().spend_public_key(),
        );

        assert!(view_key_matches_output(
            &recipient.view_key(),
            &onetime_public_key,
            &tx_pub_key
        ));

        let other_account = AccountKey::random(&mut rng);
        let bad_view_key = other_account.view_key();
        assert_eq!(
            view_key_matches_output(&bad_view_key, &onetime_public_key, &tx_pub_key),
            false,
            "The one-time public key should not match other view keys."
        );
    }

    #[test]
    // `recover_onetime_private_key` should return a valid Public/Private key pair.
    fn test_recover_onetime_private_key_valid_keypair() {
        let mut rng = McRng::default();
        let account = AccountKey::random(&mut rng);
        let tx_private_key = RistrettoPrivate::from_random(&mut rng);

        // Sender creates a one-time public key.
        let onetime_public_key: RistrettoPublic =
            create_onetime_public_key(&tx_private_key, &account.default_subaddress());
        let tx_pub_key = create_tx_public_key(
            &tx_private_key,
            account.default_subaddress().spend_public_key(),
        );

        let onetime_private_key = recover_onetime_private_key(
            &tx_pub_key,
            account.view_private_key(),
            &account.default_subaddress_spend_private(),
        );
        assert_eq!(
            onetime_public_key,
            RistrettoPublic::from(&onetime_private_key)
        );
    }

    //    #[bench]
    //    // Microbenchmark `view_key_matches_output` with a non-matching view key.
    //    fn bench_tx_target_miss(bencher: &mut Bencher) {
    //        let mut rng = McRng::default();
    //        let account_key = AccountKey::random(&mut rng);
    //        let view_key = account_key.view_key();
    //        let miss_key = AccountKey::random(&mut rng);
    //        let tx_key = generate_keypair(&mut rng);
    //        let output_key = create_onetime_public_key(&miss_key.address(), 0, &tx_key.1);
    //
    //        bencher.iter(|| {
    //            let res = view_key_matches_output(&view_key, &output_key, 0, &tx_key.0);
    //            assert_eq!(res, false);
    //        });
    //    }
    //
    //    #[bench]
    //    // Microbenchmark `view_key_matches_output` with a matching a view key.
    //    fn bench_tx_target_hit(bencher: &mut Bencher) {
    //        let mut rng = McRng::default();
    //        let account_key = AccountKey::random(&mut rng);
    //        let view_key = account_key.view_key();
    //        let tx_key = generate_keypair(&mut rng);
    //        let output_key = create_onetime_public_key(&account_key.address(), 0, &tx_key.1);
    //
    //        bencher.iter(|| {
    //            let res = view_key_matches_output(&view_key, &output_key, 0, &tx_key.0);
    //            assert_eq!(res, true);
    //        });
    //    }
    //
    //    #[bench]
    //    // Benchmark `view_key_matches_output` with non-matching view keys in a batch setting.
    //    fn bench_tx_target_miss_batch(bencher: &mut Bencher) {
    //        let mut rng = McRng::default();
    //        let NUM_ACCTS = 2;
    //        let NUM_OUTPUTS = 2;
    //
    //        let account_keys = (0..NUM_ACCTS).map(|_| AccountKey::random(&mut rng));
    //        let view_keys: Vec<ViewKey> = account_keys.map(|acct| acct.view_key()).collect();
    //        let miss_key = AccountKey::random(&mut rng);
    //        let mut tx_pub_keys = vec![];
    //        let mut tx_secret_keys = vec![];
    //        (0..NUM_OUTPUTS).for_each(|_| {
    //            let tx_key = generate_keypair(&mut rng);
    //            tx_pub_keys.push(tx_key.0);
    //            tx_secret_keys.push(tx_key.1);
    //        });
    //        let output_keys: Vec<RistrettoPublic> = (0..NUM_OUTPUTS)
    //            .map(|i| create_onetime_public_key(&miss_key.address(), 0, &tx_secret_keys[i]))
    //            .collect();
    //
    //        bencher.iter(|| {
    //            for (output_index, output_key) in output_keys.iter().enumerate() {
    //                for view_key in view_keys.iter() {
    //                    let res = view_key_matches_output(
    //                        &view_key,
    //                        output_key,
    //                        0,
    //                        &tx_pub_keys[output_index],
    //                    );
    //                    assert_eq!(res, false);
    //                }
    //            }
    //        });
    //    }
}
