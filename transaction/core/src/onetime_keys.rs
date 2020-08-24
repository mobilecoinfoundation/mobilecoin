// Copyright (c) 2018-2020 MobileCoin Inc.

//! CryptoNote-style onetime keys.
//!
//! # References
//! * [CryptoNote Whitepaper, Sections 4.3 and 4.4](https://cryptonote.org/whitepaper.pdf)

#![allow(non_snake_case)]

use crate::domain_separators::{HASH_TO_POINT_DOMAIN_TAG, HASH_TO_SCALAR_DOMAIN_TAG};
use blake2::{Blake2b, Digest};
use curve25519_dalek::{
    constants::RISTRETTO_BASEPOINT_POINT, ristretto::RistrettoPoint, scalar::Scalar,
};
use mc_account_keys::{PublicAddress, ViewKey};
use mc_crypto_keys::{RistrettoPrivate, RistrettoPublic};
use mc_util_from_random::FromRandom;
use rand_core::{CryptoRng, RngCore};

const G: RistrettoPoint = RISTRETTO_BASEPOINT_POINT;

/// Applies a hash function and returns a RistrettoPoint.
pub fn hash_to_point(ristretto_public: &RistrettoPublic) -> RistrettoPoint {
    let mut hasher = Blake2b::new();
    hasher.input(&HASH_TO_POINT_DOMAIN_TAG);
    hasher.input(&ristretto_public.to_bytes());
    RistrettoPoint::from_hash(hasher)
}

/// Applies a hash function and returns a Scalar.
pub fn hash_to_scalar<B: AsRef<[u8]>>(data: B) -> Scalar {
    let mut hasher = Blake2b::new();
    hasher.input(&HASH_TO_SCALAR_DOMAIN_TAG);
    hasher.input(data);
    Scalar::from_hash::<Blake2b>(hasher)
}

/// Generate a tx pubkey for a subaddress transaction
pub fn compute_tx_pubkey(
    tx_secret_key: &RistrettoPrivate,
    recipient_spend_key: &RistrettoPublic,
) -> RistrettoPublic {
    let s: &Scalar = tx_secret_key.as_ref();
    let D = recipient_spend_key.as_ref();
    let R = s * D;
    RistrettoPublic::from(R)
}

/// Creates the one-time public key `P = Hs(s*C)*G + D`.
///
/// # Arguments
/// * `recipient` - The recipient's subaddress `(C,D)`.
/// * `tx_private_key` - The transaction private key `s`. Assumed unique for each output.
///
pub fn create_onetime_public_key(
    recipient: &PublicAddress,
    tx_private_key: &RistrettoPrivate,
) -> RistrettoPublic {
    // `Hs(s*C)`
    let Hs: Scalar = {
        let s = tx_private_key.as_ref();
        let C = recipient.view_public_key().as_ref();
        let sC = s * C;
        hash_to_scalar(sC.compress().as_bytes())
    };

    let D = recipient.spend_public_key().as_ref();
    RistrettoPublic::from(Hs * G + D)
}

/// Returns the subaddress for a given view key, output key and tx_pubkey
/// D' = P - Hs(aR)G
///
/// # Arguments
/// * `view_private_key` - The recipient's view private key `a`.
/// * `output_public_key` - Public key of the n^th output in the transaction (P).
/// * `tx_pub_key` - The transaction public key `R`.
///
pub fn subaddress_for_key(
    view_private_key: &RistrettoPrivate,
    output_public_key: &RistrettoPublic,
    tx_public_key: &RistrettoPublic,
) -> RistrettoPublic {
    // `Hs(a*R)`
    let Hs: Scalar = {
        let a = view_private_key.as_ref();
        let R = tx_public_key.as_ref();
        let aR = a * R;
        hash_to_scalar(aR.compress().as_bytes())
    };

    let P = output_public_key.as_ref();
    RistrettoPublic::from(P - Hs * G)
}

/// Convenience method, calls `subaddress_for_key` and returns true for a match
///
/// # Arguments
/// * `subaddress_view_key` - The recipient's subaddress view key `(a, D)`.
/// * `output_public_key` - Public key of the n^th output in the transaction (P).
/// * `tx_public_key` - The transaction public key `R`.
///
pub fn view_key_matches_output(
    subaddress_view_key: &ViewKey,
    output_public_key: &RistrettoPublic,
    tx_public_key: &RistrettoPublic,
) -> bool {
    let D_prime = subaddress_for_key(
        &subaddress_view_key.view_private_key,
        output_public_key,
        tx_public_key,
    );
    subaddress_view_key.spend_public_key == D_prime
}

/// Computes the onetime private key `x = Hs(a*R) + d`.
///
/// This assumes that the output belongs to the provided private keys.
///
/// # Arguments
/// * `tx_public_key` - The transaction public key `R`.
/// * `view_private_key` - A private view key `a`.
/// * `subaddress_spend_private_key` - A private spend key `d = Hs(a || i) + b`.
///
pub fn recover_onetime_private_key(
    tx_public_key: &RistrettoPublic,
    view_private_key: &RistrettoPrivate,
    subaddress_spend_private_key: &RistrettoPrivate,
) -> RistrettoPrivate {
    // `Hs(a*R)`
    let Hs: Scalar = {
        let a = view_private_key.as_ref();
        let R = tx_public_key.as_ref();
        let aR = a * R;
        hash_to_scalar(aR.compress().as_bytes())
    };

    let d = subaddress_spend_private_key.as_ref();
    let x = Hs + d;
    RistrettoPrivate::from(x)
}

/// Computes the shared secret `aB` from a private key `a` and a public key `B`.
///
/// # Arguments
/// * `public_key` - A public key `B`.
/// * `private_key` - A private key `a`
pub fn compute_shared_secret(
    public_key: &RistrettoPublic,
    private_key: &RistrettoPrivate,
) -> RistrettoPublic {
    let a = private_key.as_ref();
    let B = public_key.as_ref();
    let aB = a * B;

    RistrettoPublic::from(aB)
}

/// Generate a tx keypair for a subaddress transaction
///
/// # Arguments
/// * `rng` - A RNG`.
/// * `recipient_spend_key` - A recipient's public spend key `D`
pub fn generate_tx_keypair<T: CryptoRng + RngCore>(
    rng: &mut T,
    recipient_spend_key: &RistrettoPublic,
) -> (RistrettoPublic, RistrettoPrivate) {
    let tx_secret_key = RistrettoPrivate::from_random(rng);
    let tx_pubkey = compute_tx_pubkey(&tx_secret_key, &recipient_spend_key);

    (tx_pubkey, tx_secret_key)
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
        let tx_secret_key = RistrettoPrivate::from_random(&mut rng);

        let recipient: AccountKey = AccountKey::random(&mut rng);

        let onetime_public_key =
            create_onetime_public_key(&recipient.default_subaddress(), &tx_secret_key);
        let tx_pub_key = compute_tx_pubkey(
            &tx_secret_key,
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
            create_onetime_public_key(&account.default_subaddress(), &tx_private_key);
        let tx_pub_key = compute_tx_pubkey(
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
