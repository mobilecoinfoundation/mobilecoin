// Copyright (c) 2018-2021 The MobileCoin Foundation

#![no_std]

//! This crate implements a simple authenticated public-key crypto API, for
//! messages of arbitrary length.
//! - Ristretto Curvepoints used for ECDH
//! - HKDF<Blake2b> used to extract key material from dh_shared_secret
//! - Aes-128-Gcm used to encrypt and mac the payload
//!
//! There is also a versioning tag used to allow for a wire-stable format
//!
//! To use, create the object `VersionedCryptoBox`, then use the CryptoBox trait
//! to encrypt and decrypt.

extern crate alloc;

mod hkdf_box;
mod traits;
mod versioned;

pub use aead::{self, generic_array, Error as AeadError};
pub use traits::{CryptoBox, Error};
pub use versioned::{VersionError, VersionedCryptoBox};

// FixedBuffer allows to use a &mut [u8] slice as a fixed-capacity aead::Buffer
mod fixed_buffer;
pub use fixed_buffer::FixedBuffer;

#[cfg(test)]
mod test {
    use super::*;
    use aead::generic_array::arr;
    use mc_crypto_keys::{RistrettoPrivate, RistrettoPublic};
    use mc_util_from_random::FromRandom;

    extern crate mc_util_test_helper;

    #[test]
    fn test_round_trip() {
        let algo = VersionedCryptoBox::default();
        let plaintext1 = b"01234567".to_vec();
        let plaintext2 = plaintext1.repeat(50);

        mc_util_test_helper::run_with_several_seeds(|mut rng| {
            let a = RistrettoPrivate::from_random(&mut rng);
            let a_pub = RistrettoPublic::from(&a);

            for plaintext in &[&plaintext1[..], &plaintext2[..]] {
                for _reps in 0..50 {
                    let ciphertext = algo.encrypt(&mut rng, &a_pub, plaintext).unwrap();
                    let (success, decrypted) =
                        algo.decrypt(&a, &ciphertext).expect("decryption failed!");
                    assert_eq!(plaintext.len(), decrypted.len());
                    assert_eq!(plaintext, &&decrypted[..]);
                    assert_eq!(bool::from(success), true);
                }
            }
        });
    }

    #[test]
    fn test_expected_failure() {
        let algo = VersionedCryptoBox::default();
        let plaintext1 = b"01234567".to_vec();
        let plaintext2 = plaintext1.repeat(50);

        mc_util_test_helper::run_with_several_seeds(|mut rng| {
            let a = RistrettoPrivate::from_random(&mut rng);
            let a_pub = RistrettoPublic::from(&a);

            let not_a = RistrettoPrivate::from_random(&mut rng);

            for plaintext in &[&plaintext1[..], &plaintext2[..]] {
                for _reps in 0..50 {
                    let ciphertext = algo.encrypt(&mut rng, &a_pub, plaintext).unwrap();
                    let (success, _decrypted) = algo.decrypt(&not_a, &ciphertext).unwrap();
                    assert_eq!(bool::from(success), false);
                }
            }
        });
    }

    #[test]
    fn test_round_trip_fixed_length() {
        let algo = VersionedCryptoBox::default();
        let plaintext1 = arr![u8; 0, 1, 2, 3, 4, 4, 3, 2];
        let plaintext2 = arr![u8; 42, 42, 42, 42, 78, 78, 78, 78];

        mc_util_test_helper::run_with_several_seeds(|mut rng| {
            let a = RistrettoPrivate::from_random(&mut rng);
            let a_pub = RistrettoPublic::from(&a);

            for plaintext in &[plaintext1, plaintext2] {
                for _reps in 0..10 {
                    let ciphertext = algo
                        .encrypt_fixed_length(&mut rng, &a_pub, plaintext)
                        .unwrap();
                    let (success, decrypted) = algo
                        .decrypt_fixed_length(&a, &ciphertext)
                        .expect("decryption failed!");
                    assert_eq!(plaintext, &decrypted);
                    assert_eq!(bool::from(success), true);
                }
            }
        });
    }
}
