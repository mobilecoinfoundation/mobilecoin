// Copyright (c) 2018-2020 MobileCoin Inc.

#![no_std]
// Following curve25519 ristretto comments
#![allow(non_snake_case)]

// Note(chris): In SGX maybe should use sgx_tcrypto?
// Note(chris): In discussion, we wanted to use aes-gcm
// but at time of writing it's not available in no_std
// aes-ctr is very close to aes-gcm, but lacks
// stream-cipher authentication functionality.
//
// Since we only plan
// to use this crate to send messages that are less than
// a block, and there's no possibility that mallory could
// get in between the blocks and change them in flight,
// stream-cipher functionality seems overkill anyways
//
// Projected uses are: account hints, encrypted tx's in
// recovery ledger.
//
// In these cases tampering with the encrypted value
// only means Bob won't be able to find his transactions
// at the next step, not that Mallory can steal them or
// trick Bob into telling them to her.
extern crate alloc;

#[cfg(test)]
extern crate test_helper;

use aes_ctr::{
    stream_cipher::{generic_array::GenericArray, NewStreamCipher, SyncStreamCipher},
    Aes256Ctr,
};
use alloc::{vec, vec::Vec};
use core::convert::TryFrom;
use hkdf::Hkdf;
use keys::{CompressedRistrettoPublic, RistrettoPrivate, RistrettoPublic, RISTRETTO_PUBLIC_LEN};
use rand_core::{CryptoRng, RngCore};
use sha2::Sha256;

/// The amount of bytes by which the cipher text is longer then plaintext.
/// This is a constant and at this revision is equal to the length of one ristretto curve point.
/// Users of ecies crate can use this constant to future proof against changes in ECIES crate.
pub const ECIES_EXTRA_SPACE: usize = RISTRETTO_PUBLIC_LEN;

/// Encrypt
///
/// # Arguments
/// * rng: Rng to use for the encryption operation
/// * key: Public key to encrypt against
/// * plaintext: The messages to be encrypted
///
/// # Returns
/// * Vec<u8> the encrypted payload (ciphertext)
///
/// Encryption can fail only if the input is not a valid compressed Ristretto point
pub fn encrypt<T: RngCore + CryptoRng>(
    rng: &mut T,
    key: &RistrettoPublic,
    plaintext: &[u8],
) -> Vec<u8> {
    encrypt_with_salt(rng, key, plaintext, &DEFAULT_HKDF_SALT)
}

/// encrypt_with_salt
/// Same as encrypt, but takes an explicit salt value
/// See https://tools.ietf.org/html/rfc5869 Sec 3.1 for discussion
/// The salt is an optional random, non-secret value which can be sent in the
/// clear, and reused, but it improves security properties if it is provided,
/// even if it is not random.
/// By default we use a hard-coded salt value, unless you can provide one.
///
/// # Arguments
/// * rng: Rng to use for encryption operation
/// * key: Public key to encrypt against
/// * plaintext: The message to be encrypted
/// * hkdf_salt: The (public) salt to use with hkdf function
///
#[inline]
pub fn encrypt_with_salt<T: RngCore + CryptoRng>(
    rng: &mut T,
    key: &RistrettoPublic,
    plaintext: &[u8],
    hkdf_salt: &[u8; 32],
) -> Vec<u8> {
    let mut result = vec![0u8; RISTRETTO_PUBLIC_LEN + plaintext.len()];

    encrypt_into(rng, &key, plaintext, hkdf_salt, &mut result);

    result
}

/// encrypt_into
/// Same as encrypt, but cannot fail, and doesn't make an allocation.
/// The output buffer must be exactly 32 bytes longer than input buffer.
/// This version is easier to use when constant time operation is required.
///
/// # Arguments
/// * rng: Rng to use for encryption operation
/// * key: Public key to encrypt against
/// * plaintext: The message to be encrypted
/// * hkdf_salt: The (public) salt to use with hkdf function
///
#[inline]
pub fn encrypt_into<T: RngCore + CryptoRng>(
    rng: &mut T,
    key: &RistrettoPublic,
    plaintext: &[u8],
    hkdf_salt: &[u8; 32],
    output: &mut [u8],
) {
    debug_assert!(plaintext.len() + RISTRETTO_PUBLIC_LEN == output.len());
    // ECDH
    use keys::KexPublic;
    let (our_public, shared_secret) = key.new_secret(rng);

    let compressed_public = CompressedRistrettoPublic::from(our_public);
    let compressed_public_bytes: &[u8] = compressed_public.as_ref();
    output[0..RISTRETTO_PUBLIC_LEN].clone_from_slice(compressed_public_bytes);

    // Copy plaintext to place where ciphertext will go
    let dst = &mut output[RISTRETTO_PUBLIC_LEN..];
    dst.clone_from_slice(plaintext);

    // KDF + AES
    common_part_with_salt(shared_secret.as_ref(), hkdf_salt, dst);
}

/// decrypt
///
/// # Arguments
/// * key: Private key to decrypt with
/// * ciphertext: The encrypted payload to decipher
///
/// # Returns
/// * Vec<u8> the plaintext, or an error
///
/// Decryption can fail if the decryption key doesn't match the encryption key
/// Depending on cryptosystem this can be detected by some MAC or by AES-GCM, etc.
/// The details of the failure are generally unhelpful, and cannot be usefully
/// distinguished programmatically at runtime, so the error type is ()
///
pub fn decrypt(key: &RistrettoPrivate, ciphertext: &[u8]) -> Result<Vec<u8>, ()> {
    decrypt_with_salt(key, ciphertext, &DEFAULT_HKDF_SALT)
}

/// decrypt_with_salt
/// Counterpart to encrypt_with_salt
///
/// # Arguments
/// * key: Private key to decrypt with
/// * ciphertext: The encrypted payload to decipher
/// * hkdf_salt: The (public) salt to use with hkdf function
///
#[inline]
pub fn decrypt_with_salt(
    key: &RistrettoPrivate,
    ciphertext: &[u8],
    hkdf_salt: &[u8; 32],
) -> Result<Vec<u8>, ()> {
    if ciphertext.len() < RISTRETTO_PUBLIC_LEN {
        return Err(());
    }

    let mut result = vec![0u8; ciphertext.len() - RISTRETTO_PUBLIC_LEN];

    decrypt_into(key, ciphertext, hkdf_salt, &mut result)?;

    Ok(result)
}

/// decrypt_into
/// Counterpart to encrypt_into
/// Output buffer must be exactly 32 bytes smaller than ciphertext buffer
///
/// # Arguments
/// * key: Private key (dalek Scalar) to decrypt with
/// * ciphertext: The encrypted payload to decipher
/// * hkdf_salt: The (public) salt to use with hkdf function
/// * output: Where to place the plaintext
///
/// # Returns
/// * Ok on success, Err if the first 32 bytes were malformed
#[inline]
pub fn decrypt_into(
    key: &RistrettoPrivate,
    ciphertext: &[u8],
    hkdf_salt: &[u8; 32],
    output: &mut [u8],
) -> Result<(), ()> {
    debug_assert!(output.len() + RISTRETTO_PUBLIC_LEN == ciphertext.len());

    // ECDH
    use keys::KexReusablePrivate;
    let B = RistrettoPublic::try_from(&ciphertext[0..RISTRETTO_PUBLIC_LEN]).map_err(|_| ())?;
    let shared_secret = key.key_exchange(&B);

    // Copy ciphertext to place where plaintext will go
    let dst = &mut output[..];
    dst.clone_from_slice(&ciphertext[RISTRETTO_PUBLIC_LEN..]);

    // KDF + AES
    common_part_with_salt(shared_secret.as_ref(), hkdf_salt, dst);

    Ok(())
}

// Symmetric part, common to encrypt and decrypt
// Factored out to avoid duplication
//
// This includes both the KDF step and the AES step
//
// Arguments:
// shared_secret: The DH shared secret bytes
// hkdf_salt: The 32 byte salt to use with hkdf
// data: The mutable data buffer to which we will apply the aes cipher
//
#[inline]
fn common_part_with_salt(shared_secret: &[u8; 32], hkdf_salt: &[u8; 32], data: &mut [u8]) {
    // KDF
    let (_, hk) = Hkdf::<Sha256>::extract(None, shared_secret);
    let mut key = [0u8; 32];
    hk.expand(hkdf_salt, &mut key).unwrap(); // This can never fail as 32 bytes is a valid amount of data that Sha256 can output

    // AES
    let nonce = [0u8; 16]; // 16 because using ctr128
    let aes_key = GenericArray::from_slice(&key);
    let aes_nonce = GenericArray::from_slice(&nonce);
    let mut cipher = Aes256Ctr::new(&aes_key, &aes_nonce);
    cipher.apply_keystream(data);
}

// DEFAULT_HKDF_SALT:
// Using a salt with hkdf is optional, see discussion at
// https://tools.ietf.org/html/rfc5869 Sec 3.1 for discussion
// I chose these using random.org, for the case when the user cannot provide one
pub const DEFAULT_HKDF_SALT: [u8; 32] = [
    21, 67, 69, 69, 93, 127, 39, 5, 45, 76, 45, 193, 107, 91, 70, 182, 44, 43, 174, 32, 88, 22,
    190, 170, 242, 187, 148, 63, 195, 2, 164, 188,
];

#[cfg(test)]
mod test {
    use super::*;
    use keys::FromRandom;

    #[test]
    fn test_round_trip() {
        let plaintext1 = b"01234567".to_vec();
        let plaintext2 = plaintext1.repeat(50);

        test_helper::run_with_several_seeds(|mut rng| {
            let a = RistrettoPrivate::from_random(&mut rng);
            let A = RistrettoPublic::from(&a);

            for plaintext in &[&plaintext1[..], &plaintext2[..]] {
                for _reps in 0..50 {
                    let ciphertext = encrypt(&mut rng, &A, plaintext);
                    let decrypted = decrypt(&a, &ciphertext).expect("decryption failed!");
                    assert_eq!(plaintext.len(), decrypted.len());
                    assert_eq!(plaintext, &&decrypted[..]);
                }
            }
        });
    }

    #[test]
    fn test_expected_failure() {
        let plaintext1 = b"01234567".to_vec();
        let plaintext2 = plaintext1.repeat(50);

        test_helper::run_with_several_seeds(|mut rng| {
            let a = RistrettoPrivate::from_random(&mut rng);
            let A = RistrettoPublic::from(&a);

            let not_a = RistrettoPrivate::from_random(&mut rng);

            for plaintext in &[&plaintext1[..], &plaintext2[..]] {
                for _reps in 0..50 {
                    let ciphertext = encrypt(&mut rng, &A, plaintext);
                    let decrypted = decrypt(&not_a, &ciphertext).expect("decryption failed!");
                    assert_eq!(plaintext.len(), decrypted.len());
                    assert_ne!(plaintext, &&decrypted[..]);
                }
            }
        });
    }
}
