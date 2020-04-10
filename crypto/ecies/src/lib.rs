// Copyright (c) 2018-2020 MobileCoin Inc.

#![no_std]

//! This crate implements ECIES cryptosystem:
//! - Ristretto Curvepoints used for ECDH
//! - HKDF<Blake2b> used to extract key material from dh_shared_secret
//! - Aes-128-Gcm used to encrypt and mac the payload

extern crate alloc;
use alloc::{vec, vec::Vec};

#[cfg(test)]
extern crate test_helper;

use aead::{
    generic_array::{
        sequence::{Concat, Split},
        typenum::{Sum, Unsigned, U12, U16, U32},
        GenericArray,
    },
    Aead, NewAead,
};
use aes_gcm::Aes128Gcm;
use blake2::Blake2b;
use core::convert::TryFrom;
use failure::Fail;
use hkdf::Hkdf;
use keys::{
    CompressedRistrettoPublic, KeyError, RistrettoPrivate, RistrettoPublic, RISTRETTO_PUBLIC_LEN,
};
use rand_core::{CryptoRng, RngCore};

/// The amount of bytes by which the cipher text is longer then plaintext.
/// This is a constant, the sum of:
/// - a compressed ristretto curve point (32 bytes)
/// - an aes-128-gcm mac (16 bytes)
/// Users of ecies crate can use this constant to future-proof against changes in ECIES crate.
pub const ECIES_EXTRA_SPACE: usize = ECIESExtraSpaceLen::USIZE;
pub type ECIESExtraSpaceLen = Sum<RistrettoLen, AesMacLen>;
pub type ECIESExtraSpace = GenericArray<u8, ECIESExtraSpaceLen>;

type RistrettoLen = U32;
type AesMacLen = <Aes128Gcm as Aead>::TagSize;

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
    let mut result = vec![0u8; ECIES_EXTRA_SPACE + plaintext.len()];
    encrypt_into(rng, key, plaintext, &mut result);
    result
}

/// encrypt_into
/// Same as encrypt, but cannot fail, and doesn't make an allocation.
/// The output buffer MUST be exactly ECIES_EXTRA_BYTES bytes longer than input buffer.
/// The header returned from encrypt_in_place_detached will be placed at the
/// front of the output buffer.
///
/// # Arguments
/// * rng: Rng to use for encryption operation
/// * key: Public key to encrypt against
/// * plaintext: The message to be encrypted
/// * output: The output buffer, which must have the right length.
///
/// Preconditions: The output buffer is EXACTLY ECIES_EXTRA_SPACE bytes longer
/// than plaintext.
pub fn encrypt_into<T: RngCore + CryptoRng>(
    rng: &mut T,
    key: &RistrettoPublic,
    plaintext: &[u8],
    output: &mut [u8],
) {
    debug_assert!(plaintext.len() + ECIES_EXTRA_SPACE == output.len(), "Precondition failed: The output buffer must be ECIES_EXTRA_SPACE bytes longer than input buffer");
    // Copy plaintext to place where ciphertext will go, leaving gap for header
    let dst = &mut output[ECIES_EXTRA_SPACE..];
    dst.copy_from_slice(plaintext);

    // Encrypt
    let header = encrypt_in_place_detached(rng, key, dst);

    // Put the header before the ciphertext
    output[0..ECIES_EXTRA_SPACE].copy_from_slice(header.as_slice());
}

/// encrypt_in_place_detached
///
/// This API mirrors the aead trait: `aead::encrypt_in_place_detached`.
/// Takes the plaintext buffer as a mutable argument, and transforms it in-place
/// into the ciphertext, returning the "header".
/// The header contains the additional information needed to verify and decrypt the
/// ciphertext.
///
/// The tag includes both the ephemeral public key for the ciphertext, and the
/// mac value. The tag has length exactly ECIES_EXTRA_BYTES.
///
/// # Arguments
/// * rng: Rng to use for encryption operation
/// * key: Public key to encrypt against
/// * buffer: The buffer which will be encrypted in-place
///
/// # Returns
/// * The "header" containing the additional information needed to decrypt.
///
pub fn encrypt_in_place_detached<T: RngCore + CryptoRng>(
    rng: &mut T,
    key: &RistrettoPublic,
    buffer: &mut [u8],
) -> ECIESExtraSpace {
    // ECDH
    use keys::KexPublic;
    let (our_public, shared_secret) = key.new_secret(rng);

    let compressed_public = CompressedRistrettoPublic::from(our_public);
    let curve_point_bytes =
        GenericArray::<u8, RistrettoLen>::clone_from_slice(compressed_public.as_ref());

    // KDF
    let (aes_key, aes_nonce) = kdf_step(shared_secret.as_ref());

    // AES
    let aead = Aes128Gcm::new(aes_key);
    let mac = aead
        .encrypt_in_place_detached(&aes_nonce, &[], buffer)
        .expect("Buffer size calculation was wrong, fix math and rebuild");

    // Header is curve_point_bytes || aes_mac_bytes
    curve_point_bytes.concat(mac)
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
/// Decryption can fail if:
/// - The ciphertext is too short (< ECIES_EXTRA_SPACE)
/// - The curvepoint cannot be deserialized
/// - The mac check fails
pub fn decrypt(key: &RistrettoPrivate, ciphertext: &[u8]) -> Result<Vec<u8>, Error> {
    if ciphertext.len() < ECIES_EXTRA_SPACE {
        return Err(Error::TooShort(ciphertext.len()));
    }

    let mut result = vec![0u8; ciphertext.len() - ECIES_EXTRA_SPACE];
    decrypt_into(key, ciphertext, &mut result)?;
    Ok(result)
}

/// decrypt_into
/// Counterpart to encrypt_into
/// Output buffer must be exactly ECIES_EXTRA_SPACE bytes smaller than ciphertext buffer
/// The first ECIES_EXTRA_SPACE bytes must be the header (same format as encrypt_into)
///
/// # Arguments
/// * key: Private key (dalek Scalar) to decrypt with
/// * ciphertext: The encrypted payload to decipher
/// * output: Where to place the plaintext
///
/// # Returns
/// * Ok on success, Err if decryption failed
///
/// Decryption can fail if:
/// - The curvepoint cannot be deserialized
/// - The mac check fails
///
/// Preconditions: The output buffer is EXACTLY ECIES_EXTRA_SPACE bytes smaller
/// than ciphertext.
pub fn decrypt_into(
    key: &RistrettoPrivate,
    ciphertext: &[u8],
    output: &mut [u8],
) -> Result<(), Error> {
    // Extract the header from front of ciphertext, doing bounds checks
    if ciphertext.len() < ECIES_EXTRA_SPACE {
        return Err(Error::TooShort(ciphertext.len()));
    }
    let header = ECIESExtraSpace::from_slice(&ciphertext[..ECIES_EXTRA_SPACE]);

    // Copy ciphertext to place where plaintext will go
    debug_assert!(output.len() + ECIES_EXTRA_SPACE == ciphertext.len(), "Precondition failed: The output length must be exactly ECIES_EXTRA_SPACE bytes less than the input length");
    let dst = &mut output[..];
    dst.clone_from_slice(&ciphertext[ECIES_EXTRA_SPACE..]);

    // Call to detached form
    decrypt_in_place_detached(key, header, output)
}

/// decrypt_in_place_detached
///
/// This API mirrors the aead trait: `aead::decrypt_in_place_detached`.
/// The "header" bytes are consumed separately from the ciphertext buffer, which
/// is mutated in-place, producing the plaintext.
///
/// # Arguments
/// * key: private key to decrypt with
/// * header: The header produced by encrypt_in_place_detached
/// * buffer: The buffer which will be decrypted in place
///
/// # Returns
/// * Ok on success, Err if decryption failed
///
/// Decryption can fail if:
/// - The curvepoint cannot be deserialized
/// - The mac check fails
pub fn decrypt_in_place_detached(
    key: &RistrettoPrivate,
    header: &ECIESExtraSpace,
    buffer: &mut [u8],
) -> Result<(), Error> {
    // ECDH
    use keys::KexReusablePrivate;
    let public_key =
        RistrettoPublic::try_from(&header[..RISTRETTO_PUBLIC_LEN]).map_err(Error::Key)?;
    let shared_secret = key.key_exchange(&public_key);

    // KDF
    let (aes_key, aes_nonce) = kdf_step(shared_secret.as_ref());

    // AES
    let mac_ref = <&GenericArray<u8, AesMacLen>>::from(&header[RISTRETTO_PUBLIC_LEN..]);
    let aead = Aes128Gcm::new(aes_key);
    aead.decrypt_in_place_detached(&aes_nonce, &[], buffer, mac_ref)
        .map_err(|_| Error::MacFailed)?;

    Ok(())
}

/// KDF part, factored out to avoid duplication
/// This part must produce the key and IV/nonce for aes-gcm
/// Blake2b produces 64 bytes of private key material which is more than we need,
/// so we don't do the HKDF-EXPAND step.
fn kdf_step(dh_shared_secret: &[u8; 32]) -> (GenericArray<u8, U16>, GenericArray<u8, U12>) {
    let (prk, _) = Hkdf::<Blake2b>::extract(Some(b"ecies"), dh_shared_secret);
    // Split the prk into a 16 byte and a 12 byte piece
    let (sixteen, remainder): (GenericArray<u8, U16>, _) = prk.split();
    let (twelve, _): (GenericArray<u8, U12>, _) = remainder.split();
    (sixteen, twelve)
}

/// Error type for decyrption
#[derive(PartialEq, Eq, Fail, Debug)]
pub enum Error {
    #[fail(display = "Error decoding curvepoint: {}", _0)]
    Key(KeyError),
    #[fail(display = "Too short to be a ciphertext: {}", _0)]
    TooShort(usize),
    #[fail(display = "Mac failed")]
    MacFailed,
}

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
            let a_pub = RistrettoPublic::from(&a);

            for plaintext in &[&plaintext1[..], &plaintext2[..]] {
                for _reps in 0..50 {
                    let ciphertext = encrypt(&mut rng, &a_pub, plaintext);
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
            let a_pub = RistrettoPublic::from(&a);

            let not_a = RistrettoPrivate::from_random(&mut rng);

            for plaintext in &[&plaintext1[..], &plaintext2[..]] {
                for _reps in 0..50 {
                    let ciphertext = encrypt(&mut rng, &a_pub, plaintext);
                    let decrypted = decrypt(&not_a, &ciphertext);
                    assert!(decrypted.is_err());
                    assert_eq!(decrypted, Err(Error::MacFailed));
                }
            }
        });
    }
}
