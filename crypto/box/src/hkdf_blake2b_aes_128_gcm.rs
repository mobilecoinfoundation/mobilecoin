use crate::traits::{CryptoBox, Error};

use aead::{
    generic_array::{
        sequence::{Concat, Split},
        typenum::{Sum, U12, U16, U32},
        GenericArray,
    },
    Aead, Error as AeadError, NewAead,
};
use aes_gcm::Aes128Gcm;
use blake2::Blake2b;
use core::convert::TryFrom;
use hkdf::Hkdf;
use keys::{CompressedRistrettoPublic, RistrettoPrivate, RistrettoPublic, RISTRETTO_PUBLIC_LEN};
use rand_core::{CryptoRng, RngCore};

type RistrettoLen = U32;
type AesMacLen = <Aes128Gcm as Aead>::TagSize;

/// Represents an implementation of Ristretto-Box using Hkdf<Blake2b> and Aes128Gcm
///
/// This structure contains the actual cryptographic primitive details, and
/// specifies part of the wire format of the "footer" where the ephemeral
/// public key comes first, and the mac comes second.
#[derive(Default)]
pub struct RistrettoHkdfBlake2bAes128Gcm {}

impl CryptoBox for RistrettoHkdfBlake2bAes128Gcm {
    type FooterSize = Sum<RistrettoLen, AesMacLen>;

    fn encrypt_in_place_detached<T: RngCore + CryptoRng>(
        &self,
        rng: &mut T,
        key: &RistrettoPublic,
        buffer: &mut [u8],
    ) -> Result<GenericArray<u8, Self::FooterSize>, AeadError> {
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
        let mac = aead.encrypt_in_place_detached(&aes_nonce, &[], buffer)?;

        // Tag is curve_point_bytes || aes_mac_bytes
        Ok(curve_point_bytes.concat(mac))
    }

    fn decrypt_in_place_detached(
        &self,
        key: &RistrettoPrivate,
        tag: &GenericArray<u8, Self::FooterSize>,
        buffer: &mut [u8],
    ) -> Result<(), Error> {
        // ECDH
        use keys::KexReusablePrivate;
        let public_key =
            RistrettoPublic::try_from(&tag[..RISTRETTO_PUBLIC_LEN]).map_err(Error::Key)?;
        let shared_secret = key.key_exchange(&public_key);

        // KDF
        let (aes_key, aes_nonce) = kdf_step(shared_secret.as_ref());

        // AES
        let mac_ref = <&GenericArray<u8, AesMacLen>>::from(&tag[RISTRETTO_PUBLIC_LEN..]);
        let aead = Aes128Gcm::new(aes_key);
        aead.decrypt_in_place_detached(&aes_nonce, &[], buffer, mac_ref)
            .map_err(|_| Error::MacFailed)?;

        Ok(())
    }
}

/// KDF part, factored out to avoid duplication
/// This part must produce the key and IV/nonce for aes-gcm
/// Blake2b produces 64 bytes of private key material which is more than we need,
/// so we don't do the HKDF-EXPAND step.
fn kdf_step(dh_shared_secret: &[u8; 32]) -> (GenericArray<u8, U16>, GenericArray<u8, U12>) {
    let (prk, _) = Hkdf::<Blake2b>::extract(Some(b"dei-salty-box"), dh_shared_secret);
    // Split the prk into a 16 byte and a 12 byte piece
    let (sixteen, remainder): (GenericArray<u8, U16>, _) = prk.split();
    let (twelve, _): (GenericArray<u8, U12>, _) = remainder.split();
    (sixteen, twelve)
}

#[cfg(test)]
mod test {
    use super::*;
    use mc_util_from_random::FromRandom;

    extern crate test_helper;

    #[test]
    fn test_round_trip() {
        let algo = RistrettoHkdfBlake2bAes128Gcm::default();
        let plaintext1 = b"01234567".to_vec();
        let plaintext2 = plaintext1.repeat(50);

        test_helper::run_with_several_seeds(|mut rng| {
            let a = RistrettoPrivate::from_random(&mut rng);
            let a_pub = RistrettoPublic::from(&a);

            for plaintext in &[&plaintext1[..], &plaintext2[..]] {
                for _reps in 0..50 {
                    let ciphertext = algo.encrypt(&mut rng, &a_pub, plaintext).unwrap();
                    let decrypted = algo.decrypt(&a, &ciphertext).expect("decryption failed!");
                    assert_eq!(plaintext.len(), decrypted.len());
                    assert_eq!(plaintext, &&decrypted[..]);
                }
            }
        });
    }

    #[test]
    fn test_expected_failure() {
        let algo = RistrettoHkdfBlake2bAes128Gcm::default();
        let plaintext1 = b"01234567".to_vec();
        let plaintext2 = plaintext1.repeat(50);

        test_helper::run_with_several_seeds(|mut rng| {
            let a = RistrettoPrivate::from_random(&mut rng);
            let a_pub = RistrettoPublic::from(&a);

            let not_a = RistrettoPrivate::from_random(&mut rng);

            for plaintext in &[&plaintext1[..], &plaintext2[..]] {
                for _reps in 0..50 {
                    let ciphertext = algo.encrypt(&mut rng, &a_pub, plaintext).unwrap();
                    let decrypted = algo.decrypt(&not_a, &ciphertext);
                    assert!(decrypted.is_err());
                    assert_eq!(decrypted, Err(Error::MacFailed));
                }
            }
        });
    }
}
