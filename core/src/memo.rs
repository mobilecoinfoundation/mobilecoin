//! Memo types, signing and encryption helpers

use aes::{
    cipher::{FromBlockCipher, StreamCipher},
    Aes256, Aes256Ctr, NewBlockCipher,
};
use generic_array::{
    sequence::Split,
    typenum::{U32, U48},
    GenericArray,
};
use hkdf::Hkdf;
use sha2::Sha512;

use mc_core_types::{
    keys::{
        SubaddressSpendPrivate, SubaddressSpendPublic, SubaddressViewPrivate, SubaddressViewPublic,
    },
};
use mc_crypto_keys::{
    CompressedRistrettoPublic, KexReusablePrivate, RistrettoPrivate, RistrettoPublic,
    RistrettoSecret,
};
use mc_crypto_memo_mac::compute_category1_hmac;

pub use mc_core_types::memo::Hmac;

/// Memo helper / marker type
#[derive(Copy, Clone, PartialEq, Debug)]
pub struct Memo;

impl Memo {
    /// Encrypt a cleartext memo payload
    pub fn encrypt(
        sender_default_spend_private: &SubaddressSpendPrivate,
        receiver_view_public: &SubaddressViewPublic,
        payload: &mut [u8; 66],
    ) {
        // Perform KX against receiver subaddress view pubic key
        let shared_secret = shared_secret(sender_default_spend_private, receiver_view_public);

        // Apply encryption
        Self::apply_keystream(&shared_secret, &mut payload[..]);
    }

    /// Decrypt an encrypted memo payload
    pub fn decrypt(
        sender_default_spend_public: &SubaddressSpendPublic,
        receiver_view_private: &SubaddressViewPrivate,
        payload: &mut [u8; 66],
    ) {
        // Perform KX against sender subaddress spend public key
        let shared_secret = shared_secret(receiver_view_private, sender_default_spend_public);

        // Apply decryption
        Self::apply_keystream(&shared_secret, &mut payload[..]);
    }

    /// Compute HMAC for an incoming memo body
    pub fn hmac_check(
        tx_out_public_key: &RistrettoPublic,
        sender_default_spend_public: &SubaddressSpendPublic,
        receiver_view_private: &SubaddressViewPrivate,
        kind: [u8; 2],
        data: &[u8; 48],
    ) -> Hmac {
        // Compute shared secret
        let shared_secret = shared_secret(receiver_view_private, sender_default_spend_public);

        // Compute HMAC for memo data
        let hmac_value = compute_category1_hmac(
            shared_secret.as_ref(),
            &CompressedRistrettoPublic::from(tx_out_public_key),
            kind,
            &data,
        );

        Hmac(hmac_value)
    }

    /// Compute HMAC for an outgoing memo body
    pub fn hmac_sign(
        tx_out_public_key: &RistrettoPublic,
        sender_default_spend_private: &SubaddressSpendPrivate,
        receiver_view_public: &SubaddressViewPublic,
        kind: [u8; 2],
        data: &[u8; 48],
    ) -> Hmac {
        // Compute shared secret
        let shared_secret = shared_secret(sender_default_spend_private, receiver_view_public);

        // Compute HMAC for memo data
        let hmac_value = compute_category1_hmac(
            shared_secret.as_ref(),
            &CompressedRistrettoPublic::from(tx_out_public_key),
            kind,
            &data,
        );

        Hmac(hmac_value)
    }

    /// Apply AES256 keystream to the provided memo buffer
    pub fn apply_keystream(shared_secret: impl AsRef<[u8]>, buff: &mut [u8]) -> () {
        // Use HKDF-SHA512 to produce an AES key and AES nonce
        let kdf = Hkdf::<Sha512>::new(Some(b"mc-memo-okm"), shared_secret.as_ref());

        // OKM is "output key material", see RFC HKDF for discussion of terms
        let mut okm = GenericArray::<u8, U48>::default();
        kdf.expand(b"", &mut okm[..])
            .expect("Digest output size is insufficient");

        let (key, nonce) = Split::<u8, U32>::split(okm);

        // Apply AES-256 in counter mode to the buffer
        let mut aes256ctr = Aes256Ctr::from_block_cipher(Aes256::new(&key), &nonce);
        aes256ctr.apply_keystream(buff);
    }
}

/// KX using sender default subaddress spend and receiver subaddress view keys
/// to determine shared secret for memo HMAC or encryption
pub fn shared_secret(
    private_key: impl AsRef<RistrettoPrivate>,
    public_key: impl AsRef<RistrettoPublic>,
) -> RistrettoSecret {
    let private_key: &RistrettoPrivate = private_key.as_ref();
    let shared_secret = private_key.key_exchange(public_key.as_ref());

    shared_secret
}

#[cfg(test)]
mod tests {
    use rand_core::{OsRng, RngCore};

    use mc_core_types::keys::*;
    use mc_crypto_keys::{RistrettoPrivate, RistrettoPublic};
    use mc_util_from_random::FromRandom;

    use super::{shared_secret, Memo};

    #[test]
    fn key_exchange() {
        // Setup keys
        let (pri1, pri2) = (
            SubaddressSpendPrivate::from(RistrettoPrivate::from_random(&mut OsRng {})),
            SubaddressViewPrivate::from(RistrettoPrivate::from_random(&mut OsRng {})),
        );
        let (pub1, pub2) = (
            SubaddressSpendPublic::from(&pri1),
            SubaddressViewPublic::from(&pri2),
        );

        let s1 = shared_secret(&pri1, &pub2);
        let s2 = shared_secret(&pri2, &pub1);

        let (s1, s2): (&[u8], &[u8]) = (s1.as_ref(), s2.as_ref());

        assert_eq!(&s1, &s2);
    }

    #[test]
    fn encrypt_decrypt() {
        // Setup keys
        let (pri1, pri2) = (
            SubaddressSpendPrivate::from(RistrettoPrivate::from_random(&mut OsRng {})),
            SubaddressViewPrivate::from(RistrettoPrivate::from_random(&mut OsRng {})),
        );
        let (pub1, pub2) = (
            SubaddressSpendPublic::from(&pri1),
            SubaddressViewPublic::from(&pri2),
        );

        let key1 = RistrettoPrivate::from_random(&mut OsRng {});

        let mut p1 = [0u8; 66];
        OsRng {}.try_fill_bytes(&mut p1[..]).unwrap();

        let mut e1 = p1.clone();
        Memo::encrypt(&pri1, &pub2, &mut e1);

        let mut d1 = e1.clone();
        Memo::decrypt(&pub1, &pri2, &mut d1);

        assert_eq!(p1, d1, "roundtrip failed");

        let mut d2 = e1.clone();
        Memo::decrypt(&pub1, &SubaddressViewPrivate::from(key1), &mut d2);

        assert_ne!(p1, d2, "decrypt with wrong key succeeded");
    }

    #[test]
    fn hmac() {
        // Setup keys
        let (pri1, pri2) = (
            SubaddressSpendPrivate::from(RistrettoPrivate::from_random(&mut OsRng {})),
            SubaddressViewPrivate::from(RistrettoPrivate::from_random(&mut OsRng {})),
        );
        let (pub1, pub2) = (
            SubaddressSpendPublic::from(&pri1),
            SubaddressViewPublic::from(&pri2),
        );

        let tx_out_public_key = RistrettoPublic::from_random(&mut OsRng {});

        let mut data = [0u8; 48];
        OsRng {}.fill_bytes(&mut data);

        // Generate correct sender/receiver HMAC
        let h1 = Memo::hmac_sign(&tx_out_public_key, &pri1, &pub2, [1, 2], &data);

        let h2 = Memo::hmac_check(&tx_out_public_key, &pub1, &pri2, [1, 2], &data);

        assert_eq!(h1, h2, "HMAC mismatch");

        // Check HMACs for different memos do not match

        let h3 = Memo::hmac_check(&tx_out_public_key, &pub1, &pri2, [1, 3], &data);
        assert_eq!(h3, h1, "hmac with wrong kind matched");

        let mut d1 = data.clone();
        d1[0] = !d1[0];
        let h4 = Memo::hmac_check(&tx_out_public_key, &pub1, &pri2, [1, 3], &d1);
        assert_ne!(h4, h1, "hmac with wrong data matched");
    }
}
