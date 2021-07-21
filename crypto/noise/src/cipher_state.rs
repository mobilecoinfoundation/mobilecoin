// Copyright (c) 2018-2021 The MobileCoin Foundation

//! The Noise Protocol CipherState

use alloc::vec;

use aead::{AeadMut, Error as AeadError, NewAead, Payload};
use aes_gcm::Aes256Gcm;
use alloc::vec::Vec;
use core::cmp::min;
use displaydoc::Display;
use generic_array::{typenum::Unsigned, GenericArray};
use secrecy::{ExposeSecret, SecretVec};
use serde::{Deserialize, Serialize};

#[derive(
    Copy, Clone, Debug, Deserialize, Display, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize,
)]
pub enum CipherError {
    /// Key is the wrong length
    KeyLength,
    /// Nonce rollover or too many bytes encrypted
    ReKeyNeeded,
    /// The chosen cipher does not support re-keying
    ReKeyNotSupported,
    /// Rekey attempted when no key was set
    NoKey,
    /// Authenticated encryption error
    Aead,
}

impl From<AeadError> for CipherError {
    fn from(_src: AeadError) -> CipherError {
        CipherError::Aead
    }
}

/// A trait to handle cipher-specific weirdness in the noise framework.
///
/// Specifically, this trait and `aead::AeadMut` should cover the requirements
/// of [section 4.2](http://noiseprotocol.org/noise.html#cipher-functions) of
/// the spec.
pub trait NoiseCipher: AeadMut + NewAead + Sized {
    /// Generic re-keying method, will be called by NoiseCipher implementations
    /// for legit ciphers.
    ///
    /// This is the `REKEY(k)` cipher function from the specification, modified
    /// to support ciphers with alternate keys.
    fn rekey(&mut self) -> Result<Self, CipherError> {
        let nonce = Self::nonce_to_arr(core::u64::MAX);
        let msg = vec![0u8; Self::KeySize::to_usize()];
        let key = SecretVec::new(self.encrypt(
            &nonce,
            Payload {
                msg: &msg[..],
                aad: &[],
            },
        )?);
        let keyslice = key.expose_secret().as_slice();
        Ok(Self::new(&GenericArray::clone_from_slice(
            &keyslice[..Self::KeySize::to_usize()],
        )))
    }

    /// This method is an extension to the noise framework in order to support
    /// additional AEAD ciphers, which do not necessarily have a fixed overhead.
    ///
    /// The default implementation provided here will do the normal fixed-
    /// overhead modes, however.
    fn ciphertext_len(plaintext_len: usize) -> usize {
        plaintext_len + Self::CiphertextOverhead::to_usize() + Self::TagSize::to_usize()
    }

    /// Generate a nonce byte structure for this cipher. Cipher-specific
    /// implementations may override this to specify a different encoding.
    ///
    /// This deviates from in that `NonceSize` is generic, so ciphers with
    /// nonces other than 96-bits are able to be used within this
    /// implementation.
    ///
    /// The default implementation will create a byte array from the bytes
    /// of the given nonce, in big-ending encoding.
    fn nonce_to_arr(nonce: u64) -> GenericArray<u8, Self::NonceSize> {
        Self::nonce_bytes_to_arr(&nonce.to_be_bytes()[..])
    }

    /// Helper method to convert a slice of nonce bytes into an array of the
    /// proper size, in the noise style.
    ///
    /// The idea is that implementations which do not encode their nonce as
    /// big-ending bytes (e.g. ChaChaPoly) will do something like this to
    /// encode of their nonce counter as a properly sized array:
    ///
    /// ```ignore
    /// impl NoiseCipher for MyCipher {
    ///     fn nonce_to_arr(nonce: u64) -> GenericArray<u8, Self::NonceSize> {
    ///         Self::nonce_bytes_to_arr(&self.nonce.to_le_bytes()[..])
    ///     }
    /// }
    /// ```
    fn nonce_bytes_to_arr(nonce_bytes: &[u8]) -> GenericArray<u8, Self::NonceSize> {
        let mut retval = GenericArray::default();
        let nonce_len = retval.len();
        if nonce_len > 0 {
            let nonce_slice = retval.as_mut_slice();
            let overlap = min(nonce_len, nonce_bytes.len());
            nonce_slice[(nonce_len - overlap)..].copy_from_slice(&nonce_bytes[..overlap]);
        }

        retval
    }
}

impl NoiseCipher for Aes256Gcm {}

/// The Noise Protocol CipherState object, modified to support AEADs with
/// differing key/nonce lengths.
///
/// This is defined by [section 5.1](http://noiseprotocol.org/noise.html#the-cipherstate-object)
/// of the specification.
pub struct CipherState<Cipher: AeadMut + NewAead + Sized + NoiseCipher> {
    cipher: Option<Cipher>,
    nonce: u64,
    bytes_sent: u64,
}

impl<Cipher: AeadMut + NewAead + Sized + NoiseCipher> CipherState<Cipher> {
    /// The noise protocol `InitializeKey(k)` operation.
    ///
    /// This will reset the internal key, create a new AEAD cipher instance,
    /// and reset the nonce and byte counters to zero.
    pub fn initialize_key(&mut self, key: Option<Vec<u8>>) -> Result<(), CipherError> {
        match key {
            Some(key) => {
                let key = SecretVec::new(key);
                let key_slice = key.expose_secret().as_slice();
                if key_slice.len() != Cipher::KeySize::to_usize() {
                    return Err(CipherError::KeyLength);
                }
                self.cipher = Some(Cipher::new(&GenericArray::clone_from_slice(key_slice)));
            }
            None => {
                self.cipher = None;
            }
        }
        self.nonce = 0;
        self.bytes_sent = 0;
        Ok(())
    }

    /// The noise protocol `HasKey()` operation.
    ///
    /// This will return whether a key has been set via intialize_key() or not.
    pub fn has_key(&self) -> bool {
        self.cipher.is_some()
    }

    /// The noise protocol `SetNonce()` operation.
    ///
    /// This will irrevocably override the current nonce value.
    pub fn set_nonce(&mut self, nonce: u64) {
        self.nonce = nonce;
        // TODO: return current nonce? We don't provide any access otherwise...
    }

    /// The noise protocol `EncryptWithAd()` operation.
    ///
    /// Will return an error if the nonce would repeat, more than 2^56 bytes
    /// have been encrypted with the given cipher, or the underlying AEAD
    /// implementation returned an error.
    pub fn encrypt_with_ad(&mut self, aad: &[u8], msg: &[u8]) -> Result<Vec<u8>, CipherError> {
        let msg_len = msg.len() as u64;
        if self.nonce == core::u64::MAX || self.bytes_sent + msg_len > 72_057_594_037_927_940 {
            return Err(CipherError::ReKeyNeeded);
        }

        // According to the spec, if the key is empty, this should return a
        // copy of the plaintext as the ciphertext. I get the point of this,
        // but a method called "encrypt()" that decides whether it should
        // actually encrypt based on side effects should scare you.
        //
        // Instead, we're going to throw an error, which means the caller that
        // wants to send plaintext anyways needs to catch it and override.
        // Nobody lets you add a NULL cipher to a config for a reason,
        // folks.
        if let Some(cipher) = &mut self.cipher {
            let nonce = Cipher::nonce_to_arr(self.nonce);
            let retval = cipher.encrypt(&nonce, Payload { msg, aad })?;
            self.bytes_sent += msg_len;
            self.nonce += 1;
            Ok(retval)
        } else {
            Err(CipherError::NoKey)
        }
    }

    /// The noise protocol `DecryptWithAd()` operation.
    ///
    /// Will return an error if the nonce would repeat, more than 2^56 bytes
    /// have been encrypted with the given cipher, or the underlying AEAD
    /// implementation returned an error.
    pub fn decrypt_with_ad(&mut self, aad: &[u8], msg: &[u8]) -> Result<Vec<u8>, CipherError> {
        if self.nonce == core::u64::MAX {
            return Err(CipherError::ReKeyNeeded);
        }

        // See corresponding comment in encrypt_with_ad()
        if let Some(cipher) = &mut self.cipher {
            let nonce = Cipher::nonce_to_arr(self.nonce);
            let retval = cipher.decrypt(&nonce, Payload { msg, aad })?;

            // This is a little weird down here, but it indicates the far side
            // encrypted some data it shouldn't have...
            if self.bytes_sent + retval.len() as u64 > 72_057_594_037_927_940 {
                return Err(CipherError::ReKeyNeeded);
            }

            self.bytes_sent += retval.len() as u64;
            self.nonce += 1;
            Ok(retval)
        } else {
            Err(CipherError::NoKey)
        }
    }

    /// If the underlying cipher supports inline re-keying, generate a new key
    /// by encrypting zeroes with our current cipher and the "last" nonce value
    /// available.
    ///
    /// This is not specifically called out by the framework, but re-keying
    /// over a null key must result in an error, otherwise the new key could
    /// be pre-calculated.
    pub fn rekey(&mut self) -> Result<(), CipherError> {
        if let Some(cipher) = &mut self.cipher {
            self.cipher = Some((*cipher).rekey()?);
            self.bytes_sent = 0;
            Ok(())
        } else {
            Err(CipherError::NoKey)
        }
    }
}

/// Initialize a new `CipherState` with no existing data.
impl<Cipher: AeadMut + NewAead + Sized + NoiseCipher> Default for CipherState<Cipher> {
    fn default() -> Self {
        Self {
            cipher: None,
            nonce: 0,
            bytes_sent: 0,
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn default() {
        let cipher = CipherState::<Aes256Gcm>::default();
        assert!(!cipher.has_key());
        assert_eq!(cipher.nonce, 0);
        assert_eq!(cipher.bytes_sent, 0);
    }

    #[test]
    fn initialize_key() {
        let mut cipher = CipherState::<Aes256Gcm>::default();
        let key = vec![0u8; <Aes256Gcm as NewAead>::KeySize::to_usize()];

        cipher
            .initialize_key(Some(key))
            .expect("Could not initialize key");
        assert!(cipher.has_key());
        assert_eq!(cipher.nonce, 0);
        assert_eq!(cipher.bytes_sent, 0);
    }

    #[test]
    #[should_panic(expected = "KeyLength")]
    fn bad_initialize_key() {
        let mut cipher = CipherState::<Aes256Gcm>::default();
        let key = vec![0u8; <Aes256Gcm as NewAead>::KeySize::to_usize() - 1];

        cipher
            .initialize_key(Some(key))
            .expect("Could not intialize key");
    }

    #[test]
    #[should_panic(expected = "Could not encrypt: NoKey")]
    fn dont_encrypt_decrypt() {
        let mut encryptor = CipherState::<Aes256Gcm>::default();
        let key = vec![0u8; <Aes256Gcm as NewAead>::KeySize::to_usize()];

        let ciphertext = encryptor
            .encrypt_with_ad(&[], &key)
            .expect("Could not encrypt");

        assert_eq!(key, ciphertext);
        assert_eq!(encryptor.nonce, 0);
        assert_eq!(encryptor.bytes_sent, 0);

        let mut decryptor = CipherState::<Aes256Gcm>::default();
        let plaintext = decryptor
            .decrypt_with_ad(&[], &ciphertext)
            .expect("Could not decrypt");

        assert_eq!(plaintext, key);
        assert_eq!(decryptor.nonce, 0);
        assert_eq!(decryptor.bytes_sent, 0);
    }

    #[test]
    /// When a CipherState has been initialized with a key, encrypt and
    /// decrypt really do stuff.
    fn encrypt_decrypt() {
        let mut encryptor = CipherState::<Aes256Gcm>::default();
        let mut decryptor = CipherState::<Aes256Gcm>::default();
        let key = vec![0u8; <Aes256Gcm as NewAead>::KeySize::to_usize()];

        encryptor
            .initialize_key(Some(key.clone()))
            .expect("Could not initialize encryptor key");
        decryptor
            .initialize_key(Some(key.clone()))
            .expect("Could not initialize decryptor key");

        let ciphertext = encryptor
            .encrypt_with_ad(&[], &key)
            .expect("Could not encrypt");

        assert_ne!(key, ciphertext);
        assert_eq!(encryptor.nonce, 1);
        assert_eq!(encryptor.bytes_sent, key.len() as u64);

        let plaintext = decryptor
            .decrypt_with_ad(&[], &ciphertext)
            .expect("Could not decrypt");

        assert_eq!(plaintext, key);
        assert_eq!(decryptor.nonce, 1);
        assert_eq!(decryptor.bytes_sent, key.len() as u64);
    }

    #[test]
    #[should_panic(expected = "Could not encrypt without key: NoKey")]
    fn remove_key() {
        let mut encryptor = CipherState::<Aes256Gcm>::default();
        let key = vec![0u8; <Aes256Gcm as NewAead>::KeySize::to_usize()];

        encryptor
            .initialize_key(Some(key.clone()))
            .expect("Could not initialize encryptor key");
        let ciphertext = encryptor
            .encrypt_with_ad(&[], &key)
            .expect("Could not encrypt");

        assert_ne!(key, ciphertext);
        assert_eq!(encryptor.nonce, 1);
        assert_eq!(encryptor.bytes_sent, key.len() as u64);

        encryptor
            .initialize_key(None)
            .expect("Could not de-initialize key");

        let ciphertext2 = encryptor
            .encrypt_with_ad(&[], &key)
            .expect("Could not encrypt without key");

        assert!(!encryptor.has_key());
        assert_eq!(key, ciphertext2);
        assert_eq!(encryptor.nonce, 0);
        assert_eq!(encryptor.bytes_sent, 0);
    }

    #[test]
    /// Try to use the rekey method
    fn rekey() {
        let mut encryptor = CipherState::<Aes256Gcm>::default();
        let key = vec![0u8; <Aes256Gcm as NewAead>::KeySize::to_usize()];

        encryptor
            .initialize_key(Some(key.clone()))
            .expect("Could not initialize encryptor key");
        let ciphertext = encryptor
            .encrypt_with_ad(&[], &key)
            .expect("Could not encrypt");

        assert_ne!(key, ciphertext);
        encryptor.rekey().expect("Could not re-key encryptor");

        let ciphertext2 = encryptor
            .encrypt_with_ad(&[], &key)
            .expect("Could not encrypt with new key");

        assert_ne!(ciphertext, ciphertext2);

        assert_eq!(encryptor.nonce, 2);
        assert_eq!(encryptor.bytes_sent, key.len() as u64);
    }
}
