// Copyright (c) 2018-2021 The MobileCoin Foundation

/// Implement LocalCipher trait around an AesGcm object that does rekeying
use alloc::vec;
use alloc::vec::Vec;
use core::convert::TryInto;

use aes_gcm::aead::{AeadInPlace, NewAead};
use generic_array::{typenum, ArrayLength, GenericArray};
use rand_core::{CryptoRng, RngCore};
use subtle::Choice;
use typenum::Unsigned;

use crate::{CipherError, MessageCipher};

pub struct AeadMessageCipher<C: NewAead + AeadInPlace> {
    // ciphers is a list of ciphers, and the keys we used to make them
    ciphers: Vec<(C, GenericArray<u8, C::KeySize>)>,
    // nonce is the current nonce, starts from 0 every time we re-key.
    nonce: Nonce<C::NonceSize>,
}

impl<C: AeadInPlace + NewAead> MessageCipher for AeadMessageCipher<C> {
    fn new<T: CryptoRng + RngCore>(rng: &mut T) -> Self {
        let mut key: GenericArray<u8, C::KeySize> = Default::default();
        rng.fill_bytes(key.as_mut_slice());
        Self {
            ciphers: vec![(C::new(&key), key)],
            nonce: Nonce::new(),
        }
    }

    fn encrypt_bytes<R: RngCore + CryptoRng>(
        &mut self,
        rng: &mut R,
        plaintext: Vec<u8>,
    ) -> Vec<u8> {
        let mut result = plaintext;

        self.ciphers
            .last()
            .unwrap()
            .0
            .encrypt_in_place(self.nonce.as_bytes(), b"", &mut result)
            .expect("Encrypting into unbounded buffer should not fail");

        // Place the footer containing the key number and nonce
        let key_num: u64 = (self.ciphers.len() - 1) as u64;
        result.extend(&key_num.to_le_bytes());
        result.extend(self.nonce.as_bytes().as_slice());

        // Increment nonce and maybe rotate key
        self.nonce.inc();
        if self.nonce.is_max() {
            // need to get a new key and reset the nonce
            // Keep choosing random keys until we get a new one
            let key = {
                let mut key: GenericArray<u8, C::KeySize> = Default::default();

                loop {
                    rng.fill_bytes(key.as_mut_slice());

                    // Scan over all historical key bytes in constant time
                    let mut must_resample = Choice::from(0u8);
                    for (_, old_key) in self.ciphers.iter() {
                        use subtle::ConstantTimeEq;
                        must_resample |= old_key.as_slice().ct_eq(key.as_slice());
                    }
                    // If we don't have to resample then escape the loop
                    if must_resample.unwrap_u8() == 0 {
                        break;
                    }
                }

                key
            };
            self.ciphers.push((C::new(&key), key));
            self.nonce = Nonce::new();
        }

        result
    }

    fn decrypt_bytes(&mut self, ciphertext: Vec<u8>) -> Result<Vec<u8>, CipherError> {
        // The key_num is appended before the nonce, to form the footer.
        // These offsets are from the end of the ciphertext.
        let nonce_offset = C::NonceSize::to_usize();
        let key_num_offset = nonce_offset + core::mem::size_of::<u64>();

        if ciphertext.len() < key_num_offset {
            return Err(CipherError::TooShort);
        }
        let key_num = u64::from_le_bytes(
            (&ciphertext[ciphertext.len() - key_num_offset..ciphertext.len() - nonce_offset])
                .try_into()
                .unwrap(),
        );
        if key_num >= self.ciphers.len() as u64 {
            return Err(CipherError::UnknownKey);
        }
        let nonce = GenericArray::clone_from_slice(
            &ciphertext[ciphertext.len() - nonce_offset..ciphertext.len()],
        );

        // Remove the footer, then decrypt using AesGcm and the nonce
        let mut result = ciphertext;
        result.truncate(result.len() - key_num_offset);
        self.ciphers[key_num as usize]
            .0
            .decrypt_in_place(&nonce, b"", &mut result)
            .map_err(|_| CipherError::MacFailure)?;

        Ok(result)
    }
}

////
// Details
////

/// A representation of a nonce suitable for e.g. AES, supporting inc(),
/// copy_to_slice(), and other functions
struct Nonce<L: ArrayLength<u8>> {
    bytes: GenericArray<u8, L>,
}

impl<L: ArrayLength<u8>> Nonce<L> {
    pub fn new() -> Self {
        Self {
            bytes: Default::default(),
        }
    }

    pub fn is_max(&self) -> bool {
        for byte in self.bytes.iter() {
            if *byte != u8::max_value() {
                return false;
            }
        }
        true
    }

    pub fn inc(&mut self) {
        for byte in self.bytes.iter_mut() {
            *byte = byte.wrapping_add(1);
            if *byte != 0 {
                return;
            }
        }
    }

    pub fn as_bytes(&self) -> &GenericArray<u8, L> {
        &self.bytes
    }
}

////
// Tests
////

#[cfg(test)]
mod tests {
    use super::*;
    use crate::AesMessageCipher;
    use mc_util_test_helper::run_with_several_seeds;

    #[test]
    fn round_trip() {
        run_with_several_seeds(|mut rng| {
            let mut cipher = AesMessageCipher::new(&mut rng);

            let messages: &'static [&'static [u8]] =
                &[b"foobar", b"foobarbaz", b"quz", b"fizzbuzz"];
            for payload in messages {
                let ciphertext = cipher.encrypt_bytes(&mut rng, payload.to_vec());
                let plaintext = cipher.decrypt_bytes(ciphertext).unwrap();
                assert_eq!(&plaintext[..], &payload[..]);
            }
        });
    }
}
