// Copyright (c) 2018-2021 The MobileCoin Foundation

use alloc::vec::Vec;
use failure::Fail;
use mc_util_serial::prost;
use prost::Message;
use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};

////
// A message cipher is a symmetric cipher meant to be used by the enclave as an
// alternative to intel's "Sealing" when persistence across power cycles is not needed.
//
// The trait also provides convenient wrappers over prost serialization.
//
// The payloads are encrypted in a way that includes the nonce
// and the key number in a ciphertext header. Rekeying happens under the hood
// when the counter is exhausted.
////

pub trait MessageCipher {
    fn new<R: CryptoRng + RngCore>(rng: &mut R) -> Self;

    // Encrypt plaintext bytes.
    // An allocation is required when using this API, but we reuse the allocation made by caller.
    fn encrypt_bytes<R: CryptoRng + RngCore>(&mut self, rng: &mut R, plaintext: Vec<u8>)
        -> Vec<u8>;
    // Decrypt bytes produced by encrypt_bytes
    // An allocation is required when using this API, but we reuse the allocation made by caller.
    fn decrypt_bytes(&mut self, ciphertext: Vec<u8>) -> Result<Vec<u8>, CipherError>;

    ////
    // Helpers that incorporate prost serialization
    ////
    fn encrypt<R: CryptoRng + RngCore, M: Message>(&mut self, rng: &mut R, msg: &M) -> Vec<u8> {
        let plaintext = mc_util_serial::encode(msg);
        self.encrypt_bytes(rng, plaintext)
    }

    fn decrypt<M: Message + Default>(
        &mut self,
        cipher_text: Vec<u8>,
    ) -> Result<M, ProstCipherError> {
        let plaintext = self.decrypt_bytes(cipher_text)?;
        Ok(mc_util_serial::decode(&plaintext)?)
    }
}

////
// Error types
////

#[derive(Clone, Debug, Deserialize, Fail, PartialEq, PartialOrd, Serialize)]
pub enum CipherError {
    #[fail(display = "The ciphertext was too short")]
    TooShort,
    #[fail(display = "The ciphertext refers to a key that doesn't exist")]
    UnknownKey,
    #[fail(display = "Mac mismatch when decrypting")]
    MacFailure,
}

#[derive(Debug, Fail, Serialize, Deserialize)]
pub enum ProstCipherError {
    #[fail(display = "An error with the underlying cipher: {}", _0)]
    Cipher(CipherError),
    #[fail(display = "An error with prost deserialization")]
    Prost,
}

impl From<CipherError> for ProstCipherError {
    fn from(src: CipherError) -> Self {
        Self::Cipher(src)
    }
}

impl From<prost::DecodeError> for ProstCipherError {
    fn from(_src: prost::DecodeError) -> Self {
        Self::Prost
    }
}
