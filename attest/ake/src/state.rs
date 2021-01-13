// Copyright (c) 2018-2021 The MobileCoin Foundation

//! Transducer states used by initiators and/or responders.

use crate::mealy::State;
use aead::{AeadMut, NewAead};
use alloc::{string::String, vec::Vec};
use digest::{BlockInput, FixedOutput, Reset, Update};
use mc_crypto_keys::Kex;
use mc_crypto_noise::{CipherError, CipherState, HandshakeState, NoiseCipher};

/// The state of a node (initiator or responder) before anything has happened
/// yet.
pub struct Start {
    /// For responder's unique ID (hostname)
    pub(crate) responder_id: String,
}

impl Start {
    /// The Mealy machines all begin here, which contains (potentially unused)
    /// details about how to authenticate a participant.
    pub fn new(responder_id: String) -> Self {
        Self { responder_id }
    }
}

impl State for Start {}

/// The state after an NodeInit or ClientInit event has been added to
/// the Start state.
pub struct AuthPending<KexAlgo, Cipher, DigestType>
where
    KexAlgo: Kex,
    Cipher: AeadMut + NewAead + NoiseCipher + Sized,
    DigestType: BlockInput + Clone + Default + FixedOutput + Update + Reset,
{
    /// The handshake state
    pub(crate) state: HandshakeState<KexAlgo, Cipher, DigestType>,
}

impl<KexAlgo, Cipher, DigestType> State for AuthPending<KexAlgo, Cipher, DigestType>
where
    KexAlgo: Kex,
    Cipher: AeadMut + NewAead + NoiseCipher + Sized,
    DigestType: BlockInput + Clone + Default + FixedOutput + Update + Reset,
{
}

impl<KexAlgo, Cipher, DigestType> AuthPending<KexAlgo, Cipher, DigestType>
where
    KexAlgo: Kex,
    Cipher: AeadMut + NewAead + NoiseCipher + Sized,
    DigestType: BlockInput + Clone + Default + FixedOutput + Update + Reset,
{
    pub(crate) fn new(state: HandshakeState<KexAlgo, Cipher, DigestType>) -> Self {
        Self { state }
    }
}

/// The state after an auth response has been sent by a responder/received by
/// an initiator.
pub struct Ready<Cipher>
where
    Cipher: AeadMut + NewAead + NoiseCipher + Sized,
{
    pub(crate) writer: CipherState<Cipher>,
    pub(crate) reader: CipherState<Cipher>,
    pub(crate) binding: Vec<u8>,
}

impl<Cipher> Ready<Cipher>
where
    Cipher: AeadMut + NewAead + NoiseCipher + Sized,
{
    /// Retrieve the channel binding as a byte slice
    pub fn binding(&self) -> &[u8] {
        self.binding.as_ref()
    }
    /// Using the writer cipher, encrypt the given plaintext.
    pub fn encrypt(&mut self, aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, CipherError> {
        self.writer.encrypt_with_ad(aad, plaintext)
    }

    /// Using the reader cipher, decrypt the provided ciphertext.
    pub fn decrypt(&mut self, aad: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, CipherError> {
        self.reader.decrypt_with_ad(aad, ciphertext)
    }
}

impl<Cipher> State for Ready<Cipher> where Cipher: AeadMut + NewAead + NoiseCipher + Sized {}
