// Copyright (c) 2018-2021 The MobileCoin Foundation

//! Common transitions between initiator and responder.

use crate::{
    event::{Ciphertext, Plaintext},
    mealy::Transition,
    state::Ready,
};
use aead::{AeadMut, NewAead};
use alloc::vec::Vec;
use mc_crypto_noise::{CipherError, NoiseCipher};
use rand_core::{CryptoRng, RngCore};

/// Ready + Ciphertext => Ready + Vec-of-plaintext
impl<Cipher> Transition<Ready<Cipher>, Ciphertext<'_, '_>, Vec<u8>> for Ready<Cipher>
where
    Cipher: AeadMut + NewAead + NoiseCipher + Sized,
{
    type Error = CipherError;

    fn try_next<R: CryptoRng + RngCore>(
        self,
        _csprng: &mut R,
        input: Ciphertext,
    ) -> Result<(Ready<Cipher>, Vec<u8>), Self::Error> {
        let mut retval = self;
        let plaintext = retval.decrypt(input.aad, input.msg)?;
        Ok((retval, plaintext))
    }
}

/// Ready + Plaintext => Ready + Vec-of-ciphertext
impl<Cipher> Transition<Ready<Cipher>, Plaintext<'_, '_>, Vec<u8>> for Ready<Cipher>
where
    Cipher: AeadMut + NewAead + NoiseCipher + Sized,
{
    type Error = CipherError;

    fn try_next<R: CryptoRng + RngCore>(
        self,
        _csprng: &mut R,
        input: Plaintext,
    ) -> Result<(Ready<Cipher>, Vec<u8>), Self::Error> {
        let mut retval = self;
        let ciphertext = retval.encrypt(input.aad, input.msg)?;
        Ok((retval, ciphertext))
    }
}
