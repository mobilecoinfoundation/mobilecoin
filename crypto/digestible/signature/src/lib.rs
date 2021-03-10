// Copyright (c) 2018-2021 The MobileCoin Foundation

#![no_std]

use mc_crypto_digestible::{Digestible, MerlinTranscript};
use signature::{Signature, Signer, Verifier};

pub use signature::Error;

/// Construct a deterministic semantic signature over a given object.
pub trait DigestibleSigner<S: Signature, T: Digestible> {
    fn sign_digestible(&self, context: &'static [u8], message: &T) -> S;

    /// Sign the digestible hash of the given object
    fn try_sign_digestible(&self, context: &'static [u8], message: &T) -> Result<S, Error>;
}

/// Verify a deterministic semantic signature over a given object
pub trait DigestibleVerifier<S: Signature, T: Digestible> {
    /// Verify a signature made over a digestible hash of a given object
    fn verify_digestible(&self, context: &'static [u8], message: &T, sig: &S) -> Result<(), Error>;
}

/// A blanket implementation of [DigestibleSigner] for [signature::Signer]
/// implementations.
///
/// This operates akin to a deterministic pre-hashed signature, in that we
/// create a 512-bit hash of the message object, and then sign that hash.
impl<T: Digestible, S: Signature, K: Signer<S>> DigestibleSigner<S, T> for K {
    fn sign_digestible(&self, context: &'static [u8], message: &T) -> S {
        let transcript = message.digest32::<MerlinTranscript>(context);
        self.sign(&transcript)
    }

    fn try_sign_digestible(&self, context: &'static [u8], message: &T) -> Result<S, Error> {
        let transcript = message.digest32::<MerlinTranscript>(context);
        self.try_sign(&transcript)
    }
}

/// A blanket implementation of [DigestibleVerifier] for [signature::Verifier]
/// implementations.
///
/// This operates akin to a deterministic pre-hashed signature, in that we
/// create a 512-bit hash of the message object, and then sign that hash.
impl<T: Digestible, S: Signature, V: Verifier<S>> DigestibleVerifier<S, T> for V {
    fn verify_digestible(
        &self,
        context: &'static [u8],
        message: &T,
        signature: &S,
    ) -> Result<(), Error> {
        let transcript = message.digest32::<MerlinTranscript>(context);
        self.verify(&transcript, signature)
    }
}
