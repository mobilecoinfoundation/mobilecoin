// Copyright 2018-2022 The MobileCoin Foundation

//! This module contains the traits and implementations for creating and
//! verifying signatures over master minter maps and the canonical signing
//! context/domain separator byte string.

use crate::master_minters_map::MasterMintersMap;
use core::fmt::{Debug, Display};
use mc_crypto_digestible::{Digestible, MerlinTranscript};
use mc_crypto_keys::{
    Ed25519Pair, Ed25519Public, Ed25519Signature, Signature, SignatureError, Signer as SignerTrait,
    Verifier as VerifierTrait,
};

/// Retrieve the canonical signing context byte string.
///
/// This is intended to be used by crate-remote implementations of the
/// signature who want a "standard"
pub fn context() -> &'static [u8] {
    b"Master minters map signature"
}

/// A trait used to monkey-patch master minter map signatures onto existing
/// private-key types.
pub trait Signer {
    /// The signature output type
    type Sig: Signature;
    /// The error type
    type Error: Debug + Display;

    /// Sign a master minters map
    fn sign_master_minters_map(
        &self,
        master_minters_map: &MasterMintersMap,
    ) -> Result<Self::Sig, Self::Error>;
}

/// A trait used to monkey patch master minters map signature verification onto
/// existing public key types.
pub trait Verifier {
    /// The signature type to be verified
    type Sig: Signature;
    /// The error type if a signature could not be verified
    type Error: Debug + Display;

    /// Verify a signature over a master minters map.
    fn verify_master_minters_map(
        &self,
        master_minters_map: &MasterMintersMap,
        sig: &Self::Sig,
    ) -> Result<(), Self::Error>;
}

/// Ed25519 Signer implementation
impl Signer for Ed25519Pair {
    type Sig = Ed25519Signature;
    type Error = SignatureError;

    fn sign_master_minters_map(
        &self,
        master_minters_map: &MasterMintersMap,
    ) -> Result<Self::Sig, Self::Error> {
        let message = master_minters_map.digest32::<MerlinTranscript>(context());

        self.try_sign(message.as_ref())
    }
}

/// Ed25519 Verifier implementation
impl Verifier for Ed25519Public {
    type Sig = Ed25519Signature;
    type Error = SignatureError;

    fn verify_master_minters_map(
        &self,
        master_minters_map: &MasterMintersMap,
        sig: &Self::Sig,
    ) -> Result<(), Self::Error> {
        let message = master_minters_map.digest32::<MerlinTranscript>(context());

        self.verify(message.as_ref(), sig)
    }
}
