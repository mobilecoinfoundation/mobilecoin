// Copyright 2018-2021 The MobileCoin Foundation

//! This module provides an implementation of

use crate::report::Verifier;
use mc_crypto_keys::Ed25519Signature;
use mc_crypto_x509_utils::PublicKeyType;
use mc_fog_types::Report;
use signature::{Error as SignatureError, Signature as SignatureTrait};

/// A wrapper for raw signature bytes, used to satisfy type system requirements
/// while delaying parsing of the signature bytes under the key type has been
/// determined.
#[derive(Clone, Debug)]
#[repr(transparent)]
pub struct Signature(Vec<u8>);

impl AsRef<[u8]> for Signature {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl SignatureTrait for Signature {
    fn from_bytes(bytes: &[u8]) -> Result<Self, SignatureError> {
        Ok(Self(bytes.to_vec()))
    }
}

impl From<Vec<u8>> for Signature {
    fn from(src: Vec<u8>) -> Self {
        Self(src)
    }
}

/// A trait which public keys can implement to allow them to verify a signature
/// over a list of IAS verification reports with appropriate domain separators.
impl<'a> Verifier for PublicKeyType {
    /// The signature output type
    type Sig = Signature;
    /// The printable error type
    type Error = SignatureError;

    /// Verify the provided signature is valid for the object over the reports.
    fn verify_reports(&self, reports: &[Report], sig: &Self::Sig) -> Result<(), Self::Error> {
        match self {
            PublicKeyType::Ed25519(pubkey) => {
                pubkey.verify_reports(reports, &Ed25519Signature::from_bytes(sig.as_ref())?)
            } // _ => Err(SignatureError::new()),
        }
    }
}
