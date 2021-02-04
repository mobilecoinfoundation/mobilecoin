// Copyright 2018-2021 The MobileCoin Foundation

//! This module contains the traits for creating and verifying signatures over
//! fog authority public keys and the canonical signing context/domain separator
//! byte string.

mod ristretto;

use core::fmt::{Debug, Display as DisplayTrait};
use displaydoc::Display;
use mc_crypto_keys::{PrivateKey, PublicKey};
use pem::PemError;
use signature::Signature;
use x509_signature::{Error as X509Error, SubjectPublicKeyInfo, X509Certificate};

/// The context tag/domain separator for fog signatures
const DOMAIN_SEPARATOR: &[u8; 23] = b"Fog authority signature";

/// Retrieve the canonical signing context byte string.
///
/// This is intended to be used by crate-remote implementations of the
/// signature who want a "standard"
pub fn context() -> &'static [u8] {
    DOMAIN_SEPARATOR
}

/// A wrap-up error type which can display authority signature-related errors
#[derive(Debug, Display, Eq, PartialEq)]
pub enum AuthorityError<E: Debug + DisplayTrait + Eq + PartialEq> {
    /// Error decoding PEM into DER: {0}
    Pem(PemError),
    /// Error parsing the X509 certificate: {0:?}
    X509(X509Error),
    /// A cryptographic error occurred: {0}
    Algorithm(E),
}

impl<E: Debug + DisplayTrait + Eq + PartialEq> From<PemError> for AuthorityError<E> {
    fn from(src: PemError) -> AuthorityError<E> {
        Self::Pem(src)
    }
}

impl<E: Debug + DisplayTrait + Eq + PartialEq> From<X509Error> for AuthorityError<E> {
    fn from(src: X509Error) -> AuthorityError<E> {
        Self::X509(src)
    }
}

/// A trait used to monkey-patch authority signatures onto existing private-key
/// types.
pub trait Signer: PrivateKey {
    /// The signature output type
    type Sig: Signature;
    /// The error type
    type Error: Debug + DisplayTrait + Eq + PartialEq;

    /// Signs a pem-encoded string containing a fog authority certificate
    fn sign_authority_pem<P: AsRef<[u8]>>(
        &self,
        authority: P,
    ) -> Result<Self::Sig, AuthorityError<<Self as Signer>::Error>> {
        self.sign_authority_der(pem::parse(authority.as_ref())?.contents)
    }

    /// Signs a DER-encoded byte string containing a fog authority certificate
    fn sign_authority_der<D: AsRef<[u8]>>(
        &self,
        authority: D,
    ) -> Result<Self::Sig, AuthorityError<<Self as Signer>::Error>> {
        self.sign_authority_x509(&x509_signature::parse_certificate(authority.as_ref())?)
    }

    /// Signs an X509 certificate for a fog authority
    fn sign_authority_x509(
        &self,
        x509: &X509Certificate,
    ) -> Result<Self::Sig, AuthorityError<<Self as Signer>::Error>> {
        self.sign_authority_spki(&x509.subject_public_key_info())
    }

    /// Signs the subjectPublicKeyInfo from a fog authority certificate
    fn sign_authority_spki(
        &self,
        spki: &SubjectPublicKeyInfo,
    ) -> Result<Self::Sig, AuthorityError<<Self as Signer>::Error>> {
        self.sign_authority_bytes(spki.spki())
    }

    /// Sign the raw bytes of a subjectPublicKeyInfo for a fog authority
    fn sign_authority_bytes(
        &self,
        spki_bytes: &[u8],
    ) -> Result<Self::Sig, AuthorityError<<Self as Signer>::Error>>;
}

pub trait Verifier: PublicKey {
    /// The signature type to be verified
    type Sig: Signature;
    /// The error type if a signature could not be verified
    type Error: Debug + DisplayTrait + Eq + PartialEq;

    /// Verify a signature over a PEM-encoded string containing a fog authority
    /// certificate
    fn verify_authority_sig<P: AsRef<[u8]>>(
        &self,
        authority: P,
        sig: &Self::Sig,
    ) -> Result<(), AuthorityError<<Self as Verifier>::Error>> {
        self.verify_authority_sig_der(pem::parse(authority.as_ref())?.contents, sig)
    }

    /// Verify a signature over a decoded certificate
    fn verify_authority_sig_der<D: AsRef<[u8]>>(
        &self,
        authority: D,
        sig: &Self::Sig,
    ) -> Result<(), AuthorityError<<Self as Verifier>::Error>> {
        self.verify_authority_sig_x509(&x509_signature::parse_certificate(authority.as_ref())?, sig)
    }

    /// Verify a signature over an X509 certificate
    fn verify_authority_sig_x509(
        &self,
        authority: &X509Certificate,
        sig: &Self::Sig,
    ) -> Result<(), AuthorityError<<Self as Verifier>::Error>> {
        self.verify_authority_sig_spki(&authority.subject_public_key_info(), sig)
    }

    /// Verify a signature over a X509 certificate's public key
    fn verify_authority_sig_spki(
        &self,
        spki: &SubjectPublicKeyInfo,
        sig: &Self::Sig,
    ) -> Result<(), AuthorityError<<Self as Verifier>::Error>> {
        self.verify_authority_sig_bytes(spki.spki(), sig)
    }

    /// Verify a signature over the raw subjectPublicKeyInfo bytes.
    fn verify_authority_sig_bytes(
        &self,
        spki_byptes: &[u8],
        sig: &Self::Sig,
    ) -> Result<(), AuthorityError<<Self as Verifier>::Error>>;
}
