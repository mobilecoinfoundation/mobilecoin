// Copyright (c) 2018-2021 MobileCoin Inc.

//! Utilities for handling X509 certificate chains

use displaydoc::Display;
use mc_crypto_keys::{DistinguishedEncoding, Ed25519Public, KeyError};
use pem::Pem;
use std::time::{SystemTime, SystemTimeError};
use x509_signature::{Error as X509Error, X509Certificate};

/// An iterator of [`X509Certificate`] objects over things which can be
/// converted to vectors of byte slices.
pub struct X509CertificateIter<'a> {
    pem_slice: Vec<&'a [u8]>,
    offset: usize,
}

impl<'a> From<Vec<&'a [u8]>> for X509CertificateIter<'a> {
    fn from(pem_slice: Vec<&'a [u8]>) -> Self {
        Self {
            pem_slice,
            offset: 0,
        }
    }
}

impl<'a> Iterator for X509CertificateIter<'a> {
    type Item = X509Certificate<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.offset == self.pem_slice.len() {
            None
        } else {
            self.offset += 1;
            x509_signature::parse_certificate(self.pem_slice[self.offset - 1]).ok()
        }
    }
}

/// A trait used to monkey-patch an X509Certificate parsing iterator over a
/// vector of byte slices.
pub trait X509CertificateIterable {
    fn iter_x509(&self) -> X509CertificateIter;
}

/// Anything which can be referenced as a Pem slice gets a method to iterate
/// certificates, and verify it is a well-formed single-path certificate chain.
impl<T: AsRef<[Pem]>> X509CertificateIterable for T {
    fn iter_x509(&self) -> X509CertificateIter {
        self.as_ref()
            .iter()
            .map(|pem| &pem.contents[..])
            .collect::<Vec<&[u8]>>()
            .into()
    }
}

/// An emumeration of errors
#[derive(Debug, Display, Eq, PartialEq)]
pub enum ChainError {
    /// The chain slice is empty
    Empty,
    /**
     * Could not retrieve the current time: second time provided was later
     * than self
     */
    SystemTime,
    /// X509 error: {0:?}
    X509(X509Error),
}

impl From<SystemTimeError> for ChainError {
    fn from(_src: SystemTimeError) -> ChainError {
        ChainError::SystemTime
    }
}

impl From<X509Error> for ChainError {
    fn from(src: X509Error) -> ChainError {
        ChainError::X509(src)
    }
}

/// A trait used to monkey-patch an X509Certificate chain verifier onto a slice
/// of X509Certificate objects.
pub trait X509CertificateChain<'a> {
    /// Verify the chain (checks validity, signatures, and CA extension of each
    /// element)
    fn verify_chain(&self) -> Result<usize, ChainError>;

    /// Get the leaf certificate
    fn leaf(&self) -> Result<&X509Certificate<'a>, ChainError>;

    /// Verify the chain and retrieve the self-signed root certificate.
    fn verified_root(&self) -> Result<&X509Certificate<'a>, ChainError>;
}

impl<'a, T: AsRef<[X509Certificate<'a>]>> X509CertificateChain<'a> for T {
    fn verify_chain(&self) -> Result<usize, ChainError> {
        let mut previous: Option<&X509Certificate> = None;
        let mut cert_count = 0usize;

        if self.as_ref().is_empty() {
            return Err(ChainError::Empty);
        }

        for (index, cert) in self.as_ref().iter().enumerate() {
            // If we aren't the first cert in the chain, and there were no errors before us,
            // verify we signed the previous cert.
            if let Some(prev_cert) = previous {
                prev_cert.check_issued_by(cert)?;
            }

            let timestamp = SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)?
                .as_secs() as i64;

            // If the cert isn't valid (temporally), fail.
            cert.valid_at_timestamp(timestamp)?;

            // Update state for the next iteration
            previous = Some(cert);
            // Update the number of certificates which have passed validation
            cert_count = index + 1;
        }

        // The last cert in the chain must be self-signed.
        if let Some(previous) = previous {
            previous.check_self_issued()?;
        }

        Ok(cert_count)
    }

    fn leaf(&self) -> Result<&X509Certificate<'a>, ChainError> {
        if self.as_ref().is_empty() {
            Err(ChainError::Empty)
        } else {
            let slice = self.as_ref();
            Ok(&slice[0])
        }
    }

    fn verified_root(&self) -> Result<&X509Certificate<'a>, ChainError> {
        let slice = self.as_ref();
        Ok(&slice[self.verify_chain()? - 1])
    }
}

/// A list of key types supported by both X.509 and mc-crypto-keys.
pub enum PublicKeyType {
    /// The public key is Ed25519
    Ed25519(Ed25519Public),
}

/// Monkey-patch support for extracting mc-crypto-keys public keys from X509
/// certificates.
pub trait X509KeyExtrator {
    /// Try to retrieve the public key.
    fn mc_public_key(&self) -> Result<PublicKeyType, KeyError>;
}

impl X509KeyExtrator for X509Certificate<'_> {
    fn mc_public_key(&self) -> Result<PublicKeyType, KeyError> {
        if let Ok(pubkey) = Ed25519Public::try_from_der(self.subject_public_key_info().spki()) {
            Ok(PublicKeyType::Ed25519(pubkey))
        } else {
            Err(KeyError::AlgorithmMismatch)
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use mc_crypto_x509_test_vectors as test_vectors;

    const TYPICAL_CHAIN_LEN: usize = 3;
    const DEPTH10_CHAIN_LEN: usize = 10;

    /// Ensure a valid RSA-RSA-Ed25519 chain is validated correctly.
    #[test]
    fn valid_chain() {
        let (pem_string, pair) = test_vectors::ok_rsa_chain_25519_leaf();

        let cert_ders = pem::parse_many(pem_string);
        let certs = cert_ders.iter_x509().collect::<Vec<X509Certificate>>();

        assert_eq!(
            TYPICAL_CHAIN_LEN,
            certs.verify_chain().expect("Could not verify valid chain")
        );

        let pubkey = certs
            .leaf()
            .expect("Could not get leaf cert")
            .mc_public_key()
            .expect("Could not parse leaf cert's pubkey");

        match pubkey {
            PublicKeyType::Ed25519(key) => assert_eq!(pair.public_key(), key),
        }
    }

    /// Ensure a longer (but still valid) chain is validated correctly.
    #[test]
    fn depth10_chain() {
        let (pem_string, pair) = test_vectors::ok_rsa_chain_depth_10();

        let cert_ders = pem::parse_many(pem_string);
        let certs = cert_ders.iter_x509().collect::<Vec<X509Certificate>>();

        assert_eq!(
            DEPTH10_CHAIN_LEN,
            certs.verify_chain().expect("Could not verify valid chain")
        );

        let pubkey = certs
            .leaf()
            .expect("Could not get last cert")
            .mc_public_key()
            .expect("Could not parse last cert's pubkey");

        match pubkey {
            PublicKeyType::Ed25519(key) => assert_eq!(pair.public_key(), key),
        }
    }

    /// Ensure a (valid) tree of certs is not verified as a chain.
    #[test]
    fn tree_not_chain() {
        let pem_string = test_vectors::ok_rsa_tree();

        let cert_ders = pem::parse_many(pem_string);
        let certs = cert_ders.iter_x509().collect::<Vec<X509Certificate>>();
        let err = certs
            .verify_chain()
            .expect_err("Verification of tree-not-chain did not fail");

        assert_eq!(err, ChainError::X509(X509Error::UnknownIssuer));
    }

    /// Ensure a certificate chain missing its root (no root, intermediate,
    /// leaf) is not verified.
    #[test]
    fn missing_head() {
        let (pem_string, _pair) = test_vectors::fail_missing_head();

        let cert_ders = pem::parse_many(pem_string);
        let certs = cert_ders.iter_x509().collect::<Vec<X509Certificate>>();
        let err = certs
            .verify_chain()
            .expect_err("Verification of missing head chain did not fail");

        assert_eq!(err, ChainError::X509(X509Error::UnknownIssuer));
    }

    /// Ensure a broken chain (root, no intermediate, leaf) is not verified.
    #[test]
    fn missing_link() {
        let (pem_string, _pair) = test_vectors::fail_missing_link();

        let cert_ders = pem::parse_many(pem_string);
        let certs = cert_ders.iter_x509().collect::<Vec<X509Certificate>>();
        let err = certs
            .verify_chain()
            .expect_err("Verification of missing-link chain did not fail");

        assert_eq!(err, ChainError::X509(X509Error::UnknownIssuer));
    }

    /// Ensure a chain containing a not-yet-valid cert is not verified.
    #[test]
    fn too_soon() {
        let (pem_string, _pair) = test_vectors::fail_leaf_too_soon();

        let cert_ders = pem::parse_many(pem_string);
        let certs = cert_ders.iter_x509().collect::<Vec<X509Certificate>>();
        let err = certs
            .verify_chain()
            .expect_err("Verification of not-yet-valid chain did not fail");

        // FIXME: Investigate
        assert_eq!(err, ChainError::X509(X509Error::CertNotValidYet));
    }

    /// Ensure a chain containing an expired cert is not verified.
    #[test]
    fn expired() {
        let (pem_string, _pair) = test_vectors::fail_leaf_expired();

        let cert_ders = pem::parse_many(pem_string);
        let certs = cert_ders.iter_x509().collect::<Vec<X509Certificate>>();
        let err = certs
            .verify_chain()
            .expect_err("Verification of expired chain did not fail");

        assert_eq!(err, ChainError::X509(X509Error::CertExpired));
    }
}
