// Copyright (c) 2018-2020 MobileCoin Inc.

//!

use mc_crypto_keys::Ed25519Public;
use std::{cmp, convert::TryFrom, io::Cursor, str::FromStr};
use x509_parser::{
    certificate::X509Certificate, der_parser::oid::Oid, pem::Pem, x509::AlgorithmIdentifier,
};

/// An iterator of [`Pem`] structures created over a string slice.
pub struct PemStringIter<T> {
    string: Cursor<T>,
    offset: usize,
}

impl<T: AsRef<[u8]>> PemStringIter<T> {
    /// Create a new iterator based on the given string.
    fn new(inner: T) -> Self {
        Self {
            string: Cursor::new(inner),
            offset: 0,
        }
    }
}

impl<T: AsRef<[u8]>> Iterator for PemStringIter<T> {
    type Item = Pem;

    fn next(&mut self) -> Option<Self::Item> {
        Pem::read(&mut self.string)
            .map(|(pem, new_offset)| {
                self.offset = new_offset;
                pem
            })
            .ok()
    }
}

/// A trait used to monkey-patch a pem parsing iterator over string slices
pub trait PemStringIterable: AsRef<[u8]> + Sized {
    /// Create an iterator over a string which contains Pem objects
    fn into_pem_iter(self) -> PemStringIter<Self>;
}

/// Anything which can be referenced as a byte slice gets into_iter_pem()
impl<T: AsRef<[u8]>> PemStringIterable for T {
    fn into_pem_iter(self) -> PemStringIter<T> {
        PemStringIter::new(self)
    }
}

/// An iterator of [`X509Certificate`] objects over a slice of [`Pem`] objects.
pub struct X509CertificateIter<'a> {
    pem_slice: &'a [Pem],
    offset: usize,
}

impl<'a> X509CertificateIter<'a> {
    fn new<T: AsRef<[Pem]>>(pems: &'a T) -> Self {
        Self {
            pem_slice: pems.as_ref(),
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
            X509Certificate::from_der(&self.pem_slice[self.offset].contents)
                .map(|(_, x509)| {
                    self.offset += 1;
                    x509
                })
                .ok()
        }
    }
}

/// A trait used to monkey-patch an X509Certificate parsing iterator over a
/// slice of [`Pem`] objects.
pub trait X509CertificateIterable {
    fn iter_x509(&self) -> X509CertificateIter;
}

/// Anything which can be referenced as a Pem slice gets a method to iterate
/// certificates, and verify it is a well-formed single-path certificate chain.
impl<T: AsRef<[Pem]>> X509CertificateIterable for T {
    fn iter_x509(&self) -> X509CertificateIter {
        X509CertificateIter::new(self)
    }
}

/// A trait used to monkey-patch an X509Certificate chain verifier onto a slice
/// of X509Certificate objects.
pub trait X509CertificateChain {
    /// Verify the chain (checks validity, signatures, and CA extension of each
    /// element)
    fn verify_chain(&self) -> bool;
}

impl<'a, T: AsRef<[X509Certificate<'a>]>> X509CertificateChain for T {
    fn verify_chain(&self) -> bool {
        let mut previous = None;
        let mut cert_count = 0usize;

        if self.as_ref().is_empty() {
            return false;
        }

        for (index, cert) in self.as_ref().iter().enumerate() {
            // If the cert wasn't signed by the preceeding cert (or itself, if first), fail.
            if cert.verify_signature(previous).is_err() {
                return false;
            }

            // If the cert isn't valid (temporally), fail.
            if !cert.validity().is_valid() {
                return false;
            }

            // Update state for the next iteration
            previous = Some(&cert.tbs_certificate.subject_pki);
            // Update the number of certificates which have passed validation
            cert_count = index + 1;

            if !cert.tbs_certificate.is_ca() {
                break;
            }
        }

        // If any of the certs didn't pass verification, or there was a non-CA
        // cert in the middle of the chain, fail.
        if cert_count != self.as_ref().len() {
            return false;
        }

        // If the last cert in the chain is a CA, fail.
        !self.as_ref()[cmp::max(0, cert_count - 1)]
            .tbs_certificate
            .is_ca()
    }
}

/// A list of key types supported by both X.509 and mc-crypto-keys.
pub enum PublicKeyType {
    /// The public key type is invalid
    Invalid,
    Unknown(Vec<u8>),
    Ed25519(Ed25519Public),
}

/// Monkey-patch support for extracting mc-crypto-keys public keys from X509
/// certificates.
pub trait X509KeyExtrator {
    /// Try to retrieve the public key.
    fn mc_public_key(&self) -> PublicKeyType;
}

fn ed25519_algorithm_identifier() -> AlgorithmIdentifier<'static> {
    AlgorithmIdentifier {
        algorithm: Oid::from_str("1.3.101.112").expect("Invalid hard-coded OID for Ed25519"),
        parameters: None,
    }
}

impl X509KeyExtrator for X509Certificate<'_> {
    fn mc_public_key(&self) -> PublicKeyType {
        if self.tbs_certificate.subject_pki.algorithm == ed25519_algorithm_identifier() {
            if let Ok(pubkey) = Ed25519Public::try_from(
                self.tbs_certificate.subject_pki.subject_public_key.as_ref(),
            ) {
                PublicKeyType::Ed25519(pubkey)
            } else {
                PublicKeyType::Invalid
            }
        } else {
            PublicKeyType::Unknown(Vec::from(
                self.tbs_certificate.subject_pki.subject_public_key.as_ref(),
            ))
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use mc_crypto_x509_test_vectors as test_vectors;

    /// Ensure a valid RSA-RSA-Ed25519 chain is validated correctly.
    #[test]
    fn valid_chain() {
        let (pem_string, pair) = test_vectors::ok_rsa_chain_25519_leaf();

        let cert_ders = pem_string.into_pem_iter().collect::<Vec<Pem>>();
        let certs = cert_ders.iter_x509().collect::<Vec<X509Certificate>>();

        assert!(certs.verify_chain());

        let pubkey = certs
            .last()
            .expect("Could not get last cert")
            .mc_public_key();
        if let PublicKeyType::Ed25519(pubkey) = pubkey {
            assert_eq!(pair.public_key(), pubkey);
        } else {
            panic!("Last cert in the chain does not contain an Ed25519 public key");
        }
    }

    /// Ensure a longer (but still valid) chain is validated correctly.
    #[test]
    fn depth10_chain() {
        let (pem_string, pair) = test_vectors::ok_rsa_chain_depth_10();

        let cert_ders = pem_string.into_pem_iter().collect::<Vec<Pem>>();
        let certs = cert_ders.iter_x509().collect::<Vec<X509Certificate>>();

        assert!(certs.verify_chain());

        let pubkey = certs
            .last()
            .expect("Could not get last cert")
            .mc_public_key();
        if let PublicKeyType::Ed25519(pubkey) = pubkey {
            assert_eq!(pair.public_key(), pubkey);
        } else {
            panic!("Last cert in the chain does not contain an Ed25519 public key");
        }
    }

    /// Ensure a (valid) tree of certs is not verified as a chain.
    #[test]
    fn tree_not_chain() {
        let pem_string = test_vectors::ok_rsa_tree();

        let cert_ders = pem_string.into_pem_iter().collect::<Vec<Pem>>();
        let certs = cert_ders.iter_x509().collect::<Vec<X509Certificate>>();

        assert!(!certs.verify_chain());
    }

    /// Ensure a certificate chain missing its root (no root, intermediate,
    /// leaf) is not verified.
    #[test]
    fn missing_head() {
        let (pem_string, _pair) = test_vectors::fail_missing_head();

        let cert_ders = pem_string.into_pem_iter().collect::<Vec<Pem>>();
        let certs = cert_ders.iter_x509().collect::<Vec<X509Certificate>>();

        assert!(!certs.verify_chain());
    }

    /// Ensure a broken chain (root, no intermediate, leaf) is not verified.
    #[test]
    fn missing_link() {
        let (pem_string, _pair) = test_vectors::fail_missing_link();

        let cert_ders = pem_string.into_pem_iter().collect::<Vec<Pem>>();
        let certs = cert_ders.iter_x509().collect::<Vec<X509Certificate>>();

        assert!(!certs.verify_chain());
    }

    /// Ensure a chain containing a not-yet-valid cert is not verified.
    #[test]
    fn too_soon() {
        let (pem_string, _pair) = test_vectors::fail_leaf_too_soon();

        let cert_ders = pem_string.into_pem_iter().collect::<Vec<Pem>>();
        let certs = cert_ders.iter_x509().collect::<Vec<X509Certificate>>();

        assert!(!certs.verify_chain());
    }

    /// Ensure a chain containing an expired cert is not verified.
    #[test]
    fn expired() {
        let (pem_string, _pair) = test_vectors::fail_leaf_expired();

        let cert_ders = pem_string.into_pem_iter().collect::<Vec<Pem>>();
        let certs = cert_ders.iter_x509().collect::<Vec<X509Certificate>>();

        assert!(!certs.verify_chain());
    }
}
