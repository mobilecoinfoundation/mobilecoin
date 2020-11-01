// Copyright (c) 2018-2020 MobileCoin Inc.

//! Parses and validates a certificate chain

use displaydoc::Display;
use mc_crypto_keys::{DistinguishedEncoding, Ed25519Pair, Ed25519Private};
use std::vec::Vec;
use x509_parser::{
    error::X509Error,
    parse_x509_der,
    pem::{pem_to_der, Pem},
};

const EXPECTED_TBS_CERT_VERSION: u32 = 2;

/// Enumeration of possible errors in course of verifying fog authority
#[derive(Debug, Display)]
pub enum CertValidationError {
    /// Unable to parse pem
    PEMParseFailure,
    /// Unable to parse x509
    X509ParseFailure,
    /// Unable to parse tbs certificate
    TBSParseFailure,
    /// Certificate valid before/after failed
    CertValidityFailed,
    /// Incorrect certificate version
    IncorrectCertVersion,
    /// The chain construction does not meet requirements
    InvalidChain,
    /// Empty cert chain
    EmptyCertChain,
    /// Cert signature validation failed
    CertSignatureFailure,
}

impl From<X509Error> for CertValidationError {
    fn from(_src: X509Error) -> Self {
        Self::CertSignatureFailure
    }
}

pub struct ValidatedChain {
    pubkeys: Vec<Vec<u8>>,
}

impl ValidatedChain {
    pub fn from_chain_bytes(
        chain_bytes: &[Vec<u8>],
    ) -> Result<ValidatedChain, CertValidationError> {
        if chain_bytes.is_empty() {
            return Err(CertValidationError::EmptyCertChain);
        }

        // Store the pubkey from each cert
        let mut pubkeys = Vec::new();

        // Construct an array of the views over the cert bytes
        let cert_bytes_view: Vec<Pem> = chain_bytes
            .iter()
            .map(|cert_bytes| {
                // Parse Pem
                let (_rem, pem) = pem_to_der(cert_bytes).unwrap(); //.map_err(|_| CertValidationError::PEMParseFailure)?;
                                                                   /*if !rem.is_empty() || pem.label != "CERTIFICATE" {
                                                                       return Err(CertValidationError::PEMParseFailure);
                                                                   }*/
                // FIXME: Surface error within map
                pem
            })
            .collect();

        // For each cert in the remaining chain, check that:
        // * It was issued by the parent (validate signature)
        // * It is valid
        for (i, pem) in cert_bytes_view.iter().enumerate() {
            // Parse x509 from pem
            let (rem, cert) =
                parse_x509_der(&pem.contents).map_err(|_| CertValidationError::X509ParseFailure)?;
            if !rem.is_empty() {
                return Err(CertValidationError::X509ParseFailure);
            }

            // Check validity
            if !cert.validity().is_valid() {
                return Err(CertValidationError::CertValidityFailed);
            }

            if cert.tbs_certificate.version != EXPECTED_TBS_CERT_VERSION {
                println!(
                    "\x1b[1;31m expected {:?} got {:?}\x1b[0m",
                    cert.tbs_certificate.version, EXPECTED_TBS_CERT_VERSION
                );
                return Err(CertValidationError::IncorrectCertVersion);
            }

            if i > 0 {
                let (rem, parent_cert) = parse_x509_der(&cert_bytes_view[i - 1].contents)
                    .map_err(|_| CertValidationError::X509ParseFailure)?;
                if !rem.is_empty() {
                    return Err(CertValidationError::X509ParseFailure);
                }
                cert.verify_signature(Some(&parent_cert.tbs_certificate.subject_pki))?;
            } else {
                // Pass None to verify self-signed
                cert.verify_signature(None)?;

                if !cert.tbs_certificate.is_ca() {
                    return Err(CertValidationError::InvalidChain);
                };
            }

            pubkeys.push(
                cert.tbs_certificate
                    .subject_pki
                    .subject_public_key
                    .data
                    .to_vec(),
            );
        }

        Ok(Self { pubkeys })
    }

    pub fn public_key(&self, index: usize) -> Vec<u8> {
        self.pubkeys[index].clone() // FIXME: error handling
    }

    pub fn root_public_key(&self) -> Vec<u8> {
        println!("\x1b[1;36mGot root pubkey {:?}\x1b[0m", self.public_key(0));
        self.public_key(0)
    }

    pub fn terminal_public_key(&self) -> Vec<u8> {
        println!(
            "\x1b[1;36mGot terminal pubkey {:?}\x1b[0m",
            self.public_key(self.pubkeys.len() - 1)
        );

        self.public_key(self.pubkeys.len() - 1)
    }
}

/// Utilities to help with parsing certs
type CertByteVec = Vec<Vec<u8>>;

/// Simple helper method to split a cert chain string, e.g. from a chain.pem file
/// to a vector containing a vector of bytes for each certificate in the chain.
pub fn split_certs_to_byte_vec(contents: &str) -> CertByteVec {
    let mut cert_strs: Vec<&str> = Vec::new();
    let mut next: &str = contents.trim();
    loop {
        match next.find("-\n-") {
            Some(ind) => {
                let (first, n) = next.split_at(ind + 1);
                next = &n[1..];
                cert_strs.push(first);
                // FIXME: add max chain size
            }
            None => {
                cert_strs.push(next);
                break;
            }
        }
    }
    let certs: Vec<Vec<u8>> = cert_strs.iter().map(|x| x.as_bytes().to_vec()).collect();
    certs
}

pub fn parse_keypair_from_pem(privkey_str: &str) -> Result<Ed25519Pair, ()> {
    let res = pem_to_der(privkey_str.as_bytes());
    match res {
        Ok((rem, pem)) => {
            assert!(rem.is_empty());
            // The private key file, in PEM format, expects the PRIVATE label
            assert_eq!(pem.label, "PRIVATE");
            let privkey = Ed25519Private::try_from_der(&pem.contents)
                .expect("Could not parse Ed25519Private from contents");
            let keypair = Ed25519Pair::from(privkey);
            Ok(keypair)
        }
        Err(_e) => Err(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mc_crypto_keys::DistinguishedEncoding;

    #[test]
    fn test_cert_validation() {
        // Load cert chain, expect no errors.
        let fog_authority_cert_chain = include_str!("../tests/data/chain.pem");
        let certs = split_certs_to_byte_vec(fog_authority_cert_chain);
        ValidatedChain::from_chain_bytes(&certs).unwrap();
    }

    // FIXME: Add error cases to tests

    #[test]
    fn test_split_certs_to_byte_vec() {
        let cert_chain = include_str!("../tests/data/chain.pem");
        let split = split_certs_to_byte_vec(cert_chain);
        assert_eq!(split.len(), 2);
        assert_eq!(
            split[0],
            include_str!("../tests/data/ca.crt").trim().as_bytes()
        );
        assert_eq!(
            split[1],
            include_str!("../tests/data/server-ed25519.crt")
                .trim()
                .as_bytes()
        );
    }

    #[test]
    fn test_read_signing_key() {
        let server_privkey = include_str!("../tests/data/server-ed25519.key");
        let keypair = parse_keypair_from_pem(server_privkey).expect("Could not parse privkey");
        assert_eq!(
            keypair.private_key().to_der(),
            vec![
                48, 46, 2, 1, 0, 48, 5, 6, 3, 43, 101, 112, 4, 34, 4, 32, 250, 52, 67, 152, 137,
                127, 169, 190, 155, 163, 182, 99, 100, 45, 59, 134, 69, 111, 246, 168, 10, 5, 194,
                116, 28, 94, 171, 189, 167, 111, 169, 128
            ]
        );
    }
}
