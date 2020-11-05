// Copyright (c) 2018-2020 MobileCoin Inc.

//! Parses and validates a certificate chain

use displaydoc::Display;
use mc_crypto_keys::{DistinguishedEncoding, Ed25519Pair, Ed25519Private};
use std::{io::Cursor, vec::Vec};
use x509_parser::{
    error::{PEMError, X509Error},
    parse_x509_der,
    pem::{pem_to_der, Pem},
    X509Version,
};

const EXPECTED_TBS_CERT_VERSION: X509Version = X509Version::V3;

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
    /// Unable to extract Ed25519 Private Key
    Ed25519Privkey,
}

impl From<X509Error> for CertValidationError {
    fn from(_src: X509Error) -> Self {
        Self::CertSignatureFailure
    }
}

impl From<PEMError> for CertValidationError {
    fn from(_src: PEMError) -> Self {
        Self::PEMParseFailure
    }
}

// FIXME: Not sure what I'm missing here - using map_err instead below
//  the trait `std::convert::From<nom::internal::Err<x509_parser::error::X509Error>>` is not implemented for `validated_chain::CertValidationError`
//    = note: the question mark operation (`?`) implicitly performs a conversion on the error value using the `From` trait
//    = help: the following implementations were found:
//              <validated_chain::CertValidationError as std::convert::From<nom::internal::Err<x509_parser::error::X509Error>>>
impl From<nom::Err<X509Error>> for CertValidationError {
    fn from(_src: nom::Err<X509Error>) -> Self {
        Self::X509ParseFailure
    }
}

pub struct Chain {
    pub pems: Vec<Pem>,
    pub byte_vec: Vec<Vec<u8>>,
}

impl Chain {
    pub fn from_chain_bytes(chain_bytes: &[Vec<u8>]) -> Result<Chain, CertValidationError> {
        if chain_bytes.is_empty() {
            return Err(CertValidationError::EmptyCertChain);
        }

        // Construct an array of the views over the cert bytes
        let cert_bytes_view = chain_bytes
            .iter()
            .map(|cert_bytes| pem_to_der(cert_bytes))
            .map(|res| Some(res.ok().unwrap().1))
            .collect::<Vec<Pem>>();
        /*
               let cert_bytes_view = chain_bytes
                   .iter()
                   .map(pem_to_der)
                   .collect::<Result<Vec<Pem>, PEMError>>()?;

        */
        Ok(Chain {
            pems: cert_bytes_view,
            byte_vec: chain_bytes.to_vec(),
        })
    }

    /// Helper method to parse a chaim.pem string to an array of Pems
    pub fn from_chain_str(chain_str: &str) -> Result<Chain, CertValidationError> {
        let mut buf = Cursor::new(chain_str);
        let mut certs: Vec<Pem> = Vec::new();
        let mut cert_bytes: Vec<Vec<u8>> = Vec::new();
        let mut prev_seek = 0;
        loop {
            let (pem, seek) = x509_parser::pem::Pem::read(&mut buf).unwrap();
            certs.push(pem);
            cert_bytes.push(chain_str.get(prev_seek..seek).unwrap().as_bytes().to_vec());
            buf.set_position(seek as u64);
            prev_seek = seek;
            if seek >= chain_str.len() {
                break;
            }
        }
        Ok(Chain {
            pems: certs,
            byte_vec: cert_bytes,
        })
    }
}

pub struct ValidatedChain {
    pubkeys: Vec<Vec<u8>>,
}

impl ValidatedChain {
    /// Process and validate a certificate chain from bytes.
    pub fn from_chain(cert_bytes_view: &[Pem]) -> Result<ValidatedChain, CertValidationError> {
        // Store the pubkey from each cert
        let mut pubkeys = Vec::new();

        // For each cert in the remaining chain, check that:
        // * It is valid
        // * It was issued by the parent (validate signature)
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

            if cert.version() != EXPECTED_TBS_CERT_VERSION {
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

    pub fn public_key(&self, index: usize) -> &[u8] {
        &self.pubkeys[index] // FIXME: error handling
    }

    pub fn root_public_key(&self) -> &[u8] {
        println!("\x1b[1;36mGot root pubkey {:?}\x1b[0m", self.public_key(0));
        self.public_key(0)
    }

    pub fn terminal_public_key(&self) -> &[u8] {
        println!(
            "\x1b[1;36mGot terminal pubkey {:?}\x1b[0m",
            self.public_key(self.pubkeys.len() - 1)
        );

        self.public_key(self.pubkeys.len() - 1)
    }
}

/// Helper method to extract Ed25519 Keypair from Pem file
pub fn parse_keypair_from_pem(privkey_str: &str) -> Result<Ed25519Pair, CertValidationError> {
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
        Err(_e) => Err(CertValidationError::Ed25519Privkey),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cert_validation_str() {
        // Load cert chain, expect no errors.
        let fog_authority_cert_chain = include_str!(concat!(env!("OUT_DIR"), "/chain.pem"));
        let chain = Chain::from_chain_str(&fog_authority_cert_chain).unwrap();
        ValidatedChain::from_chain(&chain.pems).unwrap();
    }

    #[test]
    fn test_cert_validation_bytes() {
        // Load cert chain, expect no errors.
        let ca_cert = include_str!(concat!(env!("OUT_DIR"), "/ca.crt")).trim();
        let server_cert = include_str!(concat!(env!("OUT_DIR"), "/server-ed25519.crt")).trim();
        let input_chain = vec![ca_cert.as_bytes().to_vec(), server_cert.as_bytes().to_vec()];
        let chain = Chain::from_chain_bytes(&input_chain).unwrap();
        ValidatedChain::from_chain(&chain.pems).unwrap();
    }

    // FIXME: Add error cases to tests, including empty cert chain

    #[test]
    fn test_split_certs_to_byte_vec() {
        let cert_chain = include_str!(concat!(env!("OUT_DIR"), "/chain.pem"));
        let ca_cert = include_str!(concat!(env!("OUT_DIR"), "/ca.crt")).trim();
        let server_cert = include_str!(concat!(env!("OUT_DIR"), "/server-ed25519.crt")).trim();

        let chain = Chain::from_chain_str(cert_chain).unwrap();
        let ca = Chain::from_chain_str(ca_cert).unwrap();
        let server = Chain::from_chain_str(server_cert).unwrap();

        assert_eq!(chain.pems.len(), 2);
        assert_eq!(ca.pems.len(), 1);
        assert_eq!(server.pems.len(), 1);
        assert_eq!(chain.pems[0].contents, ca.pems[0].contents);
        assert_eq!(chain.pems[1].contents, server.pems[0].contents);
    }

    #[test]
    fn test_read_signing_key() {
        let server_privkey = include_str!(concat!(env!("OUT_DIR"), "/server-ed25519.key"));
        assert!(parse_keypair_from_pem(server_privkey).is_ok());
    }
}
