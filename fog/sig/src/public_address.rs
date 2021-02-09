// Copyright 2018-2021 The MobileCoin Foundation

//! This module provides the implementation of the all-in-one verifier for
//! public addresses.

use crate::{Error, Verifier};
use core::convert::TryInto;
use mc_account_keys::PublicAddress;
use mc_crypto_keys::Ed25519Signature;
use mc_crypto_x509_utils::{
    PublicKeyType, X509CertificateChain, X509CertificateIter, X509KeyExtrator,
};
use mc_fog_sig_authority::Verifier as AuthorityVerifier;
use mc_fog_sig_report::Verifier as ReportVerifier;
use mc_fog_types::ReportResponse;
use signature::{Error as SignatureError, Signature};
use x509_signature::X509Certificate;

impl Verifier for PublicAddress {
    type ReportSigError = SignatureError;

    fn verify_fog_sig(
        &self,
        report_response: &ReportResponse,
    ) -> Result<(), Error<<Self as AuthorityVerifier>::Error, Self::ReportSigError>> {
        // Vec<Vec<u8>> -> Vec<&[u8]>
        // Vec<&[u8]> -> Vec<X509Certificate>
        let certs = X509CertificateIter::from(
            report_response
                .chain
                .iter()
                .map(|der| der.as_slice())
                .collect::<Vec<&[u8]>>(),
        )
        .collect::<Vec<X509Certificate>>();

        // Verify the authority signature
        let authority_sig = self
            .fog_authority_sig()
            .ok_or(Error::NoSignature)?
            .try_into()?;

        self.verify_authority(&certs[0].subject_public_key_info().spki(), &authority_sig)
            .map_err(Error::Authority)?;

        // Verify the chain
        let idx = certs.verify_chain()?;

        // Verify the signature over the reports matches the last verified member of the
        // chain
        match certs[idx].mc_public_key().map_err(Error::Pubkey)? {
            PublicKeyType::Ed25519(pubkey) => {
                let sig = Ed25519Signature::from_bytes(&report_response.signature)
                    .map_err(Error::SignatureParse)?;
                pubkey
                    .verify_reports(report_response.reports.as_slice(), &sig)
                    .map_err(Error::Report)
            }
        }
    }
}
