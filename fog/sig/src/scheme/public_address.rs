// Copyright 2018-2021 The MobileCoin Foundation

//! This module provides the implementation of the all-in-one verifier for
//! public addresses.

use crate::{
    authority::Verifier as AuthorityVerifier,
    report::Verifier as ReportVerifier,
    scheme::{Error, Verifier},
};
use core::convert::TryInto;
use mc_account_keys::PublicAddress;
use mc_crypto_x509_utils::{
    PublicKeyType, X509CertificateChain, X509CertificateIter, X509KeyExtrator,
};
use mc_fog_types::ReportResponse;
use x509_signature::X509Certificate;

impl Verifier for PublicAddress {
    type ReportSigError = <PublicKeyType as ReportVerifier>::Error;

    fn verify_fog_sig(
        &self,
        report_response: &ReportResponse,
    ) -> Result<(), Error<<Self as AuthorityVerifier>::Error, Self::ReportSigError>> {
        let sig = self
            .fog_authority_sig()
            .ok_or(Error::NoSignature)?
            .try_into()?;
        self.verify_authority_sig_der(&report_response.chain[0], &sig)
            .map_err(Error::Authority)?;

        // Vec<Vec<u8>> -> Vec<&[u8]>
        // Vec<&[u8]> -> Vec<X509Certificate>
        // Verify the chain
        let certs = X509CertificateIter::from(
            report_response
                .chain
                .iter()
                .map(|der| der.as_slice())
                .collect::<Vec<&[u8]>>(),
        )
        .collect::<Vec<X509Certificate>>();

        let idx = certs.verify_chain()?;

        Ok(certs[idx]
            .mc_public_key()
            .map_err(Error::Pubkey)?
            .verify_reports(
                report_response.reports.as_slice(),
                &report_response.signature.clone().into(),
            )?)
    }
}
