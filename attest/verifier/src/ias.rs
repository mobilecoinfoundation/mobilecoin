// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Verifiers which operate on the contents of the
//! [`VerificationReport`](::mc_attest_core::VerificationReport)
//! structure.

use crate::{avr::Kind as AvrKind, status::Kind as StatusKind, Error, Verify};
use alloc::{vec, vec::Vec};
use mbedtls::{
    alloc::{Box as MbedtlsBox, List as MbedtlsList},
    hash::Type as HashType,
    pk::{EcGroupId, Type as PkType},
    x509::{Certificate, Profile},
};
use mc_attest_core::{VerificationReport, VerificationReportData};
use sha2::{Digest, Sha256};

/// The maximum number of certificates to accept in an IAS report's certificate
/// chain.
const MAX_CHAIN_DEPTH: usize = 5;

/// A structure which can verify a top-level report.
#[derive(Debug)]
pub struct IasReportVerifier {
    /// A vector of trust anchor certificates to verify the report signature and
    /// chain against.
    trust_anchors: Vec<MbedtlsBox<Certificate>>,
    /// A vector of report verifiers, one of which must succeed.
    or_verifiers: Vec<StatusKind>,
    /// A vector of report verifiers, all of which must succeed.
    and_verifiers: Vec<AvrKind>,
}

impl IasReportVerifier {
    /// Create a new IAS report verifier
    pub fn new(
        trust_anchors: Vec<MbedtlsBox<Certificate>>,
        or_verifiers: Vec<StatusKind>,
        and_verifiers: Vec<AvrKind>,
    ) -> Self {
        Self {
            trust_anchors,
            or_verifiers,
            and_verifiers,
        }
    }

    /// Verify the given IAS report using this verifier object.
    pub fn verify(&self, report: &VerificationReport) -> Result<VerificationReportData, Error> {
        // Here's the background information for this code:
        //
        //  1. An X509 certificate can be signed by only one issuer.
        //  2. mbedtls' certificates-list API demands certs in the RFC5246
        //     order (endpoint cert first, every other cert signed the
        //     cert preceeding it in the list).
        //  3. I don't recall Intel's specification mentioning certificate
        //     ordering at all (meaning they can change it w/o warning).
        //  4. mbedtls' certificates-list API isn't actually exposed to us,
        //     anyways.
        //
        // As a result, we need to find the cert which signed the data (this
        // doubles as the signature check), then find a way back up the
        // derived chain until we either hit a max-height limit (and fail),
        // or top out at something that was itself signed by a trust_anchor.
        //
        // If we have the root CA that's in our trust_anchor list in the
        // provided chain, then it will pass the "signed by trust_anchor"
        // check, because all root CAs are self-signed by definition.
        //
        // If Intel doesn't provide the root CA in the chain, then the last
        // entry in the derived chain will still contain the intermediate CA,
        // which will (obviously) be signed by the root CA. Combined, these
        // two situations mean checking that the last cert in the list was
        // signed by a trust anchor will result in success.
        //
        // The third possible scenario, which is that one of the certs in the
        // middle of the chain is in our trust_anchors list. In this case, our
        // explicit trust of a cert makes any other issuer relationships
        // irrelevant, including relationships with blocklisted issuers.
        //
        // This scenario is less likely, but would occur when someone is
        // trying to deprecate an existing authority in favor of a new one. In
        // this case, they sign the old CA with the new CA, so things which
        // trust the new CA also trust the old CA "for free". When everyone
        // has the new CA in their trust list, they start issuing certs from
        // the new CA, and stop renewing certs from the old CA. The old CA is
        // gradually phased out of use as the certs it issued expire, and is
        // eventually allowed to expire itself, or revoked by the new CA.
        //
        // As a result, if any pubkey in the actual chain matches the pubkey
        // of a trust anchor, then we can consider the actual chain trusted.
        //
        // Lastly, it's possible that Intel provides multiple complete chains
        // terminating at different root CAs. That is, the signature is tied
        // to pubkey X, but there are multiple leaf certificates in the
        // provided certs for pubkey X, and each one has its own path back to
        // a trust anchor.

        if report.chain.is_empty() {
            return Err(Error::NoChain);
        }

        // Construct a verification profile for what kind of X509 chain we
        // will support
        let profile = Profile::new(
            vec![HashType::Sha256, HashType::Sha384, HashType::Sha512],
            vec![PkType::Rsa, PkType::Ecdsa],
            vec![
                EcGroupId::Curve25519,
                EcGroupId::SecP256K1,
                EcGroupId::SecP256R1,
                EcGroupId::SecP384R1,
                EcGroupId::SecP521R1,
            ],
            2048,
        );

        // Intel uses rsa-sha256 as their signature algorithm, which means
        // the signature is actually over the sha256 hash of the data, not
        // the data itself. mbedtls is primitive enough that we need to do
        // these steps ourselves.
        let hash = Sha256::digest(report.http_body.as_bytes());

        // Cloned here because it needs to be mutable because mbedtls.
        let mut trust_anchors = self.trust_anchors.clone();

        let parsed_chain: Vec<MbedtlsBox<Certificate>> = report
            .chain
            .iter()
            .filter_map(|maybe_der_bytes| Certificate::from_der(maybe_der_bytes).ok())
            .collect();

        parsed_chain
            .iter()
            // First, find any certs which contain the report signer's pubkey
            .filter_map(|src_cert| {
                let mut newcert = src_cert.clone();
                newcert
                    .public_key_mut()
                    .verify(HashType::Sha256, hash.as_slice(), report.sig.as_ref())
                    .and(Ok(newcert))
                    .ok()
            })
            // Then construct a set of chains, one for each signer certificate
            .filter_map(|cert| {
                let mut signer_chain = vec![cert];
                'outer: loop {
                    // Exclude any signing chains greater than our max depth
                    if signer_chain.len() > MAX_CHAIN_DEPTH {
                        return None;
                    }

                    for chain_cert in &parsed_chain {
                        // The verify function takes lists of certificates, so make lists of size
                        // one for each verification.
                        let mut chain_cert = chain_cert.clone();
                        let mut chain_cert_single = MbedtlsList::new();
                        chain_cert_single.push(chain_cert.clone());

                        let existing_cert = signer_chain
                            .last_mut()
                            .expect("Somehow our per-signer chain was empty");
                        let mut existing_cert_single = MbedtlsList::new();
                        existing_cert_single.push(existing_cert.clone());

                        if existing_cert.public_key_mut().write_public_der_vec()
                            != chain_cert.public_key_mut().write_public_der_vec()
                            && Certificate::verify_with_profile(
                                &existing_cert_single,
                                &chain_cert_single,
                                None,
                                Some(&profile),
                                None,
                            )
                            .is_ok()
                        {
                            signer_chain.push(chain_cert);
                            continue 'outer;
                        }
                    }

                    break;
                }
                Some(signer_chain)
            })
            // Then see if any of those chains are connected to a trust anchor
            .find_map(|mut signer_chain| {
                let signer_toplevel = signer_chain
                    .last()
                    .expect("Signer chain was somehow emptied before use.");
                let mut signer_toplevel_single = MbedtlsList::new();
                signer_toplevel_single.push(signer_toplevel.clone());

                // First, check if the last element in the chain is signed by a trust anchor
                for cacert in &trust_anchors {
                    let mut cacert_single = MbedtlsList::new();
                    cacert_single.push(cacert.clone());
                    if Certificate::verify_with_profile(
                        &signer_toplevel_single,
                        &cacert_single,
                        None,
                        Some(&profile),
                        None,
                    )
                    .is_ok()
                    {
                        return Some(());
                    }
                }

                // Otherwise, check if any of the pubkeys in the chain are a trust anchor
                for cert in &mut signer_chain {
                    for cacert in &mut trust_anchors {
                        if cert.public_key_mut().write_public_der_vec()
                            == cacert.public_key_mut().write_public_der_vec()
                        {
                            return Some(());
                        }
                    }
                }
                None
            })
            .ok_or(Error::BadSignature)?;

        let report_data = VerificationReportData::try_from(report)?;

        if (self.and_verifiers.is_empty()
            || self
                .and_verifiers
                .iter()
                .all(|verifier| verifier.verify(&report_data)))
            && (self.or_verifiers.is_empty()
                || self
                    .or_verifiers
                    .iter()
                    .any(|verifier| verifier.verify(&report_data)))
        {
            Ok(report_data)
        } else {
            Err(Error::Verification(report_data))
        }
    }
}
