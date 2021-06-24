// Copyright (c) 2018-2021 The MobileCoin Foundation

//! Intel Attestation Report Verifier

use alloc::vec;

use crate::{
    error::{IasQuoteError, IasQuoteResult, VerifyError},
    ias::verify::{VerificationReport, VerificationReportData},
    nonce::IasNonce,
    quote::{Quote, QuoteSignType},
    types::{
        attributes::Attributes,
        basename::Basename,
        config_id::ConfigId,
        cpu_svn::CpuSecurityVersion,
        epid_group_id::EpidGroupId,
        ext_prod_id::ExtendedProductId,
        family_id::FamilyId,
        measurement::{MrEnclave, MrSigner},
        report_body::ReportBody,
        report_data::ReportDataMask,
        ConfigSecurityVersion, MiscSelect, ProductId, SecurityVersion,
    },
    IAS_SIGNING_ROOT_CERT_PEMS,
};
use alloc::{
    borrow::ToOwned,
    string::{String, ToString},
    vec::Vec,
};
use core::convert::TryFrom;
use displaydoc::Display;
use mbedtls::{
    alloc::{Box as MbedtlsBox, List as MbedtlsList},
    hash::Type as HashType,
    pk::{EcGroupId, Type as PkType},
    x509::{Certificate, Profile},
    Error as TlsError,
};

use mc_sgx_css::Signature;
use mc_sgx_types::SGX_FLAGS_DEBUG;
use serde::{Deserialize, Serialize};
use sha2::{digest::Digest, Sha256};

/// A trait which can be used to verify an object using pre-configured data
trait Verify<T>: Clone {
    /// Check the data against the verifier's contents, return true on success,
    /// false on failure.
    fn verify(&self, data: &T) -> bool;
}

/// An enumeration of errors which a [`Verifier`] can produce.
#[derive(Clone, Debug, Deserialize, Display, PartialEq, PartialOrd, Serialize)]
pub enum Error {
    /**
     * The user-provided array of trust anchor PEM contains an invalid
     * certificate.
     */
    InvalidTrustAnchor(String),
    /// The IAS report does not contain a certificate chain.
    NoChain,
    /**
     * The signature is invalid, or was produced by a public key we do not
     * trust.
     */
    BadSignature,
    /// There was an error parsing the JSON contents: {0}
    Parse(VerifyError),
    /**
     * The report was properly constructed, but did not meet security
     * requirements, report contents: {0:?}
     */
    Verification(VerificationReportData),
}

/// A builder structure used to construct a report verifier based on the
/// criteria specified.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct Verifier {
    /// A list of DER-encoded trust anchor certificates.
    trust_anchors: Vec<Vec<u8>>,
    report_body_verifiers: Vec<VerifyReportBodyType>,
    quote_verifiers: Vec<VerifyQuoteType>,
    ias_verifiers: Vec<VerifyIasReportDataType>,
    status_verifiers: Vec<VerifyIasReportDataType>,
}

/// Construct a new builder using the baked-in IAS root certificates and debug
/// settings.
impl Default for Verifier {
    fn default() -> Self {
        Self::new(IAS_SIGNING_ROOT_CERT_PEMS).expect("Invalid hard-coded certificates found")
    }
}

impl Verifier {
    /// Create a new builder object to generate an IAS report verifier using the
    /// given trust anchor.
    pub fn new(pem_trust_anchors: &[&str]) -> Result<Self, Error> {
        // We parse the PEM into certificates first, then back into the DER
        // bytes.
        let trust_anchors = pem_trust_anchors
            .iter()
            .map(|pem| {
                if !pem.ends_with('\0') {
                    let mut tmp_str = String::from(*pem);
                    tmp_str.push('\0');
                    Certificate::from_pem(tmp_str.as_bytes())
                } else {
                    Certificate::from_pem(pem.as_bytes())
                }
            })
            .collect::<Result<Vec<MbedtlsBox<Certificate>>, TlsError>>()
            .map_err(|e| Error::InvalidTrustAnchor(e.to_string()))?
            .into_iter()
            .map(|cert| cert.as_der().to_owned())
            .collect::<Vec<Vec<u8>>>();

        Ok(Self {
            trust_anchors,
            report_body_verifiers: Default::default(),
            quote_verifiers: Default::default(),
            ias_verifiers: Default::default(),
            status_verifiers: Default::default(),
        })
    }

    /// Verify that the nonce contained within the report matches the nonce
    /// provided.
    ///
    /// This is useful to prevent IAS report response replay attacks.
    pub fn nonce(&mut self, nonce: &IasNonce) -> &mut Self {
        self.ias_verifiers
            .push(VerifyIasReportDataType::Nonce(NonceVerifier {
                nonce: nonce.clone(),
            }));
        self
    }

    /// Verify that the PSE manifest hash matches the one given, and the result
    /// is successful.
    pub fn pse_result(&mut self, hash: &[u8]) -> &mut Self {
        self.ias_verifiers
            .push(VerifyIasReportDataType::Pse(PseVerifier {
                hash: hash.to_owned(),
            }));
        self
    }

    /// Verify that the basename in the quote matches the basename given.
    pub fn basename(&mut self, basename: &Basename) -> &mut Self {
        self.quote_verifiers
            .push(VerifyQuoteType::Basename(BasenameVerifier {
                basename: *basename,
            }));
        self
    }

    /// Verify that the EPID group ID in the quote matches the group ID given.
    ///
    /// This test is useful to ensure continuity of message flow.
    pub fn epid_group_id(&mut self, epid_group_id: &EpidGroupId) -> &mut Self {
        self.quote_verifiers
            .push(VerifyQuoteType::EpidGroupId(EpidGroupIdVerifier {
                epid_group_id: *epid_group_id,
            }));
        self
    }

    /// Verify that the quote body within the IAS report matches the existing
    /// quote exactly.
    pub fn quote_body(&mut self, quote: &Quote) -> &mut Self {
        self.quote_verifiers
            .push(VerifyQuoteType::Body(QuoteContentsEqVerifier {
                quote: quote.clone(),
            }));
        self
    }

    /// Verify that the quote body was created with the appropriate type
    /// (linkable vs. unlinkable).
    pub fn sign_type(&mut self, sign_type: QuoteSignType) -> &mut Self {
        self.quote_verifiers
            .push(VerifyQuoteType::SignType(SignTypeVerifier { sign_type }));
        self
    }

    /// Verify that the quoting enclave's security version is at least the given
    /// version.
    pub fn qe_security_version(&mut self, qe_svn: SecurityVersion) -> &mut Self {
        self.quote_verifiers
            .push(VerifyQuoteType::QeSvn(QeSecurityVersionVerifier { qe_svn }));
        self
    }

    /// Verify that the quoting enclave's security version is at least the given
    /// version.
    pub fn pce_security_version(&mut self, pce_svn: SecurityVersion) -> &mut Self {
        self.quote_verifiers
            .push(VerifyQuoteType::PceSvn(PceSecurityVersionVerifier {
                pce_svn,
            }));
        self
    }

    /// Verify the EPID signature is of the type indicated.
    pub fn quote_sign(&mut self, sign_type: QuoteSignType) -> &mut Self {
        self.quote_verifiers
            .push(VerifyQuoteType::SignType(SignTypeVerifier { sign_type }));
        self
    }

    /// Verify the quote's XEID matches the given value
    pub fn xeid(&mut self, xeid: u32) -> &mut Self {
        self.quote_verifiers
            .push(VerifyQuoteType::Xeid(XeidVerifier { xeid }));
        self
    }

    /// Verify the report body attributes matches the given value.
    pub fn attributes(&mut self, attributes: &Attributes) -> &mut Self {
        self.report_body_verifiers
            .push(VerifyReportBodyType::Attributes(AttributesVerifier {
                attributes: *attributes,
            }));
        self
    }

    /// Verify the report body config ID matches the given value.
    pub fn config_id(&mut self, config_id: &ConfigId) -> &mut Self {
        self.report_body_verifiers
            .push(VerifyReportBodyType::ConfigId(ConfigIdVerifier {
                config_id: *config_id,
            }));
        self
    }

    /// Verify the report body config version is at least the given value.
    pub fn config_version(&mut self, config_svn: ConfigSecurityVersion) -> &mut Self {
        self.report_body_verifiers
            .push(VerifyReportBodyType::ConfigVersion(ConfigVersionVerifier {
                config_svn,
            }));
        self
    }

    /// Verify the report body CPU version is at least the given value.
    pub fn cpu_version(&mut self, cpu_svn: &CpuSecurityVersion) -> &mut Self {
        self.report_body_verifiers
            .push(VerifyReportBodyType::CpuVersion(CpuVersionVerifier {
                cpu_svn: *cpu_svn,
            }));
        self
    }

    /// Verify the enclave debug mode is as-expected
    pub fn debug(&mut self, allow_debug: bool) -> &mut Self {
        self.report_body_verifiers
            .push(VerifyReportBodyType::Debug(DebugVerifier { allow_debug }));
        self
    }

    /// Verify the report data matches the data mask given
    pub fn report_data(&mut self, report_data: &ReportDataMask) -> &mut Self {
        self.report_body_verifiers
            .push(VerifyReportBodyType::Data(DataVerifier {
                data: *report_data,
            }));
        self
    }

    /// Verify the report body extended product ID matches the given value.
    pub fn extended_product_id(&mut self, ext_prod_id: &ExtendedProductId) -> &mut Self {
        self.report_body_verifiers
            .push(VerifyReportBodyType::ExtendedProductId(
                ExtendedProductIdVerifier {
                    ext_prod_id: *ext_prod_id,
                },
            ));
        self
    }

    /// Verify the report body family ID matches the given value.
    pub fn family_id(&mut self, family_id: &FamilyId) -> &mut Self {
        self.report_body_verifiers
            .push(VerifyReportBodyType::FamilyId(FamilyIdVerifier {
                family_id: *family_id,
            }));
        self
    }

    /// Verify the report body misc selection matches the given value.
    pub fn misc_select(&mut self, misc_select: MiscSelect) -> &mut Self {
        self.report_body_verifiers
            .push(VerifyReportBodyType::MiscSelect(MiscSelectVerifier {
                misc_select,
            }));
        self
    }

    /// Verify the report body product ID matches the given value.
    pub fn product_id(&mut self, product_id: ProductId) -> &mut Self {
        self.report_body_verifiers
            .push(VerifyReportBodyType::ProductId(ProductIdVerifier {
                product_id,
            }));
        self
    }

    /// Verify the report body (enclave) version is at least the given value.
    pub fn version(&mut self, version: SecurityVersion) -> &mut Self {
        self.report_body_verifiers
            .push(VerifyReportBodyType::Version(VersionVerifier { version }));
        self
    }

    /// Verify the given MrEnclave-based status verifier succeeds
    pub fn mr_enclave(&mut self, verifier: MrEnclaveVerifier) -> &mut Self {
        self.status_verifiers
            .push(VerifyIasReportDataType::Enclave(verifier));
        self
    }

    /// Verify the given MrSigner-based status verifier succeeds
    pub fn mr_signer(&mut self, verifier: MrSignerVerifier) -> &mut Self {
        self.status_verifiers
            .push(VerifyIasReportDataType::Signer(verifier));
        self
    }

    /// Compile the report verifier which a report will be given to
    pub fn verify(&self, report: &VerificationReport) -> Result<VerificationReportData, Error> {
        // Build a list of quote verifiers
        let mut quote_verifiers = self.quote_verifiers.clone();
        quote_verifiers.push(VerifyQuoteType::ReportBody(ReportBodyVerifier {
            body_verifiers: self.report_body_verifiers.clone(),
        }));

        // Build the list of IAS report data verifiers (including a quote
        // verifier)
        let mut and_verifiers = self.ias_verifiers.clone();
        and_verifiers.push(VerifyIasReportDataType::Quote(QuoteVerifier {
            quote_verifiers,
        }));

        let trust_anchors = self
            .trust_anchors
            .iter()
            .map(|cert_der| {
                Certificate::from_der(cert_der.as_slice())
                    .expect("Trust anchors modified after Verifier creation")
            })
            .collect::<Vec<MbedtlsBox<Certificate>>>();

        // Construct the top-level verifier.
        IasReportVerifier {
            trust_anchors,
            or_verifiers: self.status_verifiers.clone(),
            and_verifiers,
        }
        .verify(report)
    }
}

/// A structure which can verify a top-level report.
#[derive(Debug)]
struct IasReportVerifier {
    /// A vector of trust anchor certificates to verify the report signature and
    /// chain against.
    trust_anchors: Vec<MbedtlsBox<Certificate>>,
    /// A vector of report verifiers, one of which must succeed.
    or_verifiers: Vec<VerifyIasReportDataType>,
    /// A vector of report verifiers, all of which must succeed.
    and_verifiers: Vec<VerifyIasReportDataType>,
}

impl From<VerifyError> for Error {
    fn from(src: VerifyError) -> Error {
        Error::Parse(src)
    }
}

const MAX_CHAIN_DEPTH: usize = 5;

impl IasReportVerifier {
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
            // First, find any certs for the signer pubkey
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
                let mut signer_chain: Vec<MbedtlsBox<Certificate>> = vec![cert];
                'outer: loop {
                    // Exclude any signing changes greater than our max depth
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

/// An enumeration of possible report-data verifier
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
enum VerifyIasReportDataType {
    /// A verifier that checks the nonce of the IAS report
    Nonce(NonceVerifier),
    /// A verifier that checks the MRENCLAVE value and advisory IDs of the
    /// examined report
    Enclave(MrEnclaveVerifier),
    /// A verifier that checks the MRSIGNER value and advisory IDs of the
    /// examined report
    Signer(MrSignerVerifier),
    /// A verifier that chains to a list of quote verifiers.
    Quote(QuoteVerifier),
    /// A verifier that checks the PSE manifest hash and result
    Pse(PseVerifier),
}

impl Verify<VerificationReportData> for VerifyIasReportDataType {
    fn verify(&self, report_data: &VerificationReportData) -> bool {
        match self {
            VerifyIasReportDataType::Nonce(v) => v.verify(report_data),
            VerifyIasReportDataType::Enclave(v) => v.verify(report_data),
            VerifyIasReportDataType::Signer(v) => v.verify(report_data),
            VerifyIasReportDataType::Quote(v) => v.verify(report_data),
            VerifyIasReportDataType::Pse(v) => v.verify(report_data),
        }
    }
}

/// A [`VerifyIasReportData`] implementation that will check report data for the
/// presence of the given IAS nonce.
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
struct NonceVerifier {
    /// The nonce to be checked for.
    pub nonce: IasNonce,
}

impl Verify<VerificationReportData> for NonceVerifier {
    fn verify(&self, data: &VerificationReportData) -> bool {
        data.nonce
            .as_ref()
            .map(|v| v.eq(&self.nonce))
            .unwrap_or(false)
    }
}

/// A helper function used to check exceptions to the quote error = fail rule.
fn check_ids(quote_status: &IasQuoteResult, config_ids: &[String], sw_ids: &[String]) -> bool {
    match quote_status {
        Ok(_) => true,
        Err(IasQuoteError::ConfigurationNeeded { advisory_ids, .. }) => {
            advisory_ids.iter().all(|id| config_ids.contains(id))
        }
        Err(IasQuoteError::SwHardeningNeeded { advisory_ids, .. }) => {
            advisory_ids.iter().all(|id| sw_ids.contains(id))
        }
        Err(IasQuoteError::ConfigurationAndSwHardeningNeeded { advisory_ids, .. }) => advisory_ids
            .iter()
            .all(|id| config_ids.contains(id) || sw_ids.contains(id)),
        Err(_) => false,
    }
}

/// A [`VerifyIasReportData`] implementation that will check if the enclave in
/// question has the given MrEnclave, and has no other IAS report status issues.
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub struct MrEnclaveVerifier {
    mr_enclave: MrEnclave,
    config_ids: Vec<String>,
    sw_ids: Vec<String>,
}

impl MrEnclaveVerifier {
    /// Create a new status verifier that will check for the existence of the
    /// given MrEnclave.
    pub fn new(mr_enclave: MrEnclave) -> MrEnclaveVerifier {
        Self {
            mr_enclave,
            config_ids: Default::default(),
            sw_ids: Default::default(),
        }
    }

    /// Assume an enclave with the specified measurement does not need
    /// BIOS configuration changes to address the provided advisory ID.
    ///
    /// This method should only be used when advised by an enclave author.
    pub fn allow_config_advisory(&mut self, id: &str) -> &mut Self {
        self.config_ids.push(id.to_owned());
        self
    }

    /// Assume an enclave with the specified measurement does not need
    /// BIOS configuration changes to address the provided advisory IDs.
    ///
    /// This method should only be used when advised by an enclave author.
    pub fn allow_config_advisories(&mut self, ids: &[&str]) -> &mut Self {
        for id in ids {
            self.config_ids.push((*id).to_owned());
        }
        self
    }

    /// Assume the given MrEnclave value has the appropriate software/build-time
    /// hardening for the given advisory ID.
    ///
    /// This method should only be used when advised by an enclave author.
    pub fn allow_hardening_advisory(&mut self, id: &str) -> &mut Self {
        self.sw_ids.push(id.to_owned());
        self
    }

    /// Assume the given MrEnclave value has the appropriate software/build-time
    /// hardening for the given advisory IDs.
    ///
    /// This method should only be used when advised by an enclave author.
    pub fn allow_hardening_advisories(&mut self, ids: &[&str]) -> &mut Self {
        for id in ids {
            self.sw_ids.push((*id).to_owned());
        }
        self
    }
}

impl From<Signature> for MrEnclaveVerifier {
    fn from(src: Signature) -> Self {
        Self::new(src.mrenclave().clone().into())
    }
}

impl Verify<VerificationReportData> for MrEnclaveVerifier {
    fn verify(&self, data: &VerificationReportData) -> bool {
        if let Ok(report_body) = data.quote.report_body() {
            self.mr_enclave == report_body.mr_enclave()
                && check_ids(&data.quote_status, &self.config_ids, &self.sw_ids)
        } else {
            false
        }
    }
}

/// A [`VerifyIasReportData`] implementation that will check if the enclave in
/// question has the given MrSigner value, and has no other IAS report status
/// issues.
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub struct MrSignerVerifier {
    mr_signer: MrSigner,
    product_id: ProductId,
    minimum_svn: SecurityVersion,
    config_ids: Vec<String>,
    sw_ids: Vec<String>,
}

impl MrSignerVerifier {
    /// Create a new status verifier that will check for the existence of the
    /// given MrSigner.
    pub fn new(
        mr_signer: MrSigner,
        product_id: ProductId,
        minimum_svn: SecurityVersion,
    ) -> MrSignerVerifier {
        Self {
            mr_signer,
            product_id,
            minimum_svn,
            config_ids: Default::default(),
            sw_ids: Default::default(),
        }
    }

    /// Assume an enclave with the specified measurement does not need
    /// BIOS configuration changes to address the provided advisory ID.
    ///
    /// This method should only be used when advised by an enclave author.
    pub fn allow_config_advisory(&mut self, id: &str) -> &mut Self {
        self.config_ids.push(id.to_owned());
        self
    }

    /// Assume an enclave with the specified measurement does not need
    /// BIOS configuration changes to address the provided advisory IDs.
    ///
    /// This method should only be used when advised by an enclave author.
    pub fn allow_config_advisories(&mut self, ids: &[&str]) -> &mut Self {
        for id in ids {
            self.config_ids.push((*id).to_owned());
        }
        self
    }

    /// Assume an enclave with the specified measurement has the appropriate
    /// software/build-time hardening for the given advisory ID.
    ///
    /// This method should only be used when advised by an enclave author.
    pub fn allow_hardening_advisory(&mut self, id: &str) -> &mut Self {
        self.sw_ids.push(id.to_owned());
        self
    }

    /// Assume an enclave with the specified measurement has the appropriate
    /// software/build-time hardening for the given advisory IDs.
    ///
    /// This method should only be used when advised by an enclave author.
    pub fn allow_hardening_advisories(&mut self, ids: &[&str]) -> &mut Self {
        for id in ids {
            self.sw_ids.push((*id).to_owned());
        }
        self
    }
}

impl From<Signature> for MrSignerVerifier {
    fn from(src: Signature) -> Self {
        Self::new(src.mrsigner().into(), src.product_id(), src.version())
    }
}

impl From<&Signature> for MrSignerVerifier {
    fn from(src: &Signature) -> Self {
        Self::new(src.mrsigner().into(), src.product_id(), src.version())
    }
}

impl Verify<VerificationReportData> for MrSignerVerifier {
    fn verify(&self, data: &VerificationReportData) -> bool {
        if let Ok(report_body) = data.quote.report_body() {
            self.mr_signer == report_body.mr_signer()
                && report_body.product_id() == self.product_id
                && report_body.security_version() >= self.minimum_svn
                && check_ids(&data.quote_status, &self.config_ids, &self.sw_ids)
        } else {
            false
        }
    }
}

/// A [`VerifyIasReportData`] implementation which applies a list of verifiers
/// against the quote structure.
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
struct QuoteVerifier {
    quote_verifiers: Vec<VerifyQuoteType>,
}

impl Verify<VerificationReportData> for QuoteVerifier {
    fn verify(&self, data: &VerificationReportData) -> bool {
        for verifier in &self.quote_verifiers {
            if !verifier.verify(&data.quote) {
                return false;
            }
        }

        true
    }
}

/// A [`VerifyIasReportData`] implementation which checks the PSE result is
/// acceptable and was made over a particular hash.
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
struct PseVerifier {
    hash: Vec<u8>,
}

impl Verify<VerificationReportData> for PseVerifier {
    fn verify(&self, data: &VerificationReportData) -> bool {
        if let Some(hash) = &data.pse_manifest_hash {
            if let Some(Ok(())) = &data.pse_manifest_status {
                self.hash.eq(hash)
            } else {
                false
            }
        } else {
            false
        }
    }
}

/// An enumeration of quote content verifiers
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
enum VerifyQuoteType {
    Basename(BasenameVerifier),
    /// Verify the quote body with the report matches (exactly) the one
    /// provided.
    Body(QuoteContentsEqVerifier),
    /// Verify the EPID group id within the report matches the one provided.
    EpidGroupId(EpidGroupIdVerifier),
    /// Verify the quoting enclave's security version is at least the one given.
    QeSvn(QeSecurityVersionVerifier),
    /// Verify the provisioning certificate enclave's security version is at
    /// least the one given.
    PceSvn(PceSecurityVersionVerifier),
    /// Verify the report body using a vector of report body verifiers.
    ReportBody(ReportBodyVerifier),
    /// Verify the sign type of the report matches what's expected.
    SignType(SignTypeVerifier),
    /// Verify the XEID matches what is expected
    Xeid(XeidVerifier),
}

impl Verify<Quote> for VerifyQuoteType {
    fn verify(&self, quote: &Quote) -> bool {
        match self {
            VerifyQuoteType::Basename(v) => v.verify(quote),
            VerifyQuoteType::Body(v) => v.verify(quote),
            VerifyQuoteType::EpidGroupId(v) => v.verify(quote),
            VerifyQuoteType::QeSvn(v) => v.verify(quote),
            VerifyQuoteType::PceSvn(v) => v.verify(quote),
            VerifyQuoteType::ReportBody(v) => v.verify(quote),
            VerifyQuoteType::SignType(v) => v.verify(quote),
            VerifyQuoteType::Xeid(v) => v.verify(quote),
        }
    }
}

/// A [`Verify<Quote>`] implementation that will check if the basename is as
/// expected.
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
struct BasenameVerifier {
    basename: Basename,
}

impl Verify<Quote> for BasenameVerifier {
    fn verify(&self, quote: &Quote) -> bool {
        quote
            .basename()
            .map(|basename| basename == self.basename)
            .unwrap_or(false)
    }
}

/// A [`Verify<Quote>`] implementation that will simply check that the quote
/// contained in the IAS report matches the quote in this object.
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
struct QuoteContentsEqVerifier {
    quote: Quote,
}

impl Verify<Quote> for QuoteContentsEqVerifier {
    fn verify(&self, quote: &Quote) -> bool {
        self.quote.contents_eq(quote)
    }
}

/// A [`Verify<Quote>`] implementation that will check if the EPID group ID in
/// the IAS quote is expected.
///
/// This can form a very basic sanity check to verify that the SigRL provided
/// for the quote is as expected.
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
struct EpidGroupIdVerifier {
    epid_group_id: EpidGroupId,
}

impl Verify<Quote> for EpidGroupIdVerifier {
    fn verify(&self, quote: &Quote) -> bool {
        quote
            .epid_group_id()
            .map(|epid_group_id| epid_group_id == self.epid_group_id)
            .unwrap_or(false)
    }
}

/// A [`Verify<Quote>`] implementation that will simply check that the QE
/// security version is at least the version given.
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
struct PceSecurityVersionVerifier {
    pce_svn: SecurityVersion,
}

impl Verify<Quote> for PceSecurityVersionVerifier {
    fn verify(&self, quote: &Quote) -> bool {
        quote
            .pce_security_version()
            .map(|pce_svn| pce_svn >= self.pce_svn)
            .unwrap_or(false)
    }
}

/// A [`Verify<Quote>`] implementation that will simply check that the QE
/// security version is at least the version given.
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
struct QeSecurityVersionVerifier {
    qe_svn: SecurityVersion,
}

impl Verify<Quote> for QeSecurityVersionVerifier {
    fn verify(&self, quote: &Quote) -> bool {
        quote
            .qe_security_version()
            .map(|qe_svn| qe_svn >= self.qe_svn)
            .unwrap_or(false)
    }
}

/// A [`Verify<Quote>`] implementation that will collect the results of many
/// independent [`Verify<ReportBody>`] implementations.
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
struct ReportBodyVerifier {
    body_verifiers: Vec<VerifyReportBodyType>,
}

impl Verify<Quote> for ReportBodyVerifier {
    fn verify(&self, quote: &Quote) -> bool {
        if let Ok(report_body) = quote.report_body() {
            let mut result = 0xffff_ffff;
            for verifier in &self.body_verifiers {
                result &= verifier.verify(&report_body) as u32;
            }
            result != 0
        } else {
            false
        }
    }
}

/// A [`Verify<Quote>`] implementation that will check if the EPID signature
/// type is expected.
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
struct SignTypeVerifier {
    sign_type: QuoteSignType,
}

impl Verify<Quote> for SignTypeVerifier {
    fn verify(&self, quote: &Quote) -> bool {
        if let Ok(sign_type) = quote.sign_type() {
            sign_type == self.sign_type
        } else {
            false
        }
    }
}

/// A [`Verify<Quote>`] implementation that will check if the XEID matches
/// expectations.
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
struct XeidVerifier {
    xeid: u32,
}

impl Verify<Quote> for XeidVerifier {
    fn verify(&self, quote: &Quote) -> bool {
        quote.xeid().map(|xeid| xeid == self.xeid).unwrap_or(false)
    }
}

/// An enumeration of known report body verifier types.
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
enum VerifyReportBodyType {
    /// Verify the attributes matches the one specified.
    Attributes(AttributesVerifier),
    /// Verify the config ID matches the one specified.
    ConfigId(ConfigIdVerifier),
    /// Verify the config version is at least the one specified.
    ConfigVersion(ConfigVersionVerifier),
    /// Verify the CPU version is at least the one specified.
    CpuVersion(CpuVersionVerifier),
    /// Verify the enclave is not running in debug mode.
    Debug(DebugVerifier),
    /// Verify whether the data matches.
    Data(DataVerifier),
    /// Verify the extended product ID matches the one specified.
    ExtendedProductId(ExtendedProductIdVerifier),
    /// Verify the family ID matches the one specified
    FamilyId(FamilyIdVerifier),
    /// Verify the misc select value matches the one specified.
    MiscSelect(MiscSelectVerifier),
    /// Verify the product ID matches the one specified.
    ProductId(ProductIdVerifier),
    /// Verify the version is at least as new as the one specified.
    Version(VersionVerifier),
}

impl Verify<ReportBody> for VerifyReportBodyType {
    fn verify(&self, report_body: &ReportBody) -> bool {
        match self {
            VerifyReportBodyType::Attributes(v) => v.verify(report_body),
            VerifyReportBodyType::ConfigId(v) => v.verify(report_body),
            VerifyReportBodyType::ConfigVersion(v) => v.verify(report_body),
            VerifyReportBodyType::CpuVersion(v) => v.verify(report_body),
            VerifyReportBodyType::Debug(v) => v.verify(report_body),
            VerifyReportBodyType::Data(v) => v.verify(report_body),
            VerifyReportBodyType::ExtendedProductId(v) => v.verify(report_body),
            VerifyReportBodyType::FamilyId(v) => v.verify(report_body),
            VerifyReportBodyType::MiscSelect(v) => v.verify(report_body),
            VerifyReportBodyType::ProductId(v) => v.verify(report_body),
            VerifyReportBodyType::Version(v) => v.verify(report_body),
        }
    }
}

/// A [`Verify<ReportBody>`] implementation that will check if the enclave flags
/// match the given attributes.
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
struct AttributesVerifier {
    attributes: Attributes,
}

impl Verify<ReportBody> for AttributesVerifier {
    fn verify(&self, report_body: &ReportBody) -> bool {
        self.attributes == report_body.attributes()
    }
}

/// A [`Verify<ReportBody>`] implementation that will check if the enclave
/// configuration ID matches the given value
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
struct ConfigIdVerifier {
    config_id: ConfigId,
}

impl Verify<ReportBody> for ConfigIdVerifier {
    fn verify(&self, report_body: &ReportBody) -> bool {
        self.config_id == report_body.config_id()
    }
}

/// A [`Verify<ReportBody>`] implementation that will check if the enclave
/// configuration version is at least the version specified.
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
struct ConfigVersionVerifier {
    config_svn: ConfigSecurityVersion,
}

impl Verify<ReportBody> for ConfigVersionVerifier {
    fn verify(&self, report_body: &ReportBody) -> bool {
        self.config_svn <= report_body.config_security_version()
    }
}

/// A [`Verify<ReportBody>`] implementation that will check if the cpu version
/// is at least the version specified.
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
struct CpuVersionVerifier {
    cpu_svn: CpuSecurityVersion,
}

impl Verify<ReportBody> for CpuVersionVerifier {
    fn verify(&self, report_body: &ReportBody) -> bool {
        self.cpu_svn <= report_body.cpu_security_version()
    }
}

/// A [`Verify<ReportBody>`] implementation that will check if the enclave in
/// question is allowed to run in debug mode.
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
struct DebugVerifier {
    allow_debug: bool,
}

impl Verify<ReportBody> for DebugVerifier {
    fn verify(&self, report_body: &ReportBody) -> bool {
        self.allow_debug || (report_body.attributes().flags() & SGX_FLAGS_DEBUG == 0)
    }
}

/// A [`Verify<ReportBody>`] implementation that will check if the enclave's
/// report data matches the mask given.
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
struct DataVerifier {
    data: ReportDataMask,
}

impl Verify<ReportBody> for DataVerifier {
    fn verify(&self, report_body: &ReportBody) -> bool {
        self.data == report_body.report_data()
    }
}

/// A [`Verify<ReportBody>`] implementation that will check if the enclave's
/// extended product ID matches the one given.
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
struct ExtendedProductIdVerifier {
    ext_prod_id: ExtendedProductId,
}

impl Verify<ReportBody> for ExtendedProductIdVerifier {
    fn verify(&self, report_body: &ReportBody) -> bool {
        self.ext_prod_id == report_body.extended_product_id()
    }
}

/// A [`Verify<ReportBody>`] implementation that will check if the enclave's
/// family ID matches the one given.
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
struct FamilyIdVerifier {
    family_id: FamilyId,
}

impl Verify<ReportBody> for FamilyIdVerifier {
    fn verify(&self, report_body: &ReportBody) -> bool {
        self.family_id == report_body.family_id()
    }
}

/// A [`Verify<ReportBody>`] implementation that will check if the enclave's
/// misc select value matches the one given.
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
struct MiscSelectVerifier {
    misc_select: MiscSelect,
}

impl Verify<ReportBody> for MiscSelectVerifier {
    fn verify(&self, report_body: &ReportBody) -> bool {
        self.misc_select == report_body.misc_select()
    }
}

/// A [`Verify<ReportBody>`] implementation that will check if the enclave's
/// product ID matches the one given.
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
struct ProductIdVerifier {
    product_id: ProductId,
}

impl Verify<ReportBody> for ProductIdVerifier {
    fn verify(&self, report_body: &ReportBody) -> bool {
        self.product_id == report_body.product_id()
    }
}

/// A [`Verify<ReportBody>`] implementation that will check if the enclave's
/// security version is at least the one given.
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
struct VersionVerifier {
    version: SecurityVersion,
}

impl Verify<ReportBody> for VersionVerifier {
    fn verify(&self, report_body: &ReportBody) -> bool {
        self.version <= report_body.security_version()
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::ias::verify::VerificationSignature;
    use mc_sgx_types::{
        sgx_attributes_t, sgx_basename_t, sgx_cpu_svn_t, sgx_measurement_t, sgx_report_body_t,
        sgx_report_data_t,
    };
    use mc_util_encodings::{FromBase64, FromHex};

    extern crate std;

    const BASE64_QUOTE: &str = include_str!("../../data/test/quote_ok.txt");
    const BASE64_QUOTE2: &str = include_str!("../../data/test/quote_configuration_needed.txt");
    const IAS_OK: &str = include_str!("../../data/test/ias_ok.json");
    const IAS_CONFIG: &str = include_str!("../../data/test/ias_config.json");
    const IAS_SW: &str = include_str!("../../data/test/ias_sw.json");
    const IAS_CONFIG_SW: &str = include_str!("../../data/test/ias_config_sw.json");
    const ONES: [u8; 64] = [0xffu8; 64];
    const REPORT_BODY_SRC: sgx_report_body_t = sgx_report_body_t {
        cpu_svn: sgx_cpu_svn_t {
            svn: [1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16],
        },
        misc_select: 17,
        reserved1: [0u8; 12],
        isv_ext_prod_id: [1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16],
        attributes: sgx_attributes_t {
            flags: 0x0102_0304_0506_0708,
            xfrm: 0x0807_0605_0403_0201,
        },
        mr_enclave: sgx_measurement_t {
            m: [
                17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37,
                38, 39, 40, 41, 42, 43, 43, 44, 45, 46, 47,
            ],
        },
        reserved2: [0u8; 32],
        mr_signer: sgx_measurement_t {
            m: [
                48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64, 65, 66, 67, 68,
                69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79,
            ],
        },
        reserved3: [0u8; 32],
        config_id: [
            80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 91, 92, 93, 94, 95, 96, 97, 98, 99, 100,
            101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 112, 113, 114, 115, 116, 117,
            118, 119, 120, 121, 122, 123, 124, 125, 126, 127, 128, 129, 130, 131, 132, 133, 134,
            135, 136, 137, 138, 139, 140, 141, 142, 143,
        ],
        isv_prod_id: 144,
        isv_svn: 145,
        config_svn: 146,
        reserved4: [0u8; 42],
        isv_family_id: [
            147, 148, 149, 150, 151, 152, 153, 154, 155, 156, 157, 158, 159, 160, 161, 162,
        ],
        report_data: sgx_report_data_t {
            d: [
                163, 164, 165, 166, 167, 168, 169, 170, 171, 172, 173, 174, 175, 176, 177, 178,
                179, 180, 181, 182, 183, 184, 185, 186, 187, 188, 189, 190, 191, 192, 193, 194,
                195, 196, 197, 198, 199, 200, 201, 202, 203, 204, 205, 206, 207, 208, 209, 210,
                211, 212, 213, 214, 215, 216, 217, 218, 219, 220, 221, 222, 223, 224, 225, 226,
            ],
        },
    };
    const MR_ENCLAVE: sgx_measurement_t = sgx_measurement_t {
        m: [
            247, 180, 107, 31, 41, 201, 41, 41, 32, 42, 25, 79, 7, 29, 232, 138, 9, 180, 143, 195,
            110, 244, 197, 245, 247, 21, 202, 61, 246, 188, 124, 234,
        ],
    };
    const MR_SIGNER: sgx_measurement_t = sgx_measurement_t {
        m: [
            126, 229, 226, 157, 116, 98, 63, 219, 198, 251, 241, 69, 75, 230, 243, 187, 11, 134,
            193, 35, 102, 183, 180, 120, 173, 19, 53, 62, 68, 222, 132, 17,
        ],
    };
    const TEST_ANCHORS: &[&str] = &[include_str!(
        "../../data/Dev_AttestationReportSigningCACert.pem"
    )];

    fn get_ias_report() -> VerificationReport {
        VerificationReport {
            sig: VerificationSignature::from(vec![164u8, 105, 80, 134, 234, 173, 20, 233, 176, 192, 25, 170, 37, 122, 173, 94, 120, 55, 98, 212, 183, 187, 59, 31, 240, 29, 174, 87, 172, 54, 130, 3, 13, 59, 86, 196, 184, 158, 92, 217, 70, 198, 227, 246, 144, 228, 146, 81, 119, 241, 39, 69, 6, 15, 100, 53, 62, 28, 53, 194, 127, 121, 234, 167, 234, 97, 45, 195, 138, 118, 4, 207, 165, 114, 78, 22, 85, 167, 77, 74, 135, 25, 115, 81, 97, 222, 27, 227, 110, 0, 210, 66, 161, 3, 166, 188, 114, 73, 50, 201, 9, 138, 41, 27, 144, 163, 91, 255, 221, 42, 194, 86, 198, 103, 130, 155, 90, 64, 61, 249, 48, 106, 69, 205, 196, 118, 35, 153, 243, 197, 124, 204, 79, 205, 125, 181, 12, 190, 13, 25, 192, 30, 53, 190, 149, 11, 230, 63, 116, 15, 55, 231, 226, 169, 242, 126, 181, 8, 81, 98, 140, 166, 26, 138, 66, 4, 170, 178, 111, 158, 129, 140, 217, 171, 157, 212, 23, 225, 191, 137, 187, 254, 127, 111, 138, 209, 39, 250, 26, 250, 96, 217, 48, 113, 99, 175, 107, 179, 17, 213, 139, 116, 98, 193, 149, 89, 202, 239, 248, 42, 155, 39, 67, 173, 142, 59, 191, 54, 26, 196, 19, 67, 25, 159, 210, 199, 112, 156, 218, 117, 76, 1, 30, 251, 240, 15, 57, 141, 41, 242, 70, 42, 134, 68, 224, 117, 137, 47, 152, 246, 220, 192, 32, 201, 242, 58]),
            chain: vec![
                vec![48, 130, 4, 161, 48, 130, 3, 9, 160, 3, 2, 1, 2, 2, 9, 0, 209, 7, 118, 93, 50, 163, 176, 150, 48, 13, 6, 9, 42, 134, 72, 134, 247, 13, 1, 1, 11, 5, 0, 48, 126, 49, 11, 48, 9, 6, 3, 85, 4, 6, 19, 2, 85, 83, 49, 11, 48, 9, 6, 3, 85, 4, 8, 12, 2, 67, 65, 49, 20, 48, 18, 6, 3, 85, 4, 7, 12, 11, 83, 97, 110, 116, 97, 32, 67, 108, 97, 114, 97, 49, 26, 48, 24, 6, 3, 85, 4, 10, 12, 17, 73, 110, 116, 101, 108, 32, 67, 111, 114, 112, 111, 114, 97, 116, 105, 111, 110, 49, 48, 48, 46, 6, 3, 85, 4, 3, 12, 39, 73, 110, 116, 101, 108, 32, 83, 71, 88, 32, 65, 116, 116, 101, 115, 116, 97, 116, 105, 111, 110, 32, 82, 101, 112, 111, 114, 116, 32, 83, 105, 103, 110, 105, 110, 103, 32, 67, 65, 48, 30, 23, 13, 49, 54, 49, 49, 50, 50, 48, 57, 51, 54, 53, 56, 90, 23, 13, 50, 54, 49, 49, 50, 48, 48, 57, 51, 54, 53, 56, 90, 48, 123, 49, 11, 48, 9, 6, 3, 85, 4, 6, 19, 2, 85, 83, 49, 11, 48, 9, 6, 3, 85, 4, 8, 12, 2, 67, 65, 49, 20, 48, 18, 6, 3, 85, 4, 7, 12, 11, 83, 97, 110, 116, 97, 32, 67, 108, 97, 114, 97, 49, 26, 48, 24, 6, 3, 85, 4, 10, 12, 17, 73, 110, 116, 101, 108, 32, 67, 111, 114, 112, 111, 114, 97, 116, 105, 111, 110, 49, 45, 48, 43, 6, 3, 85, 4, 3, 12, 36, 73, 110, 116, 101, 108, 32, 83, 71, 88, 32, 65, 116, 116, 101, 115, 116, 97, 116, 105, 111, 110, 32, 82, 101, 112, 111, 114, 116, 32, 83, 105, 103, 110, 105, 110, 103, 48, 130, 1, 34, 48, 13, 6, 9, 42, 134, 72, 134, 247, 13, 1, 1, 1, 5, 0, 3, 130, 1, 15, 0, 48, 130, 1, 10, 2, 130, 1, 1, 0, 169, 122, 45, 224, 230, 110, 166, 20, 124, 158, 231, 69, 172, 1, 98, 104, 108, 113, 146, 9, 154, 252, 75, 63, 4, 15, 173, 109, 224, 147, 81, 29, 116, 232, 2, 245, 16, 215, 22, 3, 129, 87, 220, 175, 132, 244, 16, 75, 211, 254, 215, 230, 184, 249, 156, 136, 23, 253, 31, 245, 185, 184, 100, 41, 108, 61, 129, 250, 143, 27, 114, 158, 2, 210, 29, 114, 255, 238, 76, 237, 114, 94, 254, 116, 190, 166, 143, 188, 77, 66, 68, 40, 111, 205, 212, 191, 100, 64, 106, 67, 154, 21, 188, 180, 207, 103, 117, 68, 137, 196, 35, 151, 43, 74, 128, 223, 92, 46, 124, 91, 194, 219, 175, 45, 66, 187, 123, 36, 79, 124, 149, 191, 146, 199, 93, 59, 51, 252, 84, 16, 103, 138, 137, 88, 157, 16, 131, 218, 58, 204, 69, 159, 39, 4, 205, 153, 89, 140, 39, 94, 124, 24, 120, 224, 7, 87, 229, 189, 180, 232, 64, 34, 108, 17, 192, 161, 127, 247, 156, 128, 177, 92, 29, 219, 90, 242, 28, 194, 65, 112, 97, 251, 210, 162, 218, 129, 158, 211, 183, 43, 126, 250, 163, 191, 235, 226, 128, 92, 155, 138, 193, 154, 163, 70, 81, 45, 72, 76, 252, 129, 148, 30, 21, 245, 88, 129, 204, 18, 126, 143, 122, 161, 35, 0, 205, 90, 251, 87, 66, 250, 29, 32, 203, 70, 122, 91, 235, 28, 102, 108, 247, 106, 54, 137, 120, 181, 2, 3, 1, 0, 1, 163, 129, 164, 48, 129, 161, 48, 31, 6, 3, 85, 29, 35, 4, 24, 48, 22, 128, 20, 120, 67, 123, 118, 166, 126, 188, 208, 175, 126, 66, 55, 235, 53, 124, 59, 135, 1, 81, 60, 48, 14, 6, 3, 85, 29, 15, 1, 1, 255, 4, 4, 3, 2, 6, 192, 48, 12, 6, 3, 85, 29, 19, 1, 1, 255, 4, 2, 48, 0, 48, 96, 6, 3, 85, 29, 31, 4, 89, 48, 87, 48, 85, 160, 83, 160, 81, 134, 79, 104, 116, 116, 112, 58, 47, 47, 116, 114, 117, 115, 116, 101, 100, 115, 101, 114, 118, 105, 99, 101, 115, 46, 105, 110, 116, 101, 108, 46, 99, 111, 109, 47, 99, 111, 110, 116, 101, 110, 116, 47, 67, 82, 76, 47, 83, 71, 88, 47, 65, 116, 116, 101, 115, 116, 97, 116, 105, 111, 110, 82, 101, 112, 111, 114, 116, 83, 105, 103, 110, 105, 110, 103, 67, 65, 46, 99, 114, 108, 48, 13, 6, 9, 42, 134, 72, 134, 247, 13, 1, 1, 11, 5, 0, 3, 130, 1, 129, 0, 103, 8, 182, 27, 92, 43, 210, 21, 71, 62, 43, 70, 175, 153, 40, 79, 187, 147, 157, 63, 59, 21, 44, 153, 111, 26, 106, 243, 179, 41, 189, 34, 11, 29, 59, 97, 15, 107, 206, 46, 103, 83, 189, 237, 48, 77, 178, 25, 18, 243, 133, 37, 98, 22, 207, 203, 164, 86, 189, 150, 148, 11, 232, 146, 245, 105, 12, 38, 13, 30, 248, 79, 22, 6, 4, 2, 34, 229, 254, 8, 229, 50, 104, 8, 33, 42, 68, 124, 253, 214, 74, 70, 233, 75, 242, 159, 107, 75, 154, 114, 29, 37, 179, 196, 226, 246, 47, 88, 186, 237, 93, 119, 197, 5, 36, 143, 15, 128, 31, 159, 191, 183, 253, 117, 32, 128, 9, 92, 238, 128, 147, 139, 51, 159, 109, 187, 78, 22, 86, 0, 226, 14, 74, 113, 136, 18, 212, 157, 153, 1, 227, 16, 169, 181, 29, 102, 199, 153, 9, 198, 153, 101, 153, 250, 230, 215, 106, 121, 239, 20, 93, 153, 67, 191, 29, 62, 53, 211, 180, 45, 31, 185, 164, 92, 190, 142, 227, 52, 193, 102, 238, 231, 211, 47, 205, 201, 147, 93, 184, 236, 139, 177, 216, 235, 55, 121, 221, 138, 185, 43, 110, 56, 127, 1, 71, 69, 15, 30, 56, 29, 8, 88, 31, 184, 61, 243, 59, 21, 224, 0, 165, 155, 229, 126, 169, 74, 58, 82, 220, 100, 189, 174, 201, 89, 179, 70, 76, 145, 231, 37, 187, 218, 234, 61, 153, 232, 87, 227, 128, 162, 60, 157, 159, 177, 239, 88, 233, 228, 45, 113, 241, 33, 48, 249, 38, 29, 114, 52, 214, 195, 126, 43, 3, 219, 164, 13, 253, 251, 19, 172, 74, 216, 225, 63, 211, 117, 99, 86, 182, 181, 0, 21, 163, 236, 149, 128, 184, 21, 216, 124, 44, 239, 113, 92, 210, 141, 240, 11, 191, 42, 60, 64, 62, 191, 102, 145, 179, 240, 94, 221, 145, 67, 128, 60, 160, 133, 207, 245, 126, 5, 62, 236, 47, 143, 234, 70, 234, 119, 138, 104, 201, 190, 136, 91, 194, 130, 37, 188, 95, 48, 155, 228, 162, 183, 77, 58, 3, 148, 83, 25, 221, 60, 113, 34, 254, 214, 255, 83, 187, 139, 140, 179, 160, 60],
                vec![48, 130, 5, 75, 48, 130, 3, 179, 160, 3, 2, 1, 2, 2, 9, 0, 209, 7, 118, 93, 50, 163, 176, 148, 48, 13, 6, 9, 42, 134, 72, 134, 247, 13, 1, 1, 11, 5, 0, 48, 126, 49, 11, 48, 9, 6, 3, 85, 4, 6, 19, 2, 85, 83, 49, 11, 48, 9, 6, 3, 85, 4, 8, 12, 2, 67, 65, 49, 20, 48, 18, 6, 3, 85, 4, 7, 12, 11, 83, 97, 110, 116, 97, 32, 67, 108, 97, 114, 97, 49, 26, 48, 24, 6, 3, 85, 4, 10, 12, 17, 73, 110, 116, 101, 108, 32, 67, 111, 114, 112, 111, 114, 97, 116, 105, 111, 110, 49, 48, 48, 46, 6, 3, 85, 4, 3, 12, 39, 73, 110, 116, 101, 108, 32, 83, 71, 88, 32, 65, 116, 116, 101, 115, 116, 97, 116, 105, 111, 110, 32, 82, 101, 112, 111, 114, 116, 32, 83, 105, 103, 110, 105, 110, 103, 32, 67, 65, 48, 32, 23, 13, 49, 54, 49, 49, 49, 52, 49, 53, 51, 55, 51, 49, 90, 24, 15, 50, 48, 52, 57, 49, 50, 51, 49, 50, 51, 53, 57, 53, 57, 90, 48, 126, 49, 11, 48, 9, 6, 3, 85, 4, 6, 19, 2, 85, 83, 49, 11, 48, 9, 6, 3, 85, 4, 8, 12, 2, 67, 65, 49, 20, 48, 18, 6, 3, 85, 4, 7, 12, 11, 83, 97, 110, 116, 97, 32, 67, 108, 97, 114, 97, 49, 26, 48, 24, 6, 3, 85, 4, 10, 12, 17, 73, 110, 116, 101, 108, 32, 67, 111, 114, 112, 111, 114, 97, 116, 105, 111, 110, 49, 48, 48, 46, 6, 3, 85, 4, 3, 12, 39, 73, 110, 116, 101, 108, 32, 83, 71, 88, 32, 65, 116, 116, 101, 115, 116, 97, 116, 105, 111, 110, 32, 82, 101, 112, 111, 114, 116, 32, 83, 105, 103, 110, 105, 110, 103, 32, 67, 65, 48, 130, 1, 162, 48, 13, 6, 9, 42, 134, 72, 134, 247, 13, 1, 1, 1, 5, 0, 3, 130, 1, 143, 0, 48, 130, 1, 138, 2, 130, 1, 129, 0, 159, 60, 100, 126, 181, 119, 60, 187, 81, 45, 39, 50, 192, 215, 65, 94, 187, 85, 160, 250, 158, 222, 46, 100, 145, 153, 230, 130, 29, 185, 16, 213, 49, 119, 55, 9, 119, 70, 106, 106, 94, 71, 134, 204, 210, 221, 235, 212, 20, 157, 106, 47, 99, 37, 82, 157, 209, 12, 201, 135, 55, 176, 119, 156, 26, 7, 226, 156, 71, 161, 174, 0, 73, 72, 71, 108, 72, 159, 69, 165, 161, 93, 122, 200, 236, 198, 172, 198, 69, 173, 180, 61, 135, 103, 157, 245, 156, 9, 59, 197, 162, 233, 105, 108, 84, 120, 84, 27, 151, 158, 117, 75, 87, 57, 20, 190, 85, 211, 47, 244, 192, 157, 223, 39, 33, 153, 52, 205, 153, 5, 39, 179, 249, 46, 215, 143, 191, 41, 36, 106, 190, 203, 113, 36, 14, 243, 156, 45, 113, 7, 180, 71, 84, 90, 127, 251, 16, 235, 6, 10, 104, 169, 133, 128, 33, 158, 54, 145, 9, 82, 104, 56, 146, 214, 165, 226, 168, 8, 3, 25, 62, 64, 117, 49, 64, 78, 54, 179, 21, 98, 55, 153, 170, 130, 80, 116, 64, 151, 84, 162, 223, 232, 245, 175, 213, 254, 99, 30, 31, 194, 175, 56, 8, 144, 111, 40, 167, 144, 217, 221, 159, 224, 96, 147, 155, 18, 87, 144, 197, 128, 93, 3, 125, 245, 106, 153, 83, 27, 150, 222, 105, 222, 51, 237, 34, 108, 193, 32, 125, 16, 66, 181, 201, 171, 127, 64, 79, 199, 17, 192, 254, 71, 105, 251, 149, 120, 177, 220, 14, 196, 105, 234, 26, 37, 224, 255, 153, 20, 136, 110, 242, 105, 155, 35, 91, 180, 132, 125, 214, 255, 64, 182, 6, 230, 23, 7, 147, 194, 251, 152, 179, 20, 88, 127, 156, 253, 37, 115, 98, 223, 234, 177, 11, 59, 210, 217, 118, 115, 161, 164, 189, 68, 196, 83, 170, 244, 127, 193, 242, 211, 208, 243, 132, 247, 74, 6, 248, 156, 8, 159, 13, 166, 205, 183, 252, 238, 232, 201, 130, 26, 142, 84, 242, 92, 4, 22, 209, 140, 70, 131, 154, 95, 128, 18, 251, 221, 61, 199, 77, 37, 98, 121, 173, 194, 192, 213, 90, 255, 111, 6, 34, 66, 93, 27, 2, 3, 1, 0, 1, 163, 129, 201, 48, 129, 198, 48, 96, 6, 3, 85, 29, 31, 4, 89, 48, 87, 48, 85, 160, 83, 160, 81, 134, 79, 104, 116, 116, 112, 58, 47, 47, 116, 114, 117, 115, 116, 101, 100, 115, 101, 114, 118, 105, 99, 101, 115, 46, 105, 110, 116, 101, 108, 46, 99, 111, 109, 47, 99, 111, 110, 116, 101, 110, 116, 47, 67, 82, 76, 47, 83, 71, 88, 47, 65, 116, 116, 101, 115, 116, 97, 116, 105, 111, 110, 82, 101, 112, 111, 114, 116, 83, 105, 103, 110, 105, 110, 103, 67, 65, 46, 99, 114, 108, 48, 29, 6, 3, 85, 29, 14, 4, 22, 4, 20, 120, 67, 123, 118, 166, 126, 188, 208, 175, 126, 66, 55, 235, 53, 124, 59, 135, 1, 81, 60, 48, 31, 6, 3, 85, 29, 35, 4, 24, 48, 22, 128, 20, 120, 67, 123, 118, 166, 126, 188, 208, 175, 126, 66, 55, 235, 53, 124, 59, 135, 1, 81, 60, 48, 14, 6, 3, 85, 29, 15, 1, 1, 255, 4, 4, 3, 2, 1, 6, 48, 18, 6, 3, 85, 29, 19, 1, 1, 255, 4, 8, 48, 6, 1, 1, 255, 2, 1, 0, 48, 13, 6, 9, 42, 134, 72, 134, 247, 13, 1, 1, 11, 5, 0, 3, 130, 1, 129, 0, 120, 95, 45, 96, 197, 200, 10, 244, 42, 121, 118, 16, 33, 57, 21, 218, 130, 201, 178, 158, 137, 224, 144, 42, 37, 166, 199, 91, 22, 9, 28, 104, 171, 32, 74, 174, 113, 24, 137, 73, 44, 126, 30, 50, 9, 17, 69, 90, 143, 193, 52, 66, 49, 46, 119, 166, 57, 148, 217, 151, 149, 200, 234, 69, 118, 130, 60, 234, 138, 209, 225, 145, 207, 168, 98, 250, 184, 169, 50, 211, 217, 176, 83, 90, 7, 2, 208, 85, 95, 116, 229, 32, 227, 3, 48, 243, 52, 128, 231, 173, 201, 215, 200, 30, 32, 112, 49, 66, 191, 0, 197, 40, 168, 11, 70, 51, 129, 253, 96, 42, 130, 199, 3, 82, 129, 170, 229, 149, 98, 204, 181, 51, 78, 168, 144, 62, 101, 11, 1, 6, 129, 245, 206, 142, 182, 46, 172, 156, 65, 73, 136, 36, 58, 236, 146, 242, 91, 241, 60, 223, 247, 235, 204, 41, 142, 229, 27, 186, 90, 53, 56, 182, 107, 38, 203, 196, 90, 81, 222, 0, 60, 173, 48, 101, 49, 173, 124, 245, 212, 239, 15, 136, 5, 209, 185, 19, 61, 36, 19, 90, 179, 196, 100, 26, 47, 136, 8, 52, 157, 115, 51, 41, 94, 14, 118, 238, 75, 197, 34, 114, 50, 98, 142, 250, 128, 215, 157, 146, 171, 78, 61, 17, 32, 243, 251, 90, 209, 25, 205, 141, 84, 74, 161, 212, 166, 134, 94, 107, 87, 190, 172, 87, 113, 48, 126, 46, 60, 185, 7, 13, 164, 123, 75, 252, 136, 105, 224, 20, 19, 234, 9, 53, 65, 222, 138, 121, 40, 17, 183, 70, 54, 197, 233, 20, 82, 207, 12, 238, 89, 242, 251, 64, 74, 205, 11, 197, 132, 203, 156, 131, 84, 4, 115, 76, 14, 126, 198, 96, 92, 223, 207, 47, 244, 57, 182, 212, 113, 159, 112, 47, 14, 12, 63, 160, 79, 219, 18, 166, 203, 42, 209, 171, 28, 154, 241, 248, 244, 195, 160, 142, 221, 114, 163, 43, 11, 181, 208, 173, 37, 111, 253, 21, 154, 104, 59, 42, 90, 31, 29, 17, 250, 98, 83, 47, 3, 215, 84, 202, 239, 13, 165, 115, 90, 30, 90, 136, 76, 126, 137, 217, 18, 24, 201, 215]
            ],
            http_body: String::from("{\"nonce\":\"ca1bb26d4a756cabf422206fc1953e4b\",\"id\":\"179687352362288239547319787000716174273\",\"timestamp\":\"2020-09-14T23:07:16.215597\",\"version\":4,\"epidPseudonym\":\"g4cL6vn6M9IDTPSqhX8Pf7Sr9+T7z4gDo9AS85sRtTzb/TwNlXWinJvc32CaMyYxBS47BasT0X28+sZcwivjU0sMLvw4m6+fzHNNn35aDNSpxb0Uex3jzgDuCRFnf8ALnusnQCta9T4+pdSa8q+jiH/rH8o5rhWhbMEWQOn6eL4=\",\"advisoryURL\":\"https://security-center.intel.com\",\"advisoryIDs\":[\"INTEL-SA-00334\"],\"isvEnclaveQuoteStatus\":\"SW_HARDENING_NEEDED\",\"isvEnclaveQuoteBody\":\"AgABAMYLAAALAAoAAAAAAJa61F5HK4XuN+hpUAosFDUAAAAAAAAAAAAAAAAAAAAADw8DBf+ABgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABwAAAAAAAAAHAAAAAAAAAEX7JCJMNjPsjbUdCQvxHeTedsKGbAYBAjFQINmXhrgsAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADRH0aZv+C3tUfOY+GILgHu0MZUeSireJoxWoeJjyxTTQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACrVp3CmSVw8JKk216nJxDjuvgQhd5061+C3IFKOR4zFbRGu2agQhwp2GNkGUHW8zZaRLp4BJ0UyeGr0mJbxhkU\"}"),
        }
    }

    /// Ensure a verifier without any status verifiers can pass.
    #[test]
    fn no_status_ok() {
        Verifier::new(TEST_ANCHORS)
            .expect("Could not initialize new verifier")
            .debug(true)
            .nonce(
                &IasNonce::from_hex("ca1bb26d4a756cabf422206fc1953e4b")
                    .expect("Could not parse nonce hex"),
            )
            .verify(&get_ias_report())
            .expect("Could not verify IAS report");
    }

    /// Ensure an IAS verifier with only MRENCLAVE verifiers can succeed.
    #[test]
    fn multiple_mrenclave_ok() {
        let mut mr_enclave1 = MrEnclaveVerifier::new(MrEnclave::from([
            69, 251, 36, 34, 76, 54, 51, 236, 141, 181, 29, 9, 11, 241, 29, 228, 222, 118, 194,
            134, 108, 6, 1, 2, 49, 80, 32, 217, 151, 134, 184, 44,
        ]));
        mr_enclave1.allow_hardening_advisory("INTEL-SA-00334");

        let mut mr_enclave2 = MrEnclaveVerifier::new(MrEnclave::from([
            209, 31, 70, 153, 191, 224, 183, 181, 71, 206, 99, 225, 136, 46, 1, 238, 208, 198, 84,
            121, 40, 171, 120, 154, 49, 90, 135, 137, 143, 44, 83, 77,
        ]));
        mr_enclave2.allow_hardening_advisory("INTEL-SA-00334");

        Verifier::new(TEST_ANCHORS)
            .expect("Could not initialize new verifier")
            .mr_enclave(mr_enclave1)
            .mr_enclave(mr_enclave2)
            .verify(&get_ias_report())
            .expect("Could not verify IAS report");
    }

    /// Ensure an IAS verifier with multiple MRSIGNER verifiers and a debug
    /// check can succeed
    #[test]
    fn multiple_mrsigner_ok() {
        let mut mr_signer1 = MrSignerVerifier::new(
            MrSigner::from([
                209, 31, 70, 153, 191, 224, 183, 181, 71, 206, 99, 225, 136, 46, 1, 238, 208, 198,
                84, 121, 40, 171, 120, 154, 49, 90, 135, 137, 143, 44, 83, 77,
            ]),
            10,
            10,
        );
        mr_signer1.allow_hardening_advisory("INTEL-SA-00334");
        let mut mr_signer2 = MrSignerVerifier::new(
            MrSigner::from([
                209, 31, 70, 153, 191, 224, 183, 181, 71, 206, 99, 225, 136, 46, 1, 238, 208, 198,
                84, 121, 40, 171, 120, 154, 49, 90, 135, 137, 143, 44, 83, 77,
            ]),
            1,
            1,
        );
        mr_signer2.allow_hardening_advisory("INTEL-SA-00334");

        Verifier::new(TEST_ANCHORS)
            .expect("Could not initialize new verifier")
            .mr_signer(mr_signer1)
            .mr_signer(mr_signer2)
            .debug(true)
            .verify(&get_ias_report())
            .expect("Could not verify IAS report");
    }

    /// Ensure an OK result with the expected MRENCLAVE value succeeds.
    #[test]
    fn mrenclave_ok() {
        let verifier = MrEnclaveVerifier {
            mr_enclave: MrEnclave::from(&MR_ENCLAVE),
            config_ids: vec![],
            sw_ids: vec![],
        };

        let report = VerificationReport {
            sig: Default::default(),
            chain: vec![],
            http_body: IAS_OK.trim().to_owned(),
        };

        let data = VerificationReportData::try_from(&report).expect("Could not parse IAS result");
        assert!(verifier.verify(&data))
    }

    /// Ensure an OK result with the wrong MRENCLAVE value fails.
    #[test]
    fn mrenclave_fail() {
        let verifier = MrEnclaveVerifier {
            mr_enclave: MrEnclave::from(&MR_SIGNER),
            config_ids: vec![],
            sw_ids: vec![],
        };

        let report = VerificationReport {
            sig: Default::default(),
            chain: vec![],
            http_body: IAS_OK.trim().to_owned(),
        };

        let data = VerificationReportData::try_from(&report).expect("Could not parse IAS result");
        assert!(!verifier.verify(&data))
    }

    /// Ensure a CONFIGURATION_NEEDED result with the expected MRENCLAVE and
    /// allowed advisory passes.
    #[test]
    fn mrenclave_config_pass() {
        let verifier = MrEnclaveVerifier {
            mr_enclave: MrEnclave::from(&MR_ENCLAVE),
            config_ids: vec!["INTEL-SA-00239".to_owned()],
            sw_ids: vec!["INTEL-SA-00123".to_owned()],
        };

        let report = VerificationReport {
            sig: Default::default(),
            chain: vec![],
            http_body: IAS_CONFIG.trim().to_owned(),
        };

        let data = VerificationReportData::try_from(&report).expect("Could not parse IAS result");
        assert!(verifier.verify(&data))
    }

    /// Ensure a CONFIGURATION_NEEDED result with the expected MRENCLAVE but
    /// unexpected advisory fails.
    #[test]
    fn mrenclave_config_fail() {
        let verifier = MrEnclaveVerifier {
            mr_enclave: MrEnclave::from(&MR_ENCLAVE),
            config_ids: vec!["INTEL-SA-00123".to_owned()],
            sw_ids: vec!["INTEL-SA-00239".to_owned()],
        };

        let report = VerificationReport {
            sig: Default::default(),
            chain: vec![],
            http_body: IAS_CONFIG.trim().to_owned(),
        };

        let data = VerificationReportData::try_from(&report).expect("Could not parse IAS result");
        assert!(!verifier.verify(&data))
    }

    /// Ensure a SW_HARDENING_NEEDED result with the expected MRENCLAVE and
    /// advisory passes.
    #[test]
    fn mrenclave_sw_pass() {
        let verifier = MrEnclaveVerifier {
            mr_enclave: MrEnclave::from(&MR_ENCLAVE),
            config_ids: vec!["INTEL-SA-00123".to_owned()],
            sw_ids: vec!["INTEL-SA-00239".to_owned()],
        };

        let report = VerificationReport {
            sig: Default::default(),
            chain: vec![],
            http_body: IAS_SW.trim().to_owned(),
        };

        let data = VerificationReportData::try_from(&report).expect("Could not parse IAS result");
        assert!(verifier.verify(&data))
    }

    /// Ensure a SW_HARDENING_NEEDED result with the expected MRENCLAVE but
    /// unexpected advisory fails.
    #[test]
    fn mrenclave_sw_fail() {
        let verifier = MrEnclaveVerifier {
            mr_enclave: MrEnclave::from(&MR_ENCLAVE),
            config_ids: vec!["INTEL-SA-00239".to_owned()],
            sw_ids: vec!["INTEL-SA-00123".to_owned()],
        };

        let report = VerificationReport {
            sig: Default::default(),
            chain: vec![],
            http_body: IAS_SW.trim().to_owned(),
        };

        let data = VerificationReportData::try_from(&report).expect("Could not parse IAS result");
        assert!(!verifier.verify(&data))
    }

    /// Ensure a CONFIGURATION_AND_SW_HARDENING_NEEDED result with the expected
    /// MRENCLAVE and config advisory passes.
    #[test]
    fn mrenclave_config_sw_pass_config() {
        let verifier = MrEnclaveVerifier {
            mr_enclave: MrEnclave::from(&MR_ENCLAVE),
            config_ids: vec!["INTEL-SA-00239".to_owned()],
            sw_ids: vec!["INTEL-SA-00123".to_owned()],
        };

        let report = VerificationReport {
            sig: Default::default(),
            chain: vec![],
            http_body: IAS_CONFIG_SW.trim().to_owned(),
        };

        let data = VerificationReportData::try_from(&report).expect("Could not parse IAS result");
        assert!(verifier.verify(&data))
    }

    /// Ensure a CONFIGURATION_AND_SW_HARDENING_NEEDED result with the expected
    /// MRENCLAVE and hardening advisory passes.
    #[test]
    fn mrenclave_config_sw_pass_sw() {
        let verifier = MrEnclaveVerifier {
            mr_enclave: MrEnclave::from(&MR_ENCLAVE),
            config_ids: vec!["INTEL-SA-00123".to_owned()],
            sw_ids: vec!["INTEL-SA-00239".to_owned()],
        };

        let report = VerificationReport {
            sig: Default::default(),
            chain: vec![],
            http_body: IAS_CONFIG_SW.trim().to_owned(),
        };

        let data = VerificationReportData::try_from(&report).expect("Could not parse IAS result");
        assert!(verifier.verify(&data))
    }

    /// Ensure a CONFIGURATION_AND_SW_HARDENING_NEEDED result with the expected
    /// MRENCLAVE but an unexpected advisory fails.
    #[test]
    fn mrenclave_config_sw_fail() {
        let verifier = MrEnclaveVerifier {
            mr_enclave: MrEnclave::from(&MR_ENCLAVE),
            config_ids: vec!["INTEL-SA-00123".to_owned()],
            sw_ids: vec!["INTEL-SA-00123".to_owned()],
        };

        let report = VerificationReport {
            sig: Default::default(),
            chain: vec![],
            http_body: IAS_CONFIG_SW.trim().to_owned(),
        };

        let data = VerificationReportData::try_from(&report).expect("Could not parse IAS result");
        assert!(!verifier.verify(&data))
    }

    /// Ensure an OK result with the expected MRSIGNER, product, and minimum
    /// version passes.
    #[test]
    fn mrsigner_ok() {
        let verifier = MrSignerVerifier {
            mr_signer: MrSigner::from(&MR_SIGNER),
            product_id: 0,
            minimum_svn: 0,
            config_ids: vec![],
            sw_ids: vec![],
        };

        let report = VerificationReport {
            sig: Default::default(),
            chain: vec![],
            http_body: IAS_OK.trim().to_owned(),
        };

        let data = VerificationReportData::try_from(&report).expect("Could not parse IAS result");
        assert!(verifier.verify(&data))
    }

    /// Ensure an OK result with the expected MRSIGNER, product, and minimum
    /// version passes.
    #[test]
    fn mrsigner_fail_notok() {
        let verifier = MrSignerVerifier {
            mr_signer: MrSigner::from(&MR_SIGNER),
            product_id: 0,
            minimum_svn: 0,
            config_ids: vec![],
            sw_ids: vec![],
        };

        let report = VerificationReport {
            sig: Default::default(),
            chain: vec![],
            http_body: IAS_CONFIG.trim().to_owned(),
        };

        let data = VerificationReportData::try_from(&report).expect("Could not parse IAS result");
        assert!(!verifier.verify(&data))
    }

    /// Ensure an OK result with an unexpected MRSIGNER fails.
    #[test]
    fn mrsigner_fail_mrsigner() {
        let verifier = MrSignerVerifier {
            mr_signer: MrSigner::from(&MR_ENCLAVE),
            product_id: 0,
            minimum_svn: 0,
            config_ids: vec![],
            sw_ids: vec![],
        };

        let report = VerificationReport {
            sig: Default::default(),
            chain: vec![],
            http_body: IAS_OK.trim().to_owned(),
        };

        let data = VerificationReportData::try_from(&report).expect("Could not parse IAS result");
        assert!(!verifier.verify(&data))
    }

    /// Ensure an OK result with an unexpected product ID fails
    #[test]
    fn mrsigner_fail_product_id() {
        let verifier = MrSignerVerifier {
            mr_signer: MrSigner::from(&MR_SIGNER),
            product_id: 1,
            minimum_svn: 0,
            config_ids: vec![],
            sw_ids: vec![],
        };

        let report = VerificationReport {
            sig: Default::default(),
            chain: vec![],
            http_body: IAS_OK.trim().to_owned(),
        };

        let data = VerificationReportData::try_from(&report).expect("Could not parse IAS result");
        assert!(!verifier.verify(&data))
    }

    /// Ensure an OK result with a greater version fails
    #[test]
    fn mrsigner_fail_version() {
        let verifier = MrSignerVerifier {
            mr_signer: MrSigner::from(&MR_SIGNER),
            product_id: 0,
            minimum_svn: 1,
            config_ids: vec![],
            sw_ids: vec![],
        };

        let report = VerificationReport {
            sig: Default::default(),
            chain: vec![],
            http_body: IAS_OK.trim().to_owned(),
        };

        let data = VerificationReportData::try_from(&report).expect("Could not parse IAS result");
        assert!(!verifier.verify(&data))
    }

    /// Ensure a CONFIGURATION_NEEDED result with the expected MRSIGNER,
    /// product, and minimum version passes, as long as the advisory is
    /// accounted for
    #[test]
    fn mrsigner_pass_config() {
        let verifier = MrSignerVerifier {
            mr_signer: MrSigner::from(&MR_SIGNER),
            product_id: 0,
            minimum_svn: 0,
            config_ids: vec!["INTEL-SA-00239".to_owned()],
            sw_ids: vec![],
        };

        let report = VerificationReport {
            sig: Default::default(),
            chain: vec![],
            http_body: IAS_CONFIG.trim().to_owned(),
        };

        let data = VerificationReportData::try_from(&report).expect("Could not parse IAS result");
        assert!(verifier.verify(&data))
    }

    /// Ensure a SW_HARDENING_NEEDED result with the expected MRSIGNER,
    /// product, and minimum version passes, as long as the advisory is
    /// accounted for
    #[test]
    fn mrsigner_pass_sw() {
        let verifier = MrSignerVerifier {
            mr_signer: MrSigner::from(&MR_SIGNER),
            product_id: 0,
            minimum_svn: 0,
            config_ids: vec![],
            sw_ids: vec!["INTEL-SA-00239".to_owned()],
        };

        let report = VerificationReport {
            sig: Default::default(),
            chain: vec![],
            http_body: IAS_SW.trim().to_owned(),
        };

        let data = VerificationReportData::try_from(&report).expect("Could not parse IAS result");
        assert!(verifier.verify(&data))
    }

    /// Ensure a CONFIGURATION_AND_SW_HARDENING_NEEDED result with the expected
    /// MRSIGNER, product, and minimum version passes, as long as the
    /// advisory is accounted for.
    #[test]
    fn mrsigner_pass_sw_config_via_sw() {
        let verifier = MrSignerVerifier {
            mr_signer: MrSigner::from(&MR_SIGNER),
            product_id: 0,
            minimum_svn: 0,
            config_ids: vec![],
            sw_ids: vec!["INTEL-SA-00239".to_owned()],
        };

        let report = VerificationReport {
            sig: Default::default(),
            chain: vec![],
            http_body: IAS_CONFIG_SW.trim().to_owned(),
        };

        let data = VerificationReportData::try_from(&report).expect("Could not parse IAS result");
        assert!(verifier.verify(&data))
    }

    /// Ensure a CONFIGURATION_AND_SW_HARDENING_NEEDED result with the expected
    /// MRSIGNER, product, and minimum version passes, as long as the
    /// advisory is accounted for.
    #[test]
    fn mrsigner_pass_sw_config_via_config() {
        let verifier = MrSignerVerifier {
            mr_signer: MrSigner::from(&MR_SIGNER),
            product_id: 0,
            minimum_svn: 0,
            config_ids: vec![],
            sw_ids: vec!["INTEL-SA-00239".to_owned()],
        };

        let report = VerificationReport {
            sig: Default::default(),
            chain: vec![],
            http_body: IAS_CONFIG_SW.trim().to_owned(),
        };

        let data = VerificationReportData::try_from(&report).expect("Could not parse IAS result");
        assert!(verifier.verify(&data))
    }

    /// Ensure a CONFIGURATION_AND_SW_HARDENING_NEEDED result with the expected
    /// MRSIGNER, and minimum version, but the wrong product fails, even if
    /// the advisory is accounted for.
    #[test]
    fn mrsigner_fail_sw_config_for_product() {
        let verifier = MrSignerVerifier {
            mr_signer: MrSigner::from(&MR_SIGNER),
            product_id: 1,
            minimum_svn: 0,
            config_ids: vec![],
            sw_ids: vec!["INTEL-SA-00239".to_owned()],
        };

        let report = VerificationReport {
            sig: Default::default(),
            chain: vec![],
            http_body: IAS_CONFIG_SW.trim().to_owned(),
        };

        let data = VerificationReportData::try_from(&report).expect("Could not parse IAS result");
        assert!(!verifier.verify(&data))
    }

    /// Ensure a CONFIGURATION_AND_SW_HARDENING_NEEDED result with the expected
    /// MRSIGNER and product, but an earlier version, fails, even if the
    /// advisory is accounted for.
    #[test]
    fn mrsigner_fail_sw_config_for_version() {
        let verifier = MrSignerVerifier {
            mr_signer: MrSigner::from(&MR_SIGNER),
            product_id: 0,
            minimum_svn: 1,
            config_ids: vec![],
            sw_ids: vec!["INTEL-SA-00239".to_owned()],
        };

        let report = VerificationReport {
            sig: Default::default(),
            chain: vec![],
            http_body: IAS_CONFIG_SW.trim().to_owned(),
        };

        let data = VerificationReportData::try_from(&report).expect("Could not parse IAS result");
        assert!(!verifier.verify(&data))
    }

    /// When the quote contains the basename we're expecting
    #[test]
    fn basename_success() {
        let quote =
            Quote::from_base64(BASE64_QUOTE).expect("Could not parse quote from base64 file");
        let verifier = BasenameVerifier {
            basename: quote.basename().expect("Could not read basename"),
        };

        assert!(verifier.verify(&quote));
    }

    /// When the quote does not contain the basename we're expecting
    #[test]
    fn basename_fail() {
        let quote =
            Quote::from_base64(BASE64_QUOTE).expect("Could not parse quote from base64 file");
        let basename = sgx_basename_t { name: [0u8; 32] };
        let verifier = BasenameVerifier {
            basename: Basename::from(basename),
        };

        assert!(!verifier.verify(&quote));
    }

    /// When the quote matches what we're expecting
    #[test]
    fn quote_contents_success() {
        let quote =
            Quote::from_base64(BASE64_QUOTE).expect("Could not parse quote from base64 file");
        let verifier = QuoteContentsEqVerifier {
            quote: quote.clone(),
        };

        assert!(verifier.verify(&quote));
    }

    /// When the report does not contain the EPID group ID we're expecting
    #[test]
    fn quote_contents_fail() {
        let quote =
            Quote::from_base64(BASE64_QUOTE).expect("Could not parse quote from base64 file");
        let verifier = QuoteContentsEqVerifier {
            quote: Quote::from_base64(BASE64_QUOTE2)
                .expect("Could not parse other quote from base64 file"),
        };

        assert!(!verifier.verify(&quote));
    }

    /// When the report contains the EPID group ID we're expecting
    #[test]
    fn epid_group_id_success() {
        let quote =
            Quote::from_base64(BASE64_QUOTE).expect("Could not parse quote from base64 file");
        let verifier = EpidGroupIdVerifier {
            epid_group_id: quote.epid_group_id().expect("Could not read EPID Group ID"),
        };

        assert!(verifier.verify(&quote));
    }

    /// When the report does not contain the EPID group ID we're expecting
    #[test]
    fn epid_group_id_fail() {
        let quote =
            Quote::from_base64(BASE64_QUOTE).expect("Could not parse quote from base64 file");
        let epid_group_id = [0u8; 4];
        let verifier = EpidGroupIdVerifier {
            epid_group_id: EpidGroupId::from(epid_group_id),
        };

        assert!(!verifier.verify(&quote));
    }

    /// When the provisioning certificate enclave has the exact version we want
    #[test]
    fn pce_svn_eq_pass() {
        let quote =
            Quote::from_base64(BASE64_QUOTE).expect("Could not parse quote from base64 file");
        let verifier = PceSecurityVersionVerifier {
            pce_svn: quote
                .pce_security_version()
                .expect("PCE SVN could not be read"),
        };

        assert!(verifier.verify(&quote));
    }

    /// When the provisioning certificate enclave has a newer version than we
    /// want
    #[test]
    fn pce_svn_newer_pass() {
        let quote =
            Quote::from_base64(BASE64_QUOTE).expect("Could not parse quote from base64 file");
        let verifier = PceSecurityVersionVerifier {
            pce_svn: quote
                .pce_security_version()
                .expect("PCE SVN could not be read")
                - 1,
        };

        assert!(verifier.verify(&quote));
    }

    /// When the provisioning certificate enclave has an older version than we
    /// want
    #[test]
    fn pce_svn_older_fail() {
        let quote =
            Quote::from_base64(BASE64_QUOTE).expect("Could not parse quote from base64 file");
        let verifier = PceSecurityVersionVerifier {
            pce_svn: quote
                .pce_security_version()
                .expect("PCE SVN could not be read")
                + 1,
        };

        assert!(!verifier.verify(&quote));
    }

    /// When the quoting enclaves has the exact version we want
    #[test]
    fn qe_svn_eq_pass() {
        let quote =
            Quote::from_base64(BASE64_QUOTE).expect("Could not parse quote from base64 file");
        let verifier = QeSecurityVersionVerifier {
            qe_svn: quote
                .qe_security_version()
                .expect("QE SVN could not be read"),
        };

        assert!(verifier.verify(&quote));
    }

    /// When the quoting enclave has a newer version than we want
    #[test]
    fn qe_svn_newer_pass() {
        let quote =
            Quote::from_base64(BASE64_QUOTE).expect("Could not parse quote from base64 file");
        let verifier = QeSecurityVersionVerifier {
            qe_svn: quote
                .qe_security_version()
                .expect("QE SVN could not be read")
                - 1,
        };

        assert!(verifier.verify(&quote));
    }

    /// When the quoting enclave has an older version than we want
    #[test]
    fn qe_svn_older_fail() {
        let quote =
            Quote::from_base64(BASE64_QUOTE).expect("Could not parse quote from base64 file");
        let verifier = QeSecurityVersionVerifier {
            qe_svn: quote
                .qe_security_version()
                .expect("QE SVN could not be read")
                + 1,
        };

        assert!(!verifier.verify(&quote));
    }

    /// When the quote contains the sign type we want
    #[test]
    fn sign_type_success() {
        let quote =
            Quote::from_base64(BASE64_QUOTE).expect("Could not parse quote from base64 file");
        let verifier = SignTypeVerifier {
            sign_type: quote.sign_type().expect("Could not retreive sign type"),
        };

        assert!(verifier.verify(&quote));
    }

    /// When the quote doesn't contain the sign type we want
    #[test]
    fn sign_type_fail() {
        let quote =
            Quote::from_base64(BASE64_QUOTE).expect("Could not parse quote from base64 file");
        let verifier = SignTypeVerifier {
            sign_type: QuoteSignType::Linkable,
        };

        assert!(!verifier.verify(&quote));
    }

    /// When the report contains the attributes we want
    #[test]
    fn xeid_success() {
        let quote =
            Quote::from_base64(BASE64_QUOTE).expect("Could not parse quote from base64 file");
        let verifier = XeidVerifier {
            xeid: quote.xeid().expect("Xeid could not be read"),
        };

        assert!(verifier.verify(&quote));
    }

    /// When the report contains attributes we don't want
    #[test]
    fn xeid_fail() {
        let quote =
            Quote::from_base64(BASE64_QUOTE).expect("Could not parse quote from base64 file");
        let verifier = XeidVerifier {
            xeid: quote.xeid().expect("Xeid could not be read") + 1,
        };

        assert!(!verifier.verify(&quote));
    }

    /// When the report contains the attributes we want
    #[test]
    fn attributes_success() {
        let report_body = ReportBody::from(&REPORT_BODY_SRC);
        let verifier = AttributesVerifier {
            attributes: Attributes::from(REPORT_BODY_SRC.attributes),
        };

        assert!(verifier.verify(&report_body));
    }

    /// When the report contains attributes we don't want
    #[test]
    fn attributes_fail() {
        let report_body = ReportBody::from(&REPORT_BODY_SRC);
        let mut attributes = REPORT_BODY_SRC.attributes;
        attributes.flags = 0;
        let verifier = AttributesVerifier {
            attributes: Attributes::from(attributes),
        };

        assert!(!verifier.verify(&report_body));
    }

    /// When the report contains the config ID we want
    #[test]
    fn config_id_success() {
        let report_body = ReportBody::from(&REPORT_BODY_SRC);
        let verifier = ConfigIdVerifier {
            config_id: ConfigId::from(REPORT_BODY_SRC.config_id),
        };

        assert!(verifier.verify(&report_body));
    }

    /// When the report contains a config ID we don't want
    #[test]
    fn config_id_fail() {
        let report_body = ReportBody::from(&REPORT_BODY_SRC);
        let mut config_id = REPORT_BODY_SRC.config_id;
        config_id[0] = 0;
        let verifier = ConfigIdVerifier {
            config_id: ConfigId::from(config_id),
        };

        assert!(!verifier.verify(&report_body));
    }

    /// When the report contains exactly the config version we want
    #[test]
    fn config_version_eq_pass() {
        let report_body = ReportBody::from(&REPORT_BODY_SRC);
        let verifier = ConfigVersionVerifier {
            config_svn: REPORT_BODY_SRC.config_svn,
        };

        assert!(verifier.verify(&report_body));
    }

    /// When the report contains a newer config version than we want (pass)
    #[test]
    fn config_version_newer_pass() {
        let report_body = ReportBody::from(&REPORT_BODY_SRC);
        let verifier = ConfigVersionVerifier {
            config_svn: REPORT_BODY_SRC.config_svn - 1,
        };

        assert!(verifier.verify(&report_body));
    }

    /// When the report contains an older config version than we want
    #[test]
    fn config_version_older_fail() {
        let report_body = ReportBody::from(&REPORT_BODY_SRC);
        let verifier = ConfigVersionVerifier {
            config_svn: REPORT_BODY_SRC.config_svn + 1,
        };

        assert!(!verifier.verify(&report_body));
    }

    /// When the report contains the CPU version we want
    #[test]
    fn cpu_svn_eq_pass() {
        let report_body = ReportBody::from(&REPORT_BODY_SRC);
        let verifier = CpuVersionVerifier {
            cpu_svn: CpuSecurityVersion::from(REPORT_BODY_SRC.cpu_svn),
        };

        assert!(verifier.verify(&report_body));
    }

    /// When the report contains a CPU version newer than what we want
    #[test]
    fn cpu_svn_newer_pass() {
        let report_body = ReportBody::from(&REPORT_BODY_SRC);
        let mut cpu_svn = REPORT_BODY_SRC.cpu_svn;
        cpu_svn.svn[0] = 0;
        let verifier = CpuVersionVerifier {
            cpu_svn: CpuSecurityVersion::from(cpu_svn),
        };

        assert!(verifier.verify(&report_body));
    }

    /// When the report contains a CPU version older than what we want
    #[test]
    fn cpu_svn_older_fail() {
        let report_body = ReportBody::from(&REPORT_BODY_SRC);
        let mut cpu_svn = REPORT_BODY_SRC.cpu_svn;
        cpu_svn.svn[0] = 0xff;
        let verifier = CpuVersionVerifier {
            cpu_svn: CpuSecurityVersion::from(cpu_svn),
        };

        assert!(!verifier.verify(&report_body));
    }

    /// Allow debug means debug and non-debug both succeed
    #[test]
    fn debug_success() {
        let report_body = ReportBody::from(&REPORT_BODY_SRC);
        let verifier = DebugVerifier { allow_debug: true };

        assert!(verifier.verify(&report_body));
    }

    /// Allow debug off means only non-debug enclaves succeed
    #[test]
    fn no_debug_success() {
        let report_body = ReportBody::from(&REPORT_BODY_SRC);
        let verifier = DebugVerifier { allow_debug: false };

        assert!(verifier.verify(&report_body));
    }

    /// Allow debug off means debug enclaves fail
    #[test]
    fn no_debug_fail() {
        let mut report_body = REPORT_BODY_SRC;
        report_body.attributes.flags |= SGX_FLAGS_DEBUG;
        let report_body = ReportBody::from(report_body);
        let verifier = DebugVerifier { allow_debug: false };

        assert!(!verifier.verify(&report_body));
    }

    /// When the report contains the report data we expect
    #[test]
    fn data_success() {
        let report_body = ReportBody::from(&REPORT_BODY_SRC);
        let verifier = DataVerifier {
            data: ReportDataMask::new_with_mask(&REPORT_BODY_SRC.report_data.d, &ONES[..])
                .expect("Could not create report data mask"),
        };

        assert!(verifier.verify(&report_body));
    }

    /// When the report contains report data we don't want
    #[test]
    fn data_fail() {
        let report_body = ReportBody::from(&REPORT_BODY_SRC);
        let mut data = REPORT_BODY_SRC.report_data.d;
        data[0] = 0;
        let verifier = DataVerifier {
            data: ReportDataMask::new_with_mask(&data, &ONES[..])
                .expect("Could not create report data mask"),
        };

        assert!(!verifier.verify(&report_body));
    }

    /// When the report contains the extended product ID we want
    #[test]
    fn ext_prod_id_success() {
        let report_body = ReportBody::from(&REPORT_BODY_SRC);
        let verifier = ExtendedProductIdVerifier {
            ext_prod_id: ExtendedProductId::from(REPORT_BODY_SRC.isv_ext_prod_id),
        };

        assert!(verifier.verify(&report_body));
    }

    /// When the report contains an extended product ID we don't want
    #[test]
    fn ext_prod_id_fail() {
        let report_body = ReportBody::from(&REPORT_BODY_SRC);
        let mut ext_prod_id = REPORT_BODY_SRC.isv_ext_prod_id;
        ext_prod_id[0] = 0;
        let verifier = ExtendedProductIdVerifier {
            ext_prod_id: ExtendedProductId::from(ext_prod_id),
        };

        assert!(!verifier.verify(&report_body));
    }

    /// When the report contains the family ID we want
    #[test]
    fn family_id_success() {
        let report_body = ReportBody::from(&REPORT_BODY_SRC);
        let verifier = FamilyIdVerifier {
            family_id: FamilyId::from(REPORT_BODY_SRC.isv_family_id),
        };

        assert!(verifier.verify(&report_body));
    }

    /// When the report contains a family ID we don't want
    #[test]
    fn family_id_fail() {
        let report_body = ReportBody::from(&REPORT_BODY_SRC);
        let mut family_id = REPORT_BODY_SRC.isv_family_id;
        family_id[0] = 0;
        let verifier = FamilyIdVerifier {
            family_id: FamilyId::from(family_id),
        };

        assert!(!verifier.verify(&report_body));
    }

    /// When the report contains the product ID we want
    #[test]
    fn misc_select_success() {
        let report_body = ReportBody::from(&REPORT_BODY_SRC);
        let verifier = MiscSelectVerifier {
            misc_select: REPORT_BODY_SRC.misc_select,
        };

        assert!(verifier.verify(&report_body));
    }

    /// When the report contains a product ID we don't want
    #[test]
    fn misc_select_fail() {
        let report_body = ReportBody::from(&REPORT_BODY_SRC);
        let verifier = MiscSelectVerifier {
            misc_select: REPORT_BODY_SRC.misc_select - 1,
        };

        assert!(!verifier.verify(&report_body));
    }

    /// When the report contains the product ID we want
    #[test]
    fn product_id_success() {
        let report_body = ReportBody::from(&REPORT_BODY_SRC);
        let verifier = ProductIdVerifier {
            product_id: REPORT_BODY_SRC.isv_prod_id,
        };

        assert!(verifier.verify(&report_body));
    }

    /// When the report contains a product ID we don't want
    #[test]
    fn product_id_fail() {
        let report_body = ReportBody::from(&REPORT_BODY_SRC);
        let verifier = ProductIdVerifier {
            product_id: REPORT_BODY_SRC.isv_prod_id - 1,
        };

        assert!(!verifier.verify(&report_body));
    }

    /// When the report contains exactly the version we want
    #[test]
    fn version_eq_pass() {
        let report_body = ReportBody::from(&REPORT_BODY_SRC);
        let verifier = VersionVerifier {
            version: REPORT_BODY_SRC.isv_svn,
        };

        assert!(verifier.verify(&report_body));
    }

    /// When the report contains a newer version than we want (pass)
    #[test]
    fn version_newer_pass() {
        let report_body = ReportBody::from(&REPORT_BODY_SRC);
        let verifier = VersionVerifier {
            version: REPORT_BODY_SRC.isv_svn - 1,
        };

        assert!(verifier.verify(&report_body));
    }

    /// When the report contains an older version than we want
    #[test]
    fn version_older_fail() {
        let report_body = ReportBody::from(&REPORT_BODY_SRC);
        let verifier = VersionVerifier {
            version: REPORT_BODY_SRC.isv_svn + 1,
        };

        assert!(!verifier.verify(&report_body));
    }
}
