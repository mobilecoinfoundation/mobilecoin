// Copyright (c) 2018-2020 MobileCoin Inc.

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
    hash::Type as HashType,
    pk::{EcGroupId, Type as PkType},
    x509::{Certificate, Profile},
    Error as TlsError,
};
use mc_sgx_types::SGX_FLAGS_DEBUG;
use sha2::{digest::Digest, Sha256};

/// A trait which can be used to verify the JSON contents of an IAS verification
/// report.
trait Verify<T>: Clone {
    /// Check the data against the verifier's contents, return true on success,
    /// false on failure.
    fn verify(&self, data: &T) -> bool;
}

/// Errors which can be
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum BuilderError {
    InvalidTrustAnchor(String),
}

/// A builder structure used to construct a report verifier based on the
/// criteria specified.
pub struct Builder {
    trust_anchors: Vec<Certificate>,
    report_body_verifiers: Vec<VerifyReportBodyType>,
    quote_verifiers: Vec<VerifyQuoteType>,
    ias_verifiers: Vec<VerifyIasReportDataType>,
    status_verifiers: Vec<VerifyIasReportDataType>,
}

/// Construct a new builder using the baked-in IAS root certificates
impl Default for Builder {
    fn default() -> Self {
        Self::new(IAS_SIGNING_ROOT_CERT_PEMS).expect("Invalid hard-coded certificates found")
    }
}

impl Builder {
    /// Create a new builder object to generate an IAS report verifier using the
    /// given trust anchor.
    pub fn new(pem_trust_anchors: &[&str]) -> Result<Self, BuilderError> {
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
            .collect::<Result<Vec<Certificate>, TlsError>>()
            .map_err(|e| BuilderError::InvalidTrustAnchor(e.to_string()))?;

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
    pub fn generate(&mut self) -> IasReportVerifier {
        // Build a list of quote verifiers
        let mut quote_verifiers = self.quote_verifiers.clone();
        quote_verifiers.push(VerifyQuoteType::ReportBody(ReportBodyVerifier {
            body_verifiers: self.report_body_verifiers.clone(),
        }));

        // Build the list of IAS report data verifiers (including a quote
        // verifier)
        let mut verifiers = self.status_verifiers.clone();
        verifiers.push(VerifyIasReportDataType::Quote(QuoteVerifier {
            quote_verifiers,
        }));
        verifiers.extend_from_slice(&self.ias_verifiers);

        // Construct the top-level verifier.
        IasReportVerifier {
            trust_anchors: self.trust_anchors.clone(),
            verifiers,
        }
    }
}

/// A structure which can verify a top-level report.
pub struct IasReportVerifier {
    /// A vector of trust anchor certificates to verify the report signature and
    /// chain against.
    trust_anchors: Vec<Certificate>,
    /// A list of report data verifiers to be applied to the contents of the
    /// JSON report.
    verifiers: Vec<VerifyIasReportDataType>,
}

/// An enumeration of errors which an [`IasReportVerifier`] can produce.
#[derive(Clone, Debug, Display, PartialEq, PartialOrd)]
pub enum VerifierError {
    /// The IAS report does not contain a certificate chain.
    NoChain,
    /// The signature is invalid, or was produced by a public key we do not
    /// trust.
    BadSignature,
    /// There was an error parsing the JSON contents
    Parse(VerifyError),
    /// The report was properly constructed did not meet security requirements.
    Verification(VerificationReportData),
}

impl From<VerifyError> for VerifierError {
    fn from(src: VerifyError) -> VerifierError {
        VerifierError::Parse(src)
    }
}

const MAX_CHAIN_DEPTH: usize = 5;

impl IasReportVerifier {
    /// Verify the given IAS report using this verifier object.
    pub fn verify(
        &self,
        report: &VerificationReport,
    ) -> Result<VerificationReportData, VerifierError> {
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
        // irrelevant, including relationships with blacklisted issuers.
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
            return Err(VerifierError::NoChain);
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

        let parsed_chain: Vec<Certificate> = report
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
                let mut signer_chain: Vec<Certificate> = Vec::new();
                signer_chain.push(cert);
                'outer: loop {
                    // Exclude any signing changes greater than our max depth
                    if signer_chain.len() > MAX_CHAIN_DEPTH {
                        return None;
                    }

                    for chain_cert in &parsed_chain {
                        let mut chain_cert = chain_cert.clone();
                        let existing_cert = signer_chain
                            .last_mut()
                            .expect("Somehow our per-signer chain was empty");
                        if existing_cert.public_key_mut().write_public_der_vec()
                            != chain_cert.public_key_mut().write_public_der_vec()
                            && existing_cert
                                .verify_with_profile(&mut chain_cert, None, Some(&profile), None)
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
                    .last_mut()
                    .expect("Signer chain was somehow emptied before use.");
                // First, check if the last element in the chain is signed by a trust anchor
                for cacert in &mut trust_anchors {
                    if signer_toplevel
                        .verify_with_profile(cacert, None, Some(&profile), None)
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
            .ok_or(VerifierError::BadSignature)?;

        let report_data = VerificationReportData::try_from(report)?;

        for verifier in &self.verifiers {
            if !verifier.verify(&report_data) {
                return Err(VerifierError::Verification(report_data));
            }
        }

        Ok(report_data)
    }
}

/// An enumeration of possible report-data verifier
#[derive(Debug, Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
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
#[derive(Debug, Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
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
            for id in advisory_ids {
                if !config_ids.contains(id) {
                    return false;
                }
            }

            true
        }
        Err(IasQuoteError::SwHardeningNeeded { advisory_ids, .. }) => {
            for id in advisory_ids {
                if !sw_ids.contains(id) {
                    return false;
                }
            }

            true
        }
        Err(IasQuoteError::ConfigurationAndSwHardeningNeeded { advisory_ids, .. }) => {
            for id in advisory_ids {
                if !config_ids.contains(id) && !sw_ids.contains(id) {
                    return false;
                }
            }

            true
        }
        Err(_) => false,
    }
}

/// A [`VerifyIasReportData`] implementation that will check if the enclave in
/// question has the given MrEnclave, and has no other IAS report status issues.
#[derive(Debug, Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
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
    pub fn allow_config_advisory(mut self, id: &str) -> Self {
        self.config_ids.push(id.to_owned());
        self
    }

    /// Assume an enclave with the specified measurement does not need
    /// BIOS configuration changes to address the provided advisory IDs.
    ///
    /// This method should only be used when advised by an enclave author.
    pub fn allow_config_advisories(mut self, ids: &[&str]) -> Self {
        for id in ids {
            self.config_ids.push((*id).to_owned());
        }
        self
    }

    /// Assume the given MrEnclave value has the appropriate software/build-time
    /// hardening for the given advisory ID.
    ///
    /// This method should only be used when advised by an enclave author.
    pub fn allow_hardening_advisory(mut self, id: &str) -> Self {
        self.sw_ids.push(id.to_owned());
        self
    }

    /// Assume the given MrEnclave value has the appropriate software/build-time
    /// hardening for the given advisory IDs.
    ///
    /// This method should only be used when advised by an enclave author.
    pub fn allow_hardening_advisories(mut self, ids: &[&str]) -> Self {
        for id in ids {
            self.sw_ids.push((*id).to_owned());
        }
        self
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
#[derive(Debug, Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
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
    pub fn allow_config_advisory(mut self, id: &str) -> Self {
        self.config_ids.push(id.to_owned());
        self
    }

    /// Assume an enclave with the specified measurement does not need
    /// BIOS configuration changes to address the provided advisory IDs.
    ///
    /// This method should only be used when advised by an enclave author.
    pub fn allow_config_advisories(mut self, ids: &[&str]) -> Self {
        for id in ids {
            self.config_ids.push((*id).to_owned());
        }
        self
    }

    /// Assume the given MrEnclave value has the appropriate software/build-time
    /// hardening for the given advisory ID.
    ///
    /// This method should only be used when advised by an enclave author.
    pub fn allow_hardening_advisory(mut self, id: &str) -> Self {
        self.sw_ids.push(id.to_owned());
        self
    }

    /// Assume the given MrEnclave value has the appropriate software/build-time
    /// hardening for the given advisory IDs.
    ///
    /// This method should only be used when advised by an enclave author.
    pub fn allow_hardening_advisories(mut self, ids: &[&str]) -> Self {
        for id in ids {
            self.sw_ids.push((*id).to_owned());
        }
        self
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
#[derive(Debug, Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
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
#[derive(Debug, Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
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
#[derive(Debug, Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
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
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
struct BasenameVerifier {
    basename: Basename,
}

impl Verify<Quote> for BasenameVerifier {
    fn verify(&self, quote: &Quote) -> bool {
        self.basename == quote.basename()
    }
}

/// A [`Verify<Quote>`] implementation that will simply check that the quote
/// contained in the IAS report matches the quote in this object.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
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
#[derive(Debug, Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
struct EpidGroupIdVerifier {
    epid_group_id: EpidGroupId,
}

impl Verify<Quote> for EpidGroupIdVerifier {
    fn verify(&self, quote: &Quote) -> bool {
        self.epid_group_id == quote.epid_group_id()
    }
}

/// A [`Verify<Quote>`] implementation that will simply check that the QE
/// security version is at least the version given.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
struct PceSecurityVersionVerifier {
    pce_svn: SecurityVersion,
}

impl Verify<Quote> for PceSecurityVersionVerifier {
    fn verify(&self, quote: &Quote) -> bool {
        quote.pce_security_version() >= self.pce_svn
    }
}

/// A [`Verify<Quote>`] implementation that will simply check that the QE
/// security version is at least the version given.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
struct QeSecurityVersionVerifier {
    qe_svn: SecurityVersion,
}

impl Verify<Quote> for QeSecurityVersionVerifier {
    fn verify(&self, quote: &Quote) -> bool {
        quote.qe_security_version() >= self.qe_svn
    }
}

/// A [`Verify<Quote>`] implementation that will collect the results of many
/// independent [`Verify<ReportBody>`] implementations.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
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
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
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
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
struct XeidVerifier {
    xeid: u32,
}

impl Verify<Quote> for XeidVerifier {
    fn verify(&self, quote: &Quote) -> bool {
        self.xeid == quote.xeid()
    }
}

/// An enumeration of known report body verifier types.
#[derive(Debug, Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
enum VerifyReportBodyType {
    Attributes(AttributesVerifier),
    ConfigId(ConfigIdVerifier),
    ConfigVersion(ConfigVersionVerifier),
    CpuVersion(CpuVersionVerifier),
    Debug(DebugVerifier),
    Data(DataVerifier),
    ExtendedProductId(ExtendedProductIdVerifier),
    FamilyId(FamilyIdVerifier),
    MiscSelect(MiscSelectVerifier),
    ProductId(ProductIdVerifier),
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
#[derive(Debug, Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
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
#[derive(Debug, Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
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
#[derive(Debug, Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
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
#[derive(Debug, Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
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
#[derive(Debug, Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
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
#[derive(Debug, Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
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
#[derive(Debug, Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
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
#[derive(Debug, Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
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
#[derive(Debug, Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
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
#[derive(Debug, Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
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
#[derive(Debug, Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
struct VersionVerifier {
    version: SecurityVersion,
}

impl Verify<ReportBody> for VersionVerifier {
    fn verify(&self, report_body: &ReportBody) -> bool {
        self.version <= report_body.security_version()
    }
}
