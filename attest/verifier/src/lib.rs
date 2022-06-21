// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Intel Attestation Report Verifiers
//!
//! This crate contains a verification framework for examining a
//! [`VerificationReport`](::mc_attest_core::VerificationReport) data for
//! compliance with a pre-determined set of criteria, which is the core
//! mechanism for authenticating attested connections.

#![doc = include_str!("../README.md")]
#![no_std]

mod avr;
mod ias;
mod quote;
mod report_body;
mod status;

extern crate alloc;

pub use crate::status::{MrEnclaveVerifier, MrSignerVerifier};

cfg_if::cfg_if! {
    if #[cfg(feature = "sgx-sim")] {
        /// The build-time generated mock IAS signing root authority
        pub const IAS_SIM_ROOT_ANCHORS: &str =
            concat!(include_str!("../data/sim/root_anchor.pem"), "\0");
        /// The build-time generated mock IAS signing certificate chain
        pub const IAS_SIM_SIGNING_CHAIN: &str = concat!(include_str!("../data/sim/chain.pem"), "\0");
        /// The build-time generated mock IAS signing private key
        pub const IAS_SIM_SIGNING_KEY: &str = concat!(include_str!("../data/sim/signer.key"), "\0");

        /// Whether or not enclaves should be run and validated in debug mode
        pub const DEBUG_ENCLAVE: bool = true;
        /// An array of zero-terminated signing certificate PEM files used as root anchors.
        pub const IAS_SIGNING_ROOT_CERT_PEMS: &[&str] = &[IAS_SIM_ROOT_ANCHORS];
    } else if #[cfg(feature = "ias-dev")] {
        /// Whether or not enclaves should be run and validated in debug mode
        pub const DEBUG_ENCLAVE: bool = true;
        /// An array of zero-terminated signing certificate PEM files used as root anchors.
        pub const IAS_SIGNING_ROOT_CERT_PEMS: &[&str] = &[concat!(include_str!(
            "../data/Dev_AttestationReportSigningCACert.pem"
        ), "\0")];
    } else {
        /// Debug enclaves in prod mode are not supported.
        pub const DEBUG_ENCLAVE: bool = false;
        /// An array of zero-terminated signing certificate PEM files used as root anchors.
        pub const IAS_SIGNING_ROOT_CERT_PEMS: &[&str] = &[concat!(include_str!(
            "../data/AttestationReportSigningCACert.pem"
        ), "\0")];
    }
}

use crate::{
    avr::{Kind as AvrKind, PseVerifier},
    ias::IasReportVerifier,
    quote::{Kind as QuoteKind, XeidVerifier},
    report_body::{
        ConfigVersionVerifier, DebugVerifier, Kind as ReportBodyKind, MiscSelectVerifier,
        ProductIdVerifier, VersionVerifier,
    },
    status::Kind as StatusKind,
};
use alloc::{
    borrow::ToOwned,
    string::{String, ToString},
    vec::Vec,
};
use core::fmt;
use displaydoc::Display;
use hex_fmt::HexList;
use mbedtls::{alloc::Box as MbedtlsBox, x509::Certificate, Error as TlsError};
use mc_attest_core::{
    Attributes, Basename, ConfigId, ConfigSecurityVersion, CpuSecurityVersion, EpidGroupId,
    ExtendedProductId, FamilyId, IasNonce, MiscSelect, ProductId, Quote, QuoteSignType,
    ReportDataMask, SecurityVersion, VerificationReport, VerificationReportData, VerifyError,
};
use serde::{Deserialize, Serialize};

/// Private macros used inside this crate.
mod macros {
    // impl From<verifier> for Kind, impl From<inner> for Verifier
    macro_rules! impl_kind_from_verifier {
        ($($verifier:ident, $disc:ident, $inner:ty;)*) => {$(
            impl From<$verifier> for Kind {
                fn from(verifier: $verifier) -> Self {
                    Kind::$disc(verifier)
                }
            }

            impl From<$inner> for $verifier {
                fn from(inner: $inner) -> $verifier {
                    $verifier(inner)
                }
            }
        )*}
    }

    macro_rules! impl_kind_from_inner {
        ($($verifier:ident, $disc:ident, $inner:ty;)*) => {$(
            $crate::macros::impl_kind_from_verifier!{ $verifier, $disc, $inner; }

            impl From<$inner> for Kind {
                fn from(inner: $inner) -> Kind {
                    <$verifier>::from(inner).into()
                }
            }
        )*};
    }

    pub(crate) use impl_kind_from_inner;
    pub(crate) use impl_kind_from_verifier;
}

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

impl From<VerifyError> for Error {
    fn from(src: VerifyError) -> Error {
        Error::Parse(src)
    }
}

/// A builder structure used to construct a report verifier based on the
/// criteria specified.
#[derive(Clone, Deserialize, PartialEq, Serialize)]
pub struct Verifier {
    /// A list of DER-encoded trust anchor certificates.
    trust_anchors: Vec<Vec<u8>>,
    report_body_verifiers: Vec<ReportBodyKind>,
    quote_verifiers: Vec<QuoteKind>,
    avr_verifiers: Vec<AvrKind>,
    status_verifiers: Vec<StatusKind>,
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
            avr_verifiers: Default::default(),
            status_verifiers: Default::default(),
        })
    }

    /// Verify that the nonce contained within the report matches the nonce
    /// provided.
    ///
    /// This is useful to prevent IAS report response replay attacks.
    pub fn nonce(&mut self, nonce: &IasNonce) -> &mut Self {
        self.avr_verifiers.push(nonce.clone().into());
        self
    }

    /// Verify that the PSE manifest hash matches the one given, and the result
    /// is successful.
    pub fn pse_result(&mut self, hash: &[u8]) -> &mut Self {
        self.avr_verifiers
            .push(PseVerifier::from(hash.to_owned()).into());
        self
    }

    /// Verify that the basename in the quote matches the basename given.
    pub fn basename(&mut self, basename: &Basename) -> &mut Self {
        self.quote_verifiers.push((*basename).into());
        self
    }

    /// Verify that the EPID group ID in the quote matches the group ID given.
    ///
    /// This test is useful to ensure continuity of message flow.
    pub fn epid_group_id(&mut self, epid_group_id: &EpidGroupId) -> &mut Self {
        self.quote_verifiers.push((*epid_group_id).into());
        self
    }

    /// Verify that the quote body within the IAS report matches the existing
    /// quote exactly.
    pub fn quote_body(&mut self, quote: &Quote) -> &mut Self {
        self.quote_verifiers.push(quote.clone().into());
        self
    }

    /// Verify that the quote body was created with the appropriate type
    /// (linkable vs. unlinkable).
    pub fn sign_type(&mut self, sign_type: QuoteSignType) -> &mut Self {
        self.quote_verifiers.push(sign_type.into());
        self
    }

    /// Verify that the quoting enclave's security version is at least the given
    /// version.
    pub fn qe_security_version(&mut self, qe_svn: SecurityVersion) -> &mut Self {
        self.quote_verifiers.push(QuoteKind::QeSvn(qe_svn.into()));
        self
    }

    /// Verify that the quoting enclave's security version is at least the given
    /// version.
    pub fn pce_security_version(&mut self, pce_svn: SecurityVersion) -> &mut Self {
        self.quote_verifiers.push(QuoteKind::PceSvn(pce_svn.into()));
        self
    }

    /// Verify the EPID signature is of the type indicated.
    pub fn quote_sign(&mut self, sign_type: QuoteSignType) -> &mut Self {
        self.quote_verifiers.push(sign_type.into());
        self
    }

    /// Verify the quote's XEID matches the given value
    pub fn xeid(&mut self, xeid: u32) -> &mut Self {
        self.quote_verifiers.push(XeidVerifier::from(xeid).into());
        self
    }

    /// Verify the report body attributes matches the given value.
    pub fn attributes(&mut self, attributes: &Attributes) -> &mut Self {
        self.report_body_verifiers.push((*attributes).into());
        self
    }

    /// Verify the report body config ID matches the given value.
    pub fn config_id(&mut self, config_id: &ConfigId) -> &mut Self {
        self.report_body_verifiers.push((*config_id).into());
        self
    }

    /// Verify the report body config version is at least the given value.
    pub fn config_version(&mut self, config_svn: ConfigSecurityVersion) -> &mut Self {
        self.report_body_verifiers
            .push(ConfigVersionVerifier::from(config_svn).into());
        self
    }

    /// Verify the report body CPU version is at least the given value.
    pub fn cpu_version(&mut self, cpu_svn: &CpuSecurityVersion) -> &mut Self {
        self.report_body_verifiers.push((*cpu_svn).into());
        self
    }

    /// Verify the enclave debug mode is as-expected
    pub fn debug(&mut self, allow_debug: bool) -> &mut Self {
        self.report_body_verifiers
            .push(DebugVerifier::from(allow_debug).into());
        self
    }

    /// Verify the report data matches the data mask given
    pub fn report_data(&mut self, report_data: &ReportDataMask) -> &mut Self {
        self.report_body_verifiers.push((*report_data).into());
        self
    }

    /// Verify the report body extended product ID matches the given value.
    pub fn extended_product_id(&mut self, ext_prod_id: &ExtendedProductId) -> &mut Self {
        self.report_body_verifiers.push((*ext_prod_id).into());
        self
    }

    /// Verify the report body family ID matches the given value.
    pub fn family_id(&mut self, family_id: &FamilyId) -> &mut Self {
        self.report_body_verifiers.push((*family_id).into());
        self
    }

    /// Verify the report body misc selection matches the given value.
    pub fn misc_select(&mut self, misc_select: MiscSelect) -> &mut Self {
        self.report_body_verifiers
            .push(MiscSelectVerifier::from(misc_select).into());
        self
    }

    /// Verify the report body product ID matches the given value.
    pub fn product_id(&mut self, product_id: ProductId) -> &mut Self {
        self.report_body_verifiers
            .push(ProductIdVerifier::from(product_id).into());
        self
    }

    /// Verify the report body (enclave) version is at least the given value.
    pub fn version(&mut self, version: SecurityVersion) -> &mut Self {
        self.report_body_verifiers
            .push(VersionVerifier::from(version).into());
        self
    }

    /// Verify the given MrEnclave-based status verifier succeeds
    pub fn mr_enclave(&mut self, verifier: MrEnclaveVerifier) -> &mut Self {
        self.status_verifiers.push(verifier.into());
        self
    }

    /// Verify the given MrSigner-based status verifier succeeds
    pub fn mr_signer(&mut self, verifier: MrSignerVerifier) -> &mut Self {
        self.status_verifiers.push(verifier.into());
        self
    }

    /// Compile the report verifier which a report will be given to
    pub fn verify(&self, report: &VerificationReport) -> Result<VerificationReportData, Error> {
        // Build a list of quote verifiers
        let mut quote_verifiers = self.quote_verifiers.clone();
        quote_verifiers.push(self.report_body_verifiers.clone().into());

        // Build the list of IAS report data verifiers (including a quote
        // verifier)
        let mut and_verifiers = self.avr_verifiers.clone();
        and_verifiers.push(quote_verifiers.into());

        let trust_anchors = self
            .trust_anchors
            .iter()
            .map(|cert_der| {
                Certificate::from_der(cert_der.as_slice())
                    .expect("Trust anchors modified after Verifier creation")
            })
            .collect::<Vec<MbedtlsBox<Certificate>>>();

        // Construct the top-level verifier, and verify the IAS report
        IasReportVerifier::new(trust_anchors, self.status_verifiers.clone(), and_verifiers)
            .verify(report)
    }
}

impl fmt::Debug for Verifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Verifier")
            .field("trust_anchors", &HexList(&self.trust_anchors))
            .field("report_body_verifiers", &self.report_body_verifiers)
            .field("quote_verifiers", &self.quote_verifiers)
            .field("avr_verifiers", &self.avr_verifiers)
            .field("status_verifiers", &self.status_verifiers)
            .finish()
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use alloc::vec;
    use mc_attest_core::{MrEnclave, MrSigner, VerificationSignature};
    use mc_util_encodings::FromHex;

    const TEST_ANCHORS: &[&str] = &[include_str!(
        "../data/Dev_AttestationReportSigningCACert.pem"
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
}
