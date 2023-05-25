// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Verifiers which operate on contents of the
//! [`Quote`](::mc_attest_core::Quote) data structure.

use crate::{
    macros::{impl_kind_from_inner, impl_kind_from_verifier},
    report_body::Kind as ReportBodyKind,
    Verify,
};
use alloc::vec::Vec;
use mc_attest_core::{Basename, EpidGroupId, Quote, QuoteSignType, SecurityVersion};
use serde::{Deserialize, Serialize};

/// An enumeration of quote content verifiers
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub enum Kind {
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

impl Verify<Quote> for Kind {
    fn verify(&self, quote: &Quote) -> bool {
        match self {
            Kind::Basename(v) => v.verify(quote),
            Kind::Body(v) => v.verify(quote),
            Kind::EpidGroupId(v) => v.verify(quote),
            Kind::QeSvn(v) => v.verify(quote),
            Kind::PceSvn(v) => v.verify(quote),
            Kind::ReportBody(v) => v.verify(quote),
            Kind::SignType(v) => v.verify(quote),
            Kind::Xeid(v) => v.verify(quote),
        }
    }
}

impl_kind_from_inner! {
    BasenameVerifier, Basename, Basename;
    QuoteContentsEqVerifier, Body, Quote;
    EpidGroupIdVerifier, EpidGroupId, EpidGroupId;
    ReportBodyVerifier, ReportBody, Vec<ReportBodyKind>;
    SignTypeVerifier, SignType, QuoteSignType;
}

impl_kind_from_verifier! {
    QeSecurityVersionVerifier, QeSvn, SecurityVersion;
    PceSecurityVersionVerifier, PceSvn, SecurityVersion;
    XeidVerifier, Xeid, u32;
}

/// A [`Verify<Quote>`] implementation that will check if the basename is as
/// expected.
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub struct BasenameVerifier(Basename);

impl Verify<Quote> for BasenameVerifier {
    fn verify(&self, quote: &Quote) -> bool {
        quote
            .basename()
            .map(|basename| basename == self.0)
            .unwrap_or(false)
    }
}

/// A [`Verify<Quote>`] implementation that will simply check that the quote
/// contained in the IAS report matches the quote in this object.
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub struct QuoteContentsEqVerifier(Quote);

impl Verify<Quote> for QuoteContentsEqVerifier {
    fn verify(&self, quote: &Quote) -> bool {
        self.0.contents_eq(quote)
    }
}

/// A [`Verify<Quote>`] implementation that will check if the EPID group ID in
/// the IAS quote is expected.
///
/// This can form a very basic sanity check to verify that the SigRL provided
/// for the quote is as expected.
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub struct EpidGroupIdVerifier(EpidGroupId);

impl Verify<Quote> for EpidGroupIdVerifier {
    fn verify(&self, quote: &Quote) -> bool {
        quote
            .epid_group_id()
            .map(|epid_group_id| epid_group_id == self.0)
            .unwrap_or(false)
    }
}

/// A [`Verify<Quote>`] implementation that will simply check that the QE
/// security version is at least the version given.
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub struct PceSecurityVersionVerifier(SecurityVersion);

impl Verify<Quote> for PceSecurityVersionVerifier {
    fn verify(&self, quote: &Quote) -> bool {
        quote
            .pce_security_version()
            .map(|pce_svn| pce_svn >= self.0)
            .unwrap_or(false)
    }
}

/// A [`Verify<Quote>`] implementation that will simply check that the QE
/// security version is at least the version given.
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub struct QeSecurityVersionVerifier(SecurityVersion);

impl Verify<Quote> for QeSecurityVersionVerifier {
    fn verify(&self, quote: &Quote) -> bool {
        quote
            .qe_security_version()
            .map(|qe_svn| qe_svn >= self.0)
            .unwrap_or(false)
    }
}

/// A [`Verify<Quote>`] implementation that will collect the results of many
/// independent [`Verify<ReportBody>`] implementations.
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub struct ReportBodyVerifier(Vec<ReportBodyKind>);

impl Verify<Quote> for ReportBodyVerifier {
    fn verify(&self, quote: &Quote) -> bool {
        if let Ok(report_body) = quote.report_body() {
            let mut result = 0xffff_ffff;
            for verifier in &self.0 {
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
pub struct SignTypeVerifier(QuoteSignType);

impl Verify<Quote> for SignTypeVerifier {
    fn verify(&self, quote: &Quote) -> bool {
        if let Ok(sign_type) = quote.sign_type() {
            sign_type == self.0
        } else {
            false
        }
    }
}

/// A [`Verify<Quote>`] implementation that will check if the XEID matches
/// expectations.
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub struct XeidVerifier(u32);

impl Verify<Quote> for XeidVerifier {
    fn verify(&self, quote: &Quote) -> bool {
        quote.xeid().map(|xeid| xeid == self.0).unwrap_or(false)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use mc_sgx_types::sgx_basename_t;
    use mc_util_encodings::FromBase64;

    const BASE64_QUOTE: &str = include_str!("../data/test/quote_ok.txt");
    const BASE64_QUOTE2: &str = include_str!("../data/test/quote_configuration_needed.txt");

    /// When the quote contains the basename we're expecting
    #[test]
    fn basename_success() {
        let quote =
            Quote::from_base64(BASE64_QUOTE).expect("Could not parse quote from base64 file");
        let verifier = Kind::from(quote.basename().expect("Could not read basename"));

        assert!(verifier.verify(&quote));
    }

    /// When the quote does not contain the basename we're expecting
    #[test]
    fn basename_fail() {
        let quote =
            Quote::from_base64(BASE64_QUOTE).expect("Could not parse quote from base64 file");
        let basename = sgx_basename_t { name: [0u8; 32] };
        let verifier = Kind::from(Basename::from(basename));

        assert!(!verifier.verify(&quote));
    }

    /// When the quote matches what we're expecting
    #[test]
    fn quote_contents_success() {
        let quote =
            Quote::from_base64(BASE64_QUOTE).expect("Could not parse quote from base64 file");
        let verifier = Kind::from(quote.clone());

        assert!(verifier.verify(&quote));
    }

    /// When the report does not contain the EPID group ID we're expecting
    #[test]
    fn quote_contents_fail() {
        let quote =
            Quote::from_base64(BASE64_QUOTE).expect("Could not parse quote from base64 file");
        let verifier = Kind::from(
            Quote::from_base64(BASE64_QUOTE2)
                .expect("Could not parse other quote from base64 file"),
        );

        assert!(!verifier.verify(&quote));
    }

    /// When the report contains the EPID group ID we're expecting
    #[test]
    fn epid_group_id_success() {
        let quote =
            Quote::from_base64(BASE64_QUOTE).expect("Could not parse quote from base64 file");
        let verifier = Kind::from(quote.epid_group_id().expect("Could not read EPID Group ID"));

        assert!(verifier.verify(&quote));
    }

    /// When the report does not contain the EPID group ID we're expecting
    #[test]
    fn epid_group_id_fail() {
        let quote =
            Quote::from_base64(BASE64_QUOTE).expect("Could not parse quote from base64 file");
        let epid_group_id = [0u8; 4];
        let verifier = Kind::from(EpidGroupId::from(epid_group_id));

        assert!(!verifier.verify(&quote));
    }

    /// When the provisioning certificate enclave has the exact version we want
    #[test]
    fn pce_svn_eq_pass() {
        let quote =
            Quote::from_base64(BASE64_QUOTE).expect("Could not parse quote from base64 file");
        let verifier = Kind::PceSvn(
            quote
                .pce_security_version()
                .expect("PCE SVN could not be read")
                .into(),
        );

        assert!(verifier.verify(&quote));
    }

    /// When the provisioning certificate enclave has a newer version than we
    /// want
    #[test]
    fn pce_svn_newer_pass() {
        let quote =
            Quote::from_base64(BASE64_QUOTE).expect("Could not parse quote from base64 file");
        let verifier = Kind::PceSvn(
            (quote
                .pce_security_version()
                .expect("PCE SVN could not be read")
                - 1)
            .into(),
        );

        assert!(verifier.verify(&quote));
    }

    /// When the provisioning certificate enclave has an older version than we
    /// want
    #[test]
    fn pce_svn_older_fail() {
        let quote =
            Quote::from_base64(BASE64_QUOTE).expect("Could not parse quote from base64 file");
        let verifier = Kind::PceSvn(
            (quote
                .pce_security_version()
                .expect("PCE SVN could not be read")
                + 1)
            .into(),
        );

        assert!(!verifier.verify(&quote));
    }

    /// When the quoting enclaves has the exact version we want
    #[test]
    fn qe_svn_eq_pass() {
        let quote =
            Quote::from_base64(BASE64_QUOTE).expect("Could not parse quote from base64 file");
        let verifier = Kind::QeSvn(
            quote
                .qe_security_version()
                .expect("QE SVN could not be read")
                .into(),
        );

        assert!(verifier.verify(&quote));
    }

    /// When the quoting enclave has a newer version than we want
    #[test]
    fn qe_svn_newer_pass() {
        let quote =
            Quote::from_base64(BASE64_QUOTE).expect("Could not parse quote from base64 file");
        let verifier = Kind::QeSvn(
            (quote
                .qe_security_version()
                .expect("QE SVN could not be read")
                - 1)
            .into(),
        );

        assert!(verifier.verify(&quote));
    }

    /// When the quoting enclave has an older version than we want
    #[test]
    fn qe_svn_older_fail() {
        let quote =
            Quote::from_base64(BASE64_QUOTE).expect("Could not parse quote from base64 file");
        let verifier = Kind::QeSvn(
            (quote
                .qe_security_version()
                .expect("QE SVN could not be read")
                + 1)
            .into(),
        );

        assert!(!verifier.verify(&quote));
    }

    /// When the quote contains the sign type we want
    #[test]
    fn sign_type_success() {
        let quote =
            Quote::from_base64(BASE64_QUOTE).expect("Could not parse quote from base64 file");
        let verifier = Kind::from(quote.sign_type().expect("Could not retreive sign type"));

        assert!(verifier.verify(&quote));
    }

    /// When the quote doesn't contain the sign type we want
    #[test]
    fn sign_type_fail() {
        let quote =
            Quote::from_base64(BASE64_QUOTE).expect("Could not parse quote from base64 file");
        let verifier = Kind::from(QuoteSignType::Linkable);

        assert!(!verifier.verify(&quote));
    }

    /// When the report contains the attributes we want
    #[test]
    fn xeid_success() {
        let quote =
            Quote::from_base64(BASE64_QUOTE).expect("Could not parse quote from base64 file");
        let verifier = Kind::from(XeidVerifier::from(
            quote.xeid().expect("Xeid could not be read"),
        ));

        assert!(verifier.verify(&quote));
    }

    /// When the report contains attributes we don't want
    #[test]
    fn xeid_fail() {
        let quote =
            Quote::from_base64(BASE64_QUOTE).expect("Could not parse quote from base64 file");
        let verifier = Kind::from(XeidVerifier::from(
            quote.xeid().expect("Xeid could not be read") + 1,
        ));

        assert!(!verifier.verify(&quote));
    }
}
