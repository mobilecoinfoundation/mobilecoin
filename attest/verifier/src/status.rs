// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Verifiers which check the IAS quote status result for particular
//! [`MrEnclave`](::mc_attest_core::MrEnclave) and
//! [`MrSigner`](::mc_attest_core::MrSigner) values and advisory IDs.
//!
//! This bundle is what allows us to say "IAS failed to give us a clean bill of
//! health, and instead said SW_HARDENING_NEEDED to mitigate INTEL-SA-00334, but
//! we know enclaves with the measurement of `FOO` are hardened, so we can trust
//! it anyways."
//!
//! That sentence is the recommended verification in post-LVI SGX, and these
//! combination "measurement + known-mitigated advisories" verifiers let us
//! implement that.

use crate::Verify;
use alloc::borrow::ToOwned;
use mc_attest_core::{IasQuoteError, IasQuoteResult, IsvProductId, IsvSvn, VerificationReportData};
use mc_attestation_verifier::{
    Advisories, AdvisoriesVerifier, AdvisoryStatus, TrustedIdentity, TrustedMrEnclaveIdentity,
    TrustedMrSignerIdentity, Verifier,
};
use mc_sgx_core_types::{MrEnclave, MrSigner};
use mc_sgx_css::Signature;
use serde::{Deserialize, Serialize};

/// A helper function used to check exceptions to the quote error = fail rule.
fn check_ids(quote_status: &IasQuoteResult, advisories: &Advisories) -> bool {
    let verifier = AdvisoriesVerifier::new(advisories.to_owned());
    match quote_status {
        Ok(_) => true,
        Err(IasQuoteError::ConfigurationNeeded { advisory_ids, .. }) => verifier
            .verify(&Advisories::new(
                advisory_ids,
                AdvisoryStatus::ConfigurationNeeded,
            ))
            .is_success()
            .into(),
        Err(IasQuoteError::SwHardeningNeeded { advisory_ids, .. }) => verifier
            .verify(&Advisories::new(
                advisory_ids,
                AdvisoryStatus::SWHardeningNeeded,
            ))
            .is_success()
            .into(),
        Err(IasQuoteError::ConfigurationAndSwHardeningNeeded { advisory_ids, .. }) =>
        //advisory_ids
        {
            verifier
                .verify(&Advisories::new(
                    advisory_ids,
                    AdvisoryStatus::ConfigurationAndSWHardeningNeeded,
                ))
                .is_success()
                .into()
        }
        Err(_) => false,
    }
}

/// An enumeration of status verifier types
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub enum Kind {
    /// A measurement-and-status verifier which will check for a MRENCLAVE
    /// value, and allow select non-OK quote-status results from IAS.
    Enclave(MrEnclaveVerifier),
    /// A measurement-and-status verifier which will check for a
    /// MRSIGNER/product-id/enclave-version tuple, allow select non-OK
    /// quote-status results from IAS.
    Signer(MrSignerVerifier),
}

impl Kind {
    /// Advisories an enclave is allowed to have.
    ///
    /// This method should only be used when advised by an enclave author.
    pub fn set_advisories(&mut self, advisories: Advisories) -> &mut Self {
        match self {
            Kind::Enclave(v) => {
                v.set_advisories(advisories);
            }
            Kind::Signer(v) => {
                v.set_advisories(advisories);
            }
        }
        self
    }
}

impl From<&TrustedIdentity> for Kind {
    fn from(trusted_identity: &TrustedIdentity) -> Kind {
        match trusted_identity {
            TrustedIdentity::MrEnclave(mr_enclave) => MrEnclaveVerifier::from(mr_enclave).into(),
            TrustedIdentity::MrSigner(mr_signer) => MrSignerVerifier::from(mr_signer).into(),
        }
    }
}

impl From<MrEnclaveVerifier> for Kind {
    fn from(verifier: MrEnclaveVerifier) -> Kind {
        Kind::Enclave(verifier)
    }
}

impl From<MrSignerVerifier> for Kind {
    fn from(verifier: MrSignerVerifier) -> Kind {
        Kind::Signer(verifier)
    }
}

impl Verify<VerificationReportData> for Kind {
    fn verify(&self, data: &VerificationReportData) -> bool {
        match self {
            Kind::Enclave(v) => v.verify(data),
            Kind::Signer(v) => v.verify(data),
        }
    }
}

/// A [`Verify<VerificationReportData>`] implementation that will check if the
/// enclave in question has the given MrEnclave, and has no other IAS report
/// status issues.
#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct MrEnclaveVerifier {
    mr_enclave: MrEnclave,
    advisories: Advisories,
}

impl MrEnclaveVerifier {
    /// Create a new status verifier that will check for the existence of the
    /// given MrEnclave.
    pub fn new(mr_enclave: MrEnclave) -> MrEnclaveVerifier {
        Self {
            mr_enclave,
            advisories: Advisories::default(),
        }
    }

    /// Advisories an enclave is allowed to have.
    ///
    /// This method should only be used when advised by an enclave author.
    pub fn set_advisories(&mut self, advisories: Advisories) -> &mut Self {
        self.advisories = advisories;
        self
    }
}

impl From<Signature> for MrEnclaveVerifier {
    fn from(src: Signature) -> Self {
        Self::new(MrEnclave::from(*(src.mrenclave())))
    }
}

impl From<&TrustedMrEnclaveIdentity> for MrEnclaveVerifier {
    fn from(mr_enclave_identity: &TrustedMrEnclaveIdentity) -> Self {
        let mut verifier = Self::new(mr_enclave_identity.mr_enclave());
        verifier.set_advisories(mr_enclave_identity.advisories());
        verifier
    }
}

impl Verify<VerificationReportData> for MrEnclaveVerifier {
    fn verify(&self, data: &VerificationReportData) -> bool {
        if let Ok(report_body) = data.quote.report_body() {
            self.mr_enclave == report_body.mr_enclave()
                && check_ids(&data.quote_status, &self.advisories)
        } else {
            false
        }
    }
}

/// A [`VerifyIasReportData`] implementation that will check if the enclave in
/// question has the given MrSigner value, and has no other IAS report status
/// issues.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct MrSignerVerifier {
    mr_signer: MrSigner,
    product_id: IsvProductId,
    minimum_svn: IsvSvn,
    advisories: Advisories,
}

impl MrSignerVerifier {
    /// Create a new status verifier that will check for the existence of the
    /// given MrSigner.
    pub fn new(
        mr_signer: MrSigner,
        product_id: IsvProductId,
        minimum_svn: IsvSvn,
    ) -> MrSignerVerifier {
        Self {
            mr_signer,
            product_id,
            minimum_svn,
            advisories: Advisories::default(),
        }
    }

    /// Advisories an enclave is allowed to have.
    ///
    /// This method should only be used when advised by an enclave author.
    pub fn set_advisories(&mut self, advisories: Advisories) -> &mut Self {
        self.advisories = advisories;
        self
    }
}

impl From<Signature> for MrSignerVerifier {
    fn from(src: Signature) -> Self {
        Self::from(&src)
    }
}

impl From<&Signature> for MrSignerVerifier {
    fn from(src: &Signature) -> Self {
        Self::new(src.mrsigner().into(), src.product_id(), src.version())
    }
}

impl From<&TrustedMrSignerIdentity> for MrSignerVerifier {
    fn from(mr_signer_identity: &TrustedMrSignerIdentity) -> Self {
        let mut verifier = Self::new(
            mr_signer_identity.mr_signer(),
            mr_signer_identity.isv_product_id(),
            mr_signer_identity.isv_svn(),
        );
        verifier.set_advisories(mr_signer_identity.advisories());
        verifier
    }
}

impl Verify<VerificationReportData> for MrSignerVerifier {
    fn verify(&self, data: &VerificationReportData) -> bool {
        if let Ok(report_body) = data.quote.report_body() {
            self.mr_signer == report_body.mr_signer()
                && report_body.isv_product_id() == self.product_id
                && report_body.isv_svn().as_ref() >= self.minimum_svn.as_ref()
                && check_ids(&data.quote_status, &self.advisories)
        } else {
            false
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use alloc::vec;
    use mc_attest_core::VerificationReport;

    /// Report with OK status
    const IAS_OK: &str = include_str!("../data/test/ias_ok.json");

    /// Report with "CONFIGURATION_NEEDED" status
    const IAS_CONFIG: &str = include_str!("../data/test/ias_config.json");

    /// Report with "SW_HARDENING_NEEDED" status
    const IAS_SW: &str = include_str!("../data/test/ias_sw.json");

    /// Report with "SW_HARDENING_NEEDED" and both 334 and 615 advisories.
    const IAS_SW_334_615: &str = include_str!("../data/test/ias_sw_334_615.json");

    /// Report with "CONFIGURATION_AND_SW_HARDENING_NEEDED" status
    const IAS_CONFIG_SW: &str = include_str!("../data/test/ias_config_sw.json");

    /// Report with "CONFIGURATION_AND_SW_HARDENING_NEEDED" status, and both 334
    /// and 615 advisories.
    const IAS_CONFIG_SW_334_615: &str = include_str!("../data/test/ias_config_sw_334_615.json");

    const MR_ENCLAVE: [u8; 32] = [
        247, 180, 107, 31, 41, 201, 41, 41, 32, 42, 25, 79, 7, 29, 232, 138, 9, 180, 143, 195, 110,
        244, 197, 245, 247, 21, 202, 61, 246, 188, 124, 234,
    ];
    const MR_SIGNER: [u8; 32] = [
        126, 229, 226, 157, 116, 98, 63, 219, 198, 251, 241, 69, 75, 230, 243, 187, 11, 134, 193,
        35, 102, 183, 180, 120, 173, 19, 53, 62, 68, 222, 132, 17,
    ];

    /// Ensure an OK result with the expected MRENCLAVE value succeeds.
    #[test]
    fn mrenclave_ok() {
        let verifier = MrEnclaveVerifier {
            mr_enclave: MrEnclave::try_from(MR_ENCLAVE).expect("BUG: invalid test data"),
            advisories: Advisories::default(),
        };

        let report = VerificationReport {
            sig: Default::default(),
            chain: vec![],
            http_body: IAS_OK.trim().to_owned(),
            evidence_message_bytes: vec![],
        };

        let data = VerificationReportData::try_from(&report).expect("Could not parse IAS result");
        assert!(verifier.verify(&data))
    }

    /// Ensure an OK result with the wrong MRENCLAVE value fails.
    #[test]
    fn mrenclave_fail() {
        let verifier = MrEnclaveVerifier {
            mr_enclave: MrEnclave::try_from(MR_SIGNER).expect("BUG: invalid test data"),
            advisories: Advisories::default(),
        };

        let report = VerificationReport {
            sig: Default::default(),
            chain: vec![],
            http_body: IAS_OK.trim().to_owned(),
            evidence_message_bytes: vec![],
        };

        let data = VerificationReportData::try_from(&report).expect("Could not parse IAS result");
        assert!(!verifier.verify(&data))
    }

    /// Ensure a CONFIGURATION_NEEDED result with the expected MRENCLAVE and
    /// allowed advisory passes.
    #[test]
    fn mrenclave_config_pass() {
        let verifier = MrEnclaveVerifier {
            mr_enclave: MrEnclave::try_from(MR_ENCLAVE).expect("BUG: invalid test data"),
            advisories: Advisories::new(
                &vec!["INTEL-SA-00239".to_owned(), "INTEL-SA-00123".to_owned()],
                AdvisoryStatus::ConfigurationAndSWHardeningNeeded,
            ),
        };

        let report = VerificationReport {
            sig: Default::default(),
            chain: vec![],
            http_body: IAS_CONFIG.trim().to_owned(),
            evidence_message_bytes: vec![],
        };

        let data = VerificationReportData::try_from(&report).expect("Could not parse IAS result");
        assert!(verifier.verify(&data))
    }

    /// Ensure a CONFIGURATION_NEEDED result with the expected MRENCLAVE and
    /// unexpected advisory passes.
    #[test]
    fn mrenclave_config_and_sw_pass() {
        let verifier = MrEnclaveVerifier {
            mr_enclave: MrEnclave::try_from(MR_ENCLAVE).expect("BUG: invalid test data"),
            advisories: Advisories::new(
                &vec!["INTEL-SA-00123", "INTEL-SA-00239"],
                AdvisoryStatus::ConfigurationAndSWHardeningNeeded,
            ),
        };

        let report = VerificationReport {
            sig: Default::default(),
            chain: vec![],
            http_body: IAS_CONFIG.trim().to_owned(),
            evidence_message_bytes: vec![],
        };

        let data = VerificationReportData::try_from(&report).expect("Could not parse IAS result");
        assert!(verifier.verify(&data))
    }

    /// Ensure a SW_HARDENING_NEEDED result with the expected MRENCLAVE and
    /// advisory passes.
    #[test]
    fn mrenclave_sw_pass() {
        let verifier = MrEnclaveVerifier {
            mr_enclave: MrEnclave::try_from(MR_ENCLAVE).expect("BUG: invalid test data"),
            advisories: Advisories::new(
                &vec!["INTEL-SA-00123".to_owned(), "INTEL-SA-00239".to_owned()],
                AdvisoryStatus::ConfigurationAndSWHardeningNeeded,
            ),
        };

        let report = VerificationReport {
            sig: Default::default(),
            chain: vec![],
            http_body: IAS_SW.trim().to_owned(),
            evidence_message_bytes: vec![],
        };

        let data = VerificationReportData::try_from(&report).expect("Could not parse IAS result");
        assert!(verifier.verify(&data))
    }

    /// Ensure a SW_HARDENING_NEEDED result with the expected MRENCLAVE and
    /// advisories passes.
    #[test]
    fn mrenclave_multi_sw_pass() {
        let verifier = MrEnclaveVerifier {
            mr_enclave: MrEnclave::try_from(MR_ENCLAVE).expect("BUG: invalid test data"),
            advisories: Advisories::new(
                &vec!["INTEL-SA-00334".to_owned(), "INTEL-SA-00615".to_owned()],
                AdvisoryStatus::SWHardeningNeeded,
            ),
        };

        let report = VerificationReport {
            sig: Default::default(),
            chain: vec![],
            http_body: IAS_SW_334_615.trim().to_owned(),
            evidence_message_bytes: vec![],
        };

        let data = VerificationReportData::try_from(&report).expect("Could not parse IAS result");
        assert!(verifier.verify(&data))
    }

    /// Ensure a SW_HARDENING_NEEDED result with the expected MRENCLAVE but
    /// unexpected advisory passes.
    #[test]
    fn mrenclave_sw_fail() {
        let verifier = MrEnclaveVerifier {
            mr_enclave: MrEnclave::try_from(MR_ENCLAVE).expect("BUG: invalid test data"),
            advisories: Advisories::new(
                &vec!["INTEL-SA-00239", "INTEL-SA-00123"],
                AdvisoryStatus::SWHardeningNeeded,
            ),
        };

        let report = VerificationReport {
            sig: Default::default(),
            chain: vec![],
            http_body: IAS_SW.trim().to_owned(),
            evidence_message_bytes: vec![],
        };

        let data = VerificationReportData::try_from(&report).expect("Could not parse IAS result");
        assert!(verifier.verify(&data))
    }

    /// Ensure a SW_HARDENING_NEEDED result with the expected MRENCLAVE but
    /// unexpected advisory fails.
    #[test]
    fn mrenclave_sw_empty_fail() {
        let verifier = MrEnclaveVerifier {
            mr_enclave: MrEnclave::try_from(MR_ENCLAVE).expect("BUG: invalid test data"),
            advisories: Advisories::new(
                vec!["INTEL-SA-00334"],
                AdvisoryStatus::ConfigurationNeeded,
            ),
        };

        let report = VerificationReport {
            sig: Default::default(),
            chain: vec![],
            http_body: IAS_SW.trim().to_owned(),
            evidence_message_bytes: vec![],
        };

        let data = VerificationReportData::try_from(&report).expect("Could not parse IAS result");
        assert!(!verifier.verify(&data))
    }

    /// Ensure a SW_HARDENING_NEEDED result with the expected MRENCLAVE but
    /// unexpected advisory fails.
    #[test]
    fn mrenclave_multi_sw_empty_fail() {
        let verifier = MrEnclaveVerifier {
            mr_enclave: MrEnclave::try_from(MR_ENCLAVE).expect("BUG: invalid test data"),
            advisories: Advisories::new(
                vec!["INTEL-SA-00334"],
                AdvisoryStatus::ConfigurationNeeded,
            ),
        };

        let report = VerificationReport {
            sig: Default::default(),
            chain: vec![],
            http_body: IAS_SW_334_615.trim().to_owned(),
            evidence_message_bytes: vec![],
        };

        let data = VerificationReportData::try_from(&report).expect("Could not parse IAS result");
        assert!(!verifier.verify(&data))
    }

    /// Ensure a SW_HARDENING_NEEDED result with the expected MRENCLAVE but
    /// unexpected advisory fails.
    #[test]
    fn mrenclave_multi_sw_short_fail() {
        let verifier = MrEnclaveVerifier {
            mr_enclave: MrEnclave::try_from(MR_ENCLAVE).expect("BUG: invalid test data"),
            advisories: Advisories::new(vec!["INTEL-SA-00334"], AdvisoryStatus::SWHardeningNeeded),
        };

        let report = VerificationReport {
            sig: Default::default(),
            chain: vec![],
            http_body: IAS_SW_334_615.trim().to_owned(),
            evidence_message_bytes: vec![],
        };

        let data = VerificationReportData::try_from(&report).expect("Could not parse IAS result");
        assert!(!verifier.verify(&data))
    }

    /// Ensure a CONFIGURATION_AND_SW_HARDENING_NEEDED result with the expected
    /// MRENCLAVE and advisory passes when the advisory is given for both.
    #[test]
    fn mrenclave_config_sw_pass() {
        let verifier = MrEnclaveVerifier {
            mr_enclave: MrEnclave::try_from(MR_ENCLAVE).expect("BUG: invalid test data"),
            advisories: Advisories::new(
                &vec!["INTEL-SA-00239"],
                AdvisoryStatus::ConfigurationAndSWHardeningNeeded,
            ),
        };

        let report = VerificationReport {
            sig: Default::default(),
            chain: vec![],
            http_body: IAS_CONFIG_SW.trim().to_owned(),
            evidence_message_bytes: vec![],
        };

        let data = VerificationReportData::try_from(&report).expect("Could not parse IAS result");
        assert!(verifier.verify(&data))
    }

    /// Ensure a CONFIGURATION_AND_SW_HARDENING_NEEDED result with the expected
    /// MRENCLAVE and advisory passes when the advisory is given for both.
    #[test]
    fn mrenclave_multi_config_sw_pass() {
        let verifier = MrEnclaveVerifier {
            mr_enclave: MrEnclave::try_from(MR_ENCLAVE).expect("BUG: invalid test data"),
            advisories: Advisories::new(
                &vec!["INTEL-SA-00334", "INTEL-SA-00615"],
                AdvisoryStatus::ConfigurationAndSWHardeningNeeded,
            ),
        };

        let report = VerificationReport {
            sig: Default::default(),
            chain: vec![],
            http_body: IAS_CONFIG_SW_334_615.trim().to_owned(),
            evidence_message_bytes: vec![],
        };

        let data = VerificationReportData::try_from(&report).expect("Could not parse IAS result");
        assert!(verifier.verify(&data))
    }

    /// Ensure a CONFIGURATION_AND_SW_HARDENING_NEEDED result with the expected
    /// MRENCLAVE and config advisory passes.
    #[test]
    fn mrenclave_config_sw_pass_config() {
        let verifier = MrEnclaveVerifier {
            mr_enclave: MrEnclave::try_from(MR_ENCLAVE).expect("BUG: invalid test data"),
            advisories: Advisories::new(
                &vec!["INTEL-SA-00239", "INTEL-SA-00123"],
                AdvisoryStatus::ConfigurationAndSWHardeningNeeded,
            ),
        };

        let report = VerificationReport {
            sig: Default::default(),
            chain: vec![],
            http_body: IAS_CONFIG_SW.trim().to_owned(),
            evidence_message_bytes: vec![],
        };

        let data = VerificationReportData::try_from(&report).expect("Could not parse IAS result");
        assert!(verifier.verify(&data))
    }

    /// Ensure a CONFIGURATION_AND_SW_HARDENING_NEEDED result with the expected
    /// MRENCLAVE and sw-only advisory allow-listing fails.
    #[test]
    fn mrenclave_multi_config_sw_fail_no_config() {
        let verifier = MrEnclaveVerifier {
            mr_enclave: MrEnclave::try_from(MR_ENCLAVE).expect("BUG: invalid test data"),
            advisories: Advisories::new(
                &vec!["INTEL-SA-00334", "INTEL-SA-00615"],
                AdvisoryStatus::SWHardeningNeeded,
            ),
        };

        let report = VerificationReport {
            sig: Default::default(),
            chain: vec![],
            http_body: IAS_CONFIG_SW_334_615.trim().to_owned(),
            evidence_message_bytes: vec![],
        };

        let data = VerificationReportData::try_from(&report).expect("Could not parse IAS result");
        assert!(!verifier.verify(&data))
    }

    /// Ensure a CONFIGURATION_AND_SW_HARDENING_NEEDED result with the expected
    /// MRENCLAVE and sw-only advisory allow-listing fails.
    #[test]
    fn mrenclave_multi_config_sw_fail_no_sw() {
        let verifier = MrEnclaveVerifier {
            mr_enclave: MrEnclave::try_from(MR_ENCLAVE).expect("BUG: invalid test data"),
            advisories: Advisories::new(
                &vec!["INTEL-SA-00334", "INTEL-SA-00615"],
                AdvisoryStatus::ConfigurationNeeded,
            ),
        };

        let report = VerificationReport {
            sig: Default::default(),
            chain: vec![],
            http_body: IAS_CONFIG_SW_334_615.trim().to_owned(),
            evidence_message_bytes: vec![],
        };

        let data = VerificationReportData::try_from(&report).expect("Could not parse IAS result");
        assert!(!verifier.verify(&data))
    }

    /// Ensure a CONFIGURATION_AND_SW_HARDENING_NEEDED result with the expected
    /// MRENCLAVE and insufficient sw advisory allow-listing passes.
    #[test]
    fn mrenclave_multi_config_sw_fail_short_sw() {
        let verifier = MrEnclaveVerifier {
            mr_enclave: MrEnclave::try_from(MR_ENCLAVE).expect("BUG: invalid test data"),
            advisories: Advisories::new(
                &vec!["INTEL-SA-00334", "INTEL-SA-00615"],
                AdvisoryStatus::ConfigurationAndSWHardeningNeeded,
            ),
        };

        let report = VerificationReport {
            sig: Default::default(),
            chain: vec![],
            http_body: IAS_CONFIG_SW_334_615.trim().to_owned(),
            evidence_message_bytes: vec![],
        };

        let data = VerificationReportData::try_from(&report).expect("Could not parse IAS result");
        assert!(verifier.verify(&data))
    }

    /// Ensure a CONFIGURATION_AND_SW_HARDENING_NEEDED result with the expected
    /// MRENCLAVE and insufficient config advisory allow-listing passes.
    #[test]
    fn mrenclave_multi_config_sw_fail_short_config() {
        let verifier = MrEnclaveVerifier {
            mr_enclave: MrEnclave::try_from(MR_ENCLAVE).expect("BUG: invalid test data"),
            advisories: Advisories::new(
                &vec!["INTEL-SA-00334", "INTEL-SA-00615"],
                AdvisoryStatus::ConfigurationAndSWHardeningNeeded,
            ),
        };

        let report = VerificationReport {
            sig: Default::default(),
            chain: vec![],
            http_body: IAS_CONFIG_SW_334_615.trim().to_owned(),
            evidence_message_bytes: vec![],
        };

        let data = VerificationReportData::try_from(&report).expect("Could not parse IAS result");
        assert!(verifier.verify(&data))
    }
    /// Ensure a CONFIGURATION_AND_SW_HARDENING_NEEDED result with the expected
    /// MRENCLAVE and hardening advisory succeeds.
    #[test]
    fn mrenclave_config_sw_fail_sw() {
        let verifier = MrEnclaveVerifier {
            mr_enclave: MrEnclave::try_from(MR_ENCLAVE).expect("BUG: invalid test data"),
            advisories: Advisories::new(
                &vec!["INTEL-SA-00123", "INTEL-SA-00239"],
                AdvisoryStatus::ConfigurationAndSWHardeningNeeded,
            ),
        };

        let report = VerificationReport {
            sig: Default::default(),
            chain: vec![],
            http_body: IAS_CONFIG_SW.trim().to_owned(),
            evidence_message_bytes: vec![],
        };

        let data = VerificationReportData::try_from(&report).expect("Could not parse IAS result");
        assert!(verifier.verify(&data))
    }

    /// Ensure a CONFIGURATION_AND_SW_HARDENING_NEEDED result with the expected
    /// MRENCLAVE but an unexpected advisory fails.
    #[test]
    fn mrenclave_config_sw_fail_neither() {
        let verifier = MrEnclaveVerifier {
            mr_enclave: MrEnclave::try_from(MR_ENCLAVE).expect("BUG: invalid test data"),
            advisories: Advisories::new(
                &vec!["INTEL-SA-00123"],
                AdvisoryStatus::ConfigurationAndSWHardeningNeeded,
            ),
        };

        let report = VerificationReport {
            sig: Default::default(),
            chain: vec![],
            http_body: IAS_CONFIG_SW.trim().to_owned(),
            evidence_message_bytes: vec![],
        };

        let data = VerificationReportData::try_from(&report).expect("Could not parse IAS result");
        assert!(!verifier.verify(&data))
    }

    /// Ensure a CONFIGURATION_AND_SW_HARDENING_NEEDED result with the expected
    /// MRENCLAVE but an insufficient sw and config advisory allow-listing
    /// fails.
    #[test]
    fn mrenclave_multi_config_sw_fail_short() {
        let verifier = MrEnclaveVerifier {
            mr_enclave: MrEnclave::try_from(MR_ENCLAVE).expect("BUG: invalid test data"),
            advisories: Advisories::new(
                &vec!["INTEL-SA-00334"],
                AdvisoryStatus::ConfigurationAndSWHardeningNeeded,
            ),
        };

        let report = VerificationReport {
            sig: Default::default(),
            chain: vec![],
            http_body: IAS_CONFIG_SW_334_615.trim().to_owned(),
            evidence_message_bytes: vec![],
        };

        let data = VerificationReportData::try_from(&report).expect("Could not parse IAS result");
        assert!(!verifier.verify(&data))
    }

    /// Ensure an OK result with the expected MRSIGNER, product, and minimum
    /// version passes.
    #[test]
    fn mrsigner_ok() {
        let verifier = MrSignerVerifier {
            mr_signer: MrSigner::try_from(MR_SIGNER).expect("BUG: invalid test data"),
            product_id: 0.into(),
            minimum_svn: 0.into(),
            advisories: Advisories::default(),
        };

        let report = VerificationReport {
            sig: Default::default(),
            chain: vec![],
            http_body: IAS_OK.trim().to_owned(),
            evidence_message_bytes: vec![],
        };

        let data = VerificationReportData::try_from(&report).expect("Could not parse IAS result");
        assert!(verifier.verify(&data))
    }

    /// Ensure an OK result with the expected MRSIGNER, product, and minimum
    /// version passes.
    #[test]
    fn mrsigner_fail_notok() {
        let verifier = MrSignerVerifier {
            mr_signer: MrSigner::try_from(MR_SIGNER).expect("BUG: invalid test data"),
            product_id: 0.into(),
            minimum_svn: 0.into(),
            advisories: Advisories::default(),
        };

        let report = VerificationReport {
            sig: Default::default(),
            chain: vec![],
            http_body: IAS_CONFIG.trim().to_owned(),
            evidence_message_bytes: vec![],
        };

        let data = VerificationReportData::try_from(&report).expect("Could not parse IAS result");
        assert!(!verifier.verify(&data))
    }

    /// Ensure an OK result with an unexpected MRSIGNER fails.
    #[test]
    fn mrsigner_fail_mrsigner() {
        let verifier = MrSignerVerifier {
            mr_signer: MrSigner::try_from(MR_ENCLAVE).expect("BUG: invalid test data"),
            product_id: 0.into(),
            minimum_svn: 0.into(),
            advisories: Advisories::default(),
        };

        let report = VerificationReport {
            sig: Default::default(),
            chain: vec![],
            http_body: IAS_OK.trim().to_owned(),
            evidence_message_bytes: vec![],
        };

        let data = VerificationReportData::try_from(&report).expect("Could not parse IAS result");
        assert!(!verifier.verify(&data))
    }

    /// Ensure an OK result with an unexpected product ID fails
    #[test]
    fn mrsigner_fail_product_id() {
        let verifier = MrSignerVerifier {
            mr_signer: MrSigner::try_from(MR_SIGNER).expect("BUG: invalid test data"),
            product_id: 1.into(),
            minimum_svn: 0.into(),
            advisories: Advisories::default(),
        };

        let report = VerificationReport {
            sig: Default::default(),
            chain: vec![],
            http_body: IAS_OK.trim().to_owned(),
            evidence_message_bytes: vec![],
        };

        let data = VerificationReportData::try_from(&report).expect("Could not parse IAS result");
        assert!(!verifier.verify(&data))
    }

    /// Ensure an OK result with a greater version fails
    #[test]
    fn mrsigner_fail_version() {
        let verifier = MrSignerVerifier {
            mr_signer: MrSigner::try_from(MR_SIGNER).expect("BUG: invalid test data"),
            product_id: 0.into(),
            minimum_svn: 1.into(),
            advisories: Advisories::default(),
        };

        let report = VerificationReport {
            sig: Default::default(),
            chain: vec![],
            http_body: IAS_OK.trim().to_owned(),
            evidence_message_bytes: vec![],
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
            mr_signer: MrSigner::try_from(MR_SIGNER).expect("BUG: invalid test data"),
            product_id: 0.into(),
            minimum_svn: 0.into(),
            advisories: Advisories::new(
                &vec!["INTEL-SA-00239"],
                AdvisoryStatus::ConfigurationNeeded,
            ),
        };

        let report = VerificationReport {
            sig: Default::default(),
            chain: vec![],
            http_body: IAS_CONFIG.trim().to_owned(),
            evidence_message_bytes: vec![],
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
            mr_signer: MrSigner::try_from(MR_SIGNER).expect("BUG: invalid test data"),
            product_id: 0.into(),
            minimum_svn: 0.into(),
            advisories: Advisories::new(
                &vec!["INTEL-SA-00239".to_owned()],
                AdvisoryStatus::SWHardeningNeeded,
            ),
        };

        let report = VerificationReport {
            sig: Default::default(),
            chain: vec![],
            http_body: IAS_SW.trim().to_owned(),
            evidence_message_bytes: vec![],
        };

        let data = VerificationReportData::try_from(&report).expect("Could not parse IAS result");
        assert!(verifier.verify(&data))
    }

    /// Ensure a SW_HARDENING_NEEDED result with the expected MRSIGNER,
    /// product, and minimum version passes, as long as all advisories are
    /// accounted for
    #[test]
    fn mrsigner_pass_multi_sw() {
        let verifier = MrSignerVerifier {
            mr_signer: MrSigner::try_from(MR_SIGNER).expect("BUG: invalid test data"),
            product_id: 0.into(),
            minimum_svn: 0.into(),
            advisories: Advisories::new(
                &vec!["INTEL-SA-00334".to_owned(), "INTEL-SA-00615".to_owned()],
                AdvisoryStatus::SWHardeningNeeded,
            ),
        };

        let report = VerificationReport {
            sig: Default::default(),
            chain: vec![],
            http_body: IAS_SW_334_615.trim().to_owned(),
            evidence_message_bytes: vec![],
        };

        let data = VerificationReportData::try_from(&report).expect("Could not parse IAS result");
        assert!(verifier.verify(&data))
    }

    /// Ensure a CONFIGURATION_AND_SW_HARDENING_NEEDED result with the expected
    /// MRSIGNER, product, and minimum version succeds if all advisories are
    /// accounted for as both config and sw.
    #[test]
    fn mrsigner_pass_config_sw() {
        let verifier = MrSignerVerifier {
            mr_signer: MrSigner::try_from(MR_SIGNER).expect("BUG: invalid test data"),
            product_id: 0.into(),
            minimum_svn: 0.into(),
            advisories: Advisories::new(
                &vec!["INTEL-SA-00239".to_owned()],
                AdvisoryStatus::ConfigurationAndSWHardeningNeeded,
            ),
        };

        let report = VerificationReport {
            sig: Default::default(),
            chain: vec![],
            http_body: IAS_CONFIG_SW.trim().to_owned(),
            evidence_message_bytes: vec![],
        };

        let data = VerificationReportData::try_from(&report).expect("Could not parse IAS result");
        assert!(verifier.verify(&data))
    }

    /// Ensure a CONFIGURATION_AND_SW_HARDENING_NEEDED result with the expected
    /// MRSIGNER, product, and minimum version fails if the advisory isn't
    /// accounted for as both config and sw.
    #[test]
    fn mrsigner_fail_config_sw_no_sw() {
        let verifier = MrSignerVerifier {
            mr_signer: MrSigner::try_from(MR_SIGNER).expect("BUG: invalid test data"),
            product_id: 0.into(),
            minimum_svn: 0.into(),
            advisories: Advisories::new(
                &vec!["INTEL-SA-00239".to_owned()],
                AdvisoryStatus::ConfigurationNeeded,
            ),
        };

        let report = VerificationReport {
            sig: Default::default(),
            chain: vec![],
            http_body: IAS_CONFIG_SW.trim().to_owned(),
            evidence_message_bytes: vec![],
        };

        let data = VerificationReportData::try_from(&report).expect("Could not parse IAS result");
        assert!(!verifier.verify(&data))
    }

    /// Ensure a CONFIGURATION_AND_SW_HARDENING_NEEDED result with the expected
    /// MRSIGNER, product, and minimum version fails, if the advisory isn't
    /// accounted for in both config and sw.
    #[test]
    fn mrsigner_fail_config_sw_no_config() {
        let verifier = MrSignerVerifier {
            mr_signer: MrSigner::try_from(MR_SIGNER).expect("BUG: invalid test data"),
            product_id: 0.into(),
            minimum_svn: 0.into(),
            advisories: Advisories::new(
                &vec!["INTEL-SA-00239".to_owned()],
                AdvisoryStatus::SWHardeningNeeded,
            ),
        };

        let report = VerificationReport {
            sig: Default::default(),
            chain: vec![],
            http_body: IAS_CONFIG_SW.trim().to_owned(),
            evidence_message_bytes: vec![],
        };

        let data = VerificationReportData::try_from(&report).expect("Could not parse IAS result");
        assert!(!verifier.verify(&data))
    }

    /// Ensure a CONFIGURATION_AND_SW_HARDENING_NEEDED result with the expected
    /// MRSIGNER, product, and minimum version fails if the advisory isn't
    /// accounted for as both config and sw.
    #[test]
    fn mrsigner_fail_multi_config_sw_no_sw() {
        let verifier = MrSignerVerifier {
            mr_signer: MrSigner::try_from(MR_SIGNER).expect("BUG: invalid test data"),
            product_id: 0.into(),
            minimum_svn: 0.into(),
            advisories: Advisories::new(
                &vec!["INTEL-SA-00334".to_owned(), "INTEL-SA-00615".to_owned()],
                AdvisoryStatus::ConfigurationNeeded,
            ),
        };

        let report = VerificationReport {
            sig: Default::default(),
            chain: vec![],
            http_body: IAS_CONFIG_SW_334_615.trim().to_owned(),
            evidence_message_bytes: vec![],
        };

        let data = VerificationReportData::try_from(&report).expect("Could not parse IAS result");
        assert!(!verifier.verify(&data))
    }

    /// Ensure a CONFIGURATION_AND_SW_HARDENING_NEEDED result with the expected
    /// MRSIGNER, product, and minimum version fails if the advisory isn't
    /// accounted for in both config and sw.
    #[test]
    fn mrsigner_fail_multi_config_sw_short_sw() {
        let verifier = MrSignerVerifier {
            mr_signer: MrSigner::try_from(MR_SIGNER).expect("BUG: invalid test data"),
            product_id: 0.into(),
            minimum_svn: 0.into(),
            advisories: Advisories::new(
                &vec!["INTEL-SA-00615".to_owned()],
                AdvisoryStatus::ConfigurationNeeded,
            ),
        };

        let report = VerificationReport {
            sig: Default::default(),
            chain: vec![],
            http_body: IAS_CONFIG_SW.trim().to_owned(),
            evidence_message_bytes: vec![],
        };

        let data = VerificationReportData::try_from(&report).expect("Could not parse IAS result");
        assert!(!verifier.verify(&data))
    }

    /// Ensure a CONFIGURATION_AND_SW_HARDENING_NEEDED result with the expected
    /// MRSIGNER, product, and minimum version fails, if the advisory isn't
    /// accounted for in both config and sw.
    #[test]
    fn mrsigner_fail_multi_config_sw_no_config() {
        let verifier = MrSignerVerifier {
            mr_signer: MrSigner::try_from(MR_SIGNER).expect("BUG: invalid test data"),
            product_id: 0.into(),
            minimum_svn: 0.into(),
            advisories: Advisories::new(
                &vec!["INTEL-SA-00334".to_owned(), "INTEL-SA-00615".to_owned()],
                AdvisoryStatus::SWHardeningNeeded,
            ),
        };

        let report = VerificationReport {
            sig: Default::default(),
            chain: vec![],
            http_body: IAS_CONFIG_SW_334_615.trim().to_owned(),
            evidence_message_bytes: vec![],
        };

        let data = VerificationReportData::try_from(&report).expect("Could not parse IAS result");
        assert!(!verifier.verify(&data))
    }

    /// Ensure a CONFIGURATION_AND_SW_HARDENING_NEEDED result with the expected
    /// MRSIGNER, product, and minimum version passes, even if the advisory
    /// isn't accounted for in BOTH config and sw.
    #[test]
    fn mrsigner_pass_multi_config_sw_short_config() {
        let verifier = MrSignerVerifier {
            mr_signer: MrSigner::try_from(MR_SIGNER).expect("BUG: invalid test data"),
            product_id: 0.into(),
            minimum_svn: 0.into(),
            advisories: Advisories::new(
                &vec!["INTEL-SA-00334", "INTEL-SA-00615"],
                AdvisoryStatus::ConfigurationAndSWHardeningNeeded,
            ),
        };

        let report = VerificationReport {
            sig: Default::default(),
            chain: vec![],
            http_body: IAS_CONFIG_SW_334_615.trim().to_owned(),
            evidence_message_bytes: vec![],
        };

        let data = VerificationReportData::try_from(&report).expect("Could not parse IAS result");
        assert!(verifier.verify(&data))
    }

    /// Ensure a CONFIGURATION_AND_SW_HARDENING_NEEDED result with the expected
    /// MRSIGNER, and minimum version, but the wrong product fails, even if
    /// the advisory is accounted for.
    #[test]
    fn mrsigner_fail_sw_config_sw_for_product() {
        let verifier = MrSignerVerifier {
            mr_signer: MrSigner::try_from(MR_SIGNER).expect("BUG: invalid test data"),
            product_id: 1.into(),
            minimum_svn: 0.into(),
            advisories: Advisories::new(
                &vec!["INTEL-SA-00239".to_owned()],
                AdvisoryStatus::ConfigurationAndSWHardeningNeeded,
            ),
        };

        let report = VerificationReport {
            sig: Default::default(),
            chain: vec![],
            http_body: IAS_CONFIG_SW.trim().to_owned(),
            evidence_message_bytes: vec![],
        };

        let data = VerificationReportData::try_from(&report).expect("Could not parse IAS result");
        assert!(!verifier.verify(&data))
    }

    /// Ensure a CONFIGURATION_AND_SW_HARDENING_NEEDED result with the expected
    /// MRSIGNER, and minimum version, but the wrong product fails, even if
    /// all advisories are accounted for.
    #[test]
    fn mrsigner_fail_multi_sw_config_sw_for_product() {
        let verifier = MrSignerVerifier {
            mr_signer: MrSigner::try_from(MR_SIGNER).expect("BUG: invalid test data"),
            product_id: 1.into(),
            minimum_svn: 0.into(),
            advisories: Advisories::new(
                &vec!["INTEL-SA-00334".to_owned(), "INTEL-SA-00615".to_owned()],
                AdvisoryStatus::ConfigurationAndSWHardeningNeeded,
            ),
        };

        let report = VerificationReport {
            sig: Default::default(),
            chain: vec![],
            http_body: IAS_CONFIG_SW_334_615.trim().to_owned(),
            evidence_message_bytes: vec![],
        };

        let data = VerificationReportData::try_from(&report).expect("Could not parse IAS result");
        assert!(!verifier.verify(&data))
    }

    /// Ensure a CONFIGURATION_AND_SW_HARDENING_NEEDED result with the expected
    /// MRSIGNER and product, but an earlier version, fails, even if all
    /// advisories are accounted for.
    #[test]
    fn mrsigner_fail_config_sw_for_version() {
        let verifier = MrSignerVerifier {
            mr_signer: MrSigner::try_from(MR_SIGNER).expect("BUG: invalid test data"),
            product_id: 0.into(),
            minimum_svn: 1.into(),
            advisories: Advisories::new(
                &vec!["INTEL-SA-00239".to_owned()],
                AdvisoryStatus::ConfigurationAndSWHardeningNeeded,
            ),
        };

        let report = VerificationReport {
            sig: Default::default(),
            chain: vec![],
            http_body: IAS_CONFIG_SW.trim().to_owned(),
            evidence_message_bytes: vec![],
        };

        let data = VerificationReportData::try_from(&report).expect("Could not parse IAS result");
        assert!(!verifier.verify(&data))
    }

    /// Ensure a CONFIGURATION_AND_SW_HARDENING_NEEDED result with the expected
    /// MRSIGNER and product, but an earlier version, fails, even if the
    /// advisory is accounted for.
    #[test]
    fn mrsigner_fail_multi_config_sw_for_version() {
        let verifier = MrSignerVerifier {
            mr_signer: MrSigner::try_from(MR_SIGNER).expect("BUG: invalid test data"),
            product_id: 0.into(),
            minimum_svn: 1.into(),
            advisories: Advisories::new(
                &vec!["INTEL-SA-00334".to_owned(), "INTEL-SA-00615".to_owned()],
                AdvisoryStatus::ConfigurationAndSWHardeningNeeded,
            ),
        };

        let report = VerificationReport {
            sig: Default::default(),
            chain: vec![],
            http_body: IAS_CONFIG_SW_334_615.trim().to_owned(),
            evidence_message_bytes: vec![],
        };

        let data = VerificationReportData::try_from(&report).expect("Could not parse IAS result");
        assert!(!verifier.verify(&data))
    }

    #[test]
    fn allow_config_advisories_mr_enclave_verifier() {
        let identity = TrustedIdentity::from(TrustedMrEnclaveIdentity::new(
            MrEnclave::from(MR_ENCLAVE),
            [] as [&str; 0],
            [] as [&str; 0],
        ));
        let mut verifier = Kind::from(&identity);
        verifier.set_advisories(Advisories::new(
            ["one", "two", "three"],
            AdvisoryStatus::ConfigurationNeeded,
        ));

        let Kind::Enclave(mr_enclave_verifier) = verifier
            else {
                panic!("Should be a mr enclave verifier");
            };
        assert_eq!(
            mr_enclave_verifier.advisories,
            Advisories::new(["one", "two", "three"], AdvisoryStatus::ConfigurationNeeded)
        );
    }

    #[test]
    fn allow_hardening_advisories_mr_enclave_verifier() {
        let identity = TrustedIdentity::from(TrustedMrEnclaveIdentity::new(
            MrEnclave::from(MR_ENCLAVE),
            [] as [&str; 0],
            [] as [&str; 0],
        ));
        let mut verifier = Kind::from(&identity);
        verifier.set_advisories(Advisories::new(
            ["for", "four", "fore"],
            AdvisoryStatus::SWHardeningNeeded,
        ));

        let Kind::Enclave(mr_enclave_verifier) = verifier
        else {
            panic!("Should be a mr enclave verifier");
        };
        assert_eq!(
            mr_enclave_verifier.advisories,
            Advisories::new(["for", "four", "fore"], AdvisoryStatus::SWHardeningNeeded)
        );
    }

    #[test]
    fn allow_config_advisories_mr_signer_verifier() {
        let identity = TrustedIdentity::from(TrustedMrSignerIdentity::new(
            MrSigner::from(MR_SIGNER),
            1.into(),
            2.into(),
            [] as [&str; 0],
            [] as [&str; 0],
        ));
        let mut verifier = Kind::from(&identity);
        verifier.set_advisories(Advisories::new(
            ["who", "what", "when"],
            AdvisoryStatus::ConfigurationNeeded,
        ));

        let Kind::Signer(mr_signer_verifier) = verifier
            else {
                panic!("Should be a mr signer verifier");
            };
        assert_eq!(
            mr_signer_verifier.advisories,
            Advisories::new(["who", "what", "when"], AdvisoryStatus::ConfigurationNeeded)
        );
    }

    #[test]
    fn allow_hardening_advisories_mr_signer_verifier() {
        let identity = TrustedIdentity::from(TrustedMrSignerIdentity::new(
            MrSigner::from(MR_SIGNER),
            3.into(),
            4.into(),
            [] as [&str; 0],
            [] as [&str; 0],
        ));
        let mut verifier = Kind::from(&identity);
        verifier.set_advisories(Advisories::new(
            ["past", "present", "future"],
            AdvisoryStatus::SWHardeningNeeded,
        ));

        let Kind::Signer(mr_signer_verifier) = verifier
            else {
                panic!("Should be a mr signer verifier");
            };
        assert_eq!(
            mr_signer_verifier.advisories,
            Advisories::new(
                ["past", "present", "future"],
                AdvisoryStatus::SWHardeningNeeded
            )
        );
    }
    #[test]
    fn mr_signer_verifier_from_mr_signer_identity() {
        let mr_signer_identity = TrustedMrSignerIdentity::new(
            MrSigner::from(MR_SIGNER),
            1.into(),
            2.into(),
            ["config_1", "config_2", "config_3"],
            ["hardening_1", "hardening_2", "hardening_3"],
        );

        let verifier = MrSignerVerifier::from(&mr_signer_identity);
        assert_eq!(verifier.mr_signer, MrSigner::from(MR_SIGNER));
        assert_eq!(verifier.product_id, 1.into());
        assert_eq!(verifier.minimum_svn, 2.into());
        assert_eq!(
            verifier.advisories,
            Advisories::new(
                [
                    "config_1",
                    "config_2",
                    "config_3",
                    "hardening_1",
                    "hardening_2",
                    "hardening_3"
                ],
                AdvisoryStatus::ConfigurationAndSWHardeningNeeded,
            )
        );
    }

    #[test]
    fn mr_enclave_verifier_from_mr_enclave_identity() {
        let mr_enclave_identity = TrustedMrEnclaveIdentity::new(
            MrEnclave::from(MR_ENCLAVE),
            ["e_config_1", "e_config_2", "e_config_3"],
            ["e_hardening_1", "e_hardening_2", "e_hardening_3"],
        );

        let verifier = MrEnclaveVerifier::from(&mr_enclave_identity);
        assert_eq!(verifier.mr_enclave, MrEnclave::from(MR_ENCLAVE));
        assert_eq!(
            verifier.advisories,
            Advisories::new(
                [
                    "e_config_1",
                    "e_config_2",
                    "e_config_3",
                    "e_hardening_1",
                    "e_hardening_2",
                    "e_hardening_3"
                ],
                AdvisoryStatus::ConfigurationAndSWHardeningNeeded,
            )
        );
    }
}
