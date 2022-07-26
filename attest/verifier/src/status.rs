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
use alloc::{borrow::ToOwned, string::String, vec::Vec};
use mc_attest_core::{
    IasQuoteError, IasQuoteResult, MrEnclave, MrSigner, ProductId, SecurityVersion,
    VerificationReportData,
};
use mc_sgx_css::Signature;
use serde::{Deserialize, Serialize};

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
            .all(|id| config_ids.contains(id) && sw_ids.contains(id)),
        Err(_) => false,
    }
}

/// An enumeration of status verifier types
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub enum Kind {
    /// A measurement-and-status verifier which will check for a MRENCLAVE
    /// value, and allow select non-OK quote-status results from IAS.
    Enclave(MrEnclaveVerifier),
    /// A measurement-and-status verifier which will check for a
    /// MRSIGNER/product-id/enclave-version tuple, allow select non-OK
    /// quote-status results from IAS.
    Signer(MrSignerVerifier),
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
        Self::new(MrEnclave::from(*(src.mrenclave())))
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

    /// Assume an enclave with the specified signer, ID, and version does not
    /// need BIOS configuration changes to address the provided advisory ID.
    ///
    /// This method should only be used when advised by an enclave author.
    pub fn allow_config_advisory(&mut self, id: &str) -> &mut Self {
        self.config_ids.push(id.to_owned());
        self
    }

    /// Assume an enclave with the specified signer, ID, and version does not
    /// need BIOS configuration changes to address the provided advisory
    /// IDs.
    ///
    /// This method should only be used when advised by an enclave author.
    pub fn allow_config_advisories(&mut self, ids: &[&str]) -> &mut Self {
        for id in ids {
            self.config_ids.push((*id).to_owned());
        }
        self
    }

    /// Assume an enclave with the specified signer, ID, and version has the
    /// appropriate software/build-time hardening for the given advisory ID.
    ///
    /// This method should only be used when advised by an enclave author.
    pub fn allow_hardening_advisory(&mut self, id: &str) -> &mut Self {
        self.sw_ids.push(id.to_owned());
        self
    }

    /// Assume an enclave with the specified signer, ID, and version has the
    /// appropriate software/build-time hardening for the given advisory
    /// IDs.
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

#[cfg(test)]
mod test {
    use super::*;
    use alloc::vec;
    use mc_attest_core::VerificationReport;
    use mc_sgx_types::sgx_measurement_t;

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

    /// Ensure a SW_HARDENING_NEEDED result with the expected MRENCLAVE and
    /// advisories passes.
    #[test]
    fn mrenclave_multi_sw_pass() {
        let verifier = MrEnclaveVerifier {
            mr_enclave: MrEnclave::from(&MR_ENCLAVE),
            config_ids: vec![],
            sw_ids: vec!["INTEL-SA-00334".to_owned(), "INTEL-SA-00615".to_owned()],
        };

        let report = VerificationReport {
            sig: Default::default(),
            chain: vec![],
            http_body: IAS_SW_334_615.trim().to_owned(),
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

    /// Ensure a SW_HARDENING_NEEDED result with the expected MRENCLAVE but
    /// unexpected advisory fails.
    #[test]
    fn mrenclave_sw_empty_fail() {
        let verifier = MrEnclaveVerifier {
            mr_enclave: MrEnclave::from(&MR_ENCLAVE),
            config_ids: vec!["INTEL-SA-00334".to_owned()],
            sw_ids: vec![],
        };

        let report = VerificationReport {
            sig: Default::default(),
            chain: vec![],
            http_body: IAS_SW.trim().to_owned(),
        };

        let data = VerificationReportData::try_from(&report).expect("Could not parse IAS result");
        assert!(!verifier.verify(&data))
    }

    /// Ensure a SW_HARDENING_NEEDED result with the expected MRENCLAVE but
    /// unexpected advisory fails.
    #[test]
    fn mrenclave_multi_sw_empty_fail() {
        let verifier = MrEnclaveVerifier {
            mr_enclave: MrEnclave::from(&MR_ENCLAVE),
            config_ids: vec!["INTEL-SA-00334".to_owned()],
            sw_ids: vec![],
        };

        let report = VerificationReport {
            sig: Default::default(),
            chain: vec![],
            http_body: IAS_SW_334_615.trim().to_owned(),
        };

        let data = VerificationReportData::try_from(&report).expect("Could not parse IAS result");
        assert!(!verifier.verify(&data))
    }

    /// Ensure a SW_HARDENING_NEEDED result with the expected MRENCLAVE but
    /// unexpected advisory fails.
    #[test]
    fn mrenclave_multi_sw_short_fail() {
        let verifier = MrEnclaveVerifier {
            mr_enclave: MrEnclave::from(&MR_ENCLAVE),
            config_ids: vec![],
            sw_ids: vec!["INTEL-SA-00334".to_owned()],
        };

        let report = VerificationReport {
            sig: Default::default(),
            chain: vec![],
            http_body: IAS_SW_334_615.trim().to_owned(),
        };

        let data = VerificationReportData::try_from(&report).expect("Could not parse IAS result");
        assert!(!verifier.verify(&data))
    }

    /// Ensure a CONFIGURATION_AND_SW_HARDENING_NEEDED result with the expected
    /// MRENCLAVE and advisory passes when the advisory is given for both.
    #[test]
    fn mrenclave_config_sw_pass() {
        let verifier = MrEnclaveVerifier {
            mr_enclave: MrEnclave::from(&MR_ENCLAVE),
            config_ids: vec!["INTEL-SA-00239".to_owned()],
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
    /// MRENCLAVE and advisory passes when the advisory is given for both.
    #[test]
    fn mrenclave_multi_config_sw_pass() {
        let verifier = MrEnclaveVerifier {
            mr_enclave: MrEnclave::from(&MR_ENCLAVE),
            config_ids: vec!["INTEL-SA-00334".to_owned(), "INTEL-SA-00615".to_owned()],
            sw_ids: vec!["INTEL-SA-00334".to_owned(), "INTEL-SA-00615".to_owned()],
        };

        let report = VerificationReport {
            sig: Default::default(),
            chain: vec![],
            http_body: IAS_CONFIG_SW_334_615.trim().to_owned(),
        };

        let data = VerificationReportData::try_from(&report).expect("Could not parse IAS result");
        assert!(verifier.verify(&data))
    }

    /// Ensure a CONFIGURATION_AND_SW_HARDENING_NEEDED result with the expected
    /// MRENCLAVE and config advisory fails.
    #[test]
    fn mrenclave_config_sw_fail_config() {
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
        assert!(!verifier.verify(&data))
    }

    /// Ensure a CONFIGURATION_AND_SW_HARDENING_NEEDED result with the expected
    /// MRENCLAVE and sw-only advisory allow-listing fails.
    #[test]
    fn mrenclave_multi_config_sw_fail_no_config() {
        let verifier = MrEnclaveVerifier {
            mr_enclave: MrEnclave::from(&MR_ENCLAVE),
            config_ids: vec![],
            sw_ids: vec!["INTEL-SA-00334".to_owned(), "INTEL-SA-00615".to_owned()],
        };

        let report = VerificationReport {
            sig: Default::default(),
            chain: vec![],
            http_body: IAS_CONFIG_SW_334_615.trim().to_owned(),
        };

        let data = VerificationReportData::try_from(&report).expect("Could not parse IAS result");
        assert!(!verifier.verify(&data))
    }

    /// Ensure a CONFIGURATION_AND_SW_HARDENING_NEEDED result with the expected
    /// MRENCLAVE and sw-only advisory allow-listing fails.
    #[test]
    fn mrenclave_multi_config_sw_fail_no_sw() {
        let verifier = MrEnclaveVerifier {
            mr_enclave: MrEnclave::from(&MR_ENCLAVE),
            config_ids: vec!["INTEL-SA-00334".to_owned(), "INTEL-SA-00615".to_owned()],
            sw_ids: vec![],
        };

        let report = VerificationReport {
            sig: Default::default(),
            chain: vec![],
            http_body: IAS_CONFIG_SW_334_615.trim().to_owned(),
        };

        let data = VerificationReportData::try_from(&report).expect("Could not parse IAS result");
        assert!(!verifier.verify(&data))
    }

    /// Ensure a CONFIGURATION_AND_SW_HARDENING_NEEDED result with the expected
    /// MRENCLAVE and insufficient sw advisory allow-listing fails.
    #[test]
    fn mrenclave_multi_config_sw_fail_short_sw() {
        let verifier = MrEnclaveVerifier {
            mr_enclave: MrEnclave::from(&MR_ENCLAVE),
            config_ids: vec!["INTEL-SA-00334".to_owned(), "INTEL-SA-00615".to_owned()],
            sw_ids: vec!["INTEL-SA-00334".to_owned()],
        };

        let report = VerificationReport {
            sig: Default::default(),
            chain: vec![],
            http_body: IAS_CONFIG_SW_334_615.trim().to_owned(),
        };

        let data = VerificationReportData::try_from(&report).expect("Could not parse IAS result");
        assert!(!verifier.verify(&data))
    }

    /// Ensure a CONFIGURATION_AND_SW_HARDENING_NEEDED result with the expected
    /// MRENCLAVE and insufficient config advisory allow-listing fails.
    #[test]
    fn mrenclave_multi_config_sw_fail_short_config() {
        let verifier = MrEnclaveVerifier {
            mr_enclave: MrEnclave::from(&MR_ENCLAVE),
            config_ids: vec!["INTEL-SA-00615".to_owned()],
            sw_ids: vec!["INTEL-SA-00334".to_owned(), "INTEL-SA-00615".to_owned()],
        };

        let report = VerificationReport {
            sig: Default::default(),
            chain: vec![],
            http_body: IAS_CONFIG_SW_334_615.trim().to_owned(),
        };

        let data = VerificationReportData::try_from(&report).expect("Could not parse IAS result");
        assert!(!verifier.verify(&data))
    }
    /// Ensure a CONFIGURATION_AND_SW_HARDENING_NEEDED result with the expected
    /// MRENCLAVE and hardening advisory fails.
    #[test]
    fn mrenclave_config_sw_fail_sw() {
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
        assert!(!verifier.verify(&data))
    }

    /// Ensure a CONFIGURATION_AND_SW_HARDENING_NEEDED result with the expected
    /// MRENCLAVE but an unexpected advisory fails.
    #[test]
    fn mrenclave_config_sw_fail_neither() {
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

    /// Ensure a CONFIGURATION_AND_SW_HARDENING_NEEDED result with the expected
    /// MRENCLAVE but an insufficient sw and config advisory allow-listing 
    /// fails.
    #[test]
    fn mrenclave_multi_config_sw_fail_short() {
        let verifier = MrEnclaveVerifier {
            mr_enclave: MrEnclave::from(&MR_ENCLAVE),
            config_ids: vec!["INTEL-SA-00334".to_owned()],
            sw_ids: vec!["INTEL-SA-00334".to_owned()],
        };

        let report = VerificationReport {
            sig: Default::default(),
            chain: vec![],
            http_body: IAS_CONFIG_SW_334_615.trim().to_owned(),
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

    /// Ensure a SW_HARDENING_NEEDED result with the expected MRSIGNER,
    /// product, and minimum version passes, as long as all advisories are
    /// accounted for
    #[test]
    fn mrsigner_pass_multi_sw() {
        let verifier = MrSignerVerifier {
            mr_signer: MrSigner::from(&MR_SIGNER),
            product_id: 0,
            minimum_svn: 0,
            config_ids: vec![],
            sw_ids: vec!["INTEL-SA-00334".to_owned(), "INTEL-SA-00615".to_owned()],
        };

        let report = VerificationReport {
            sig: Default::default(),
            chain: vec![],
            http_body: IAS_SW_334_615.trim().to_owned(),
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
            mr_signer: MrSigner::from(&MR_SIGNER),
            product_id: 0,
            minimum_svn: 0,
            config_ids: vec!["INTEL-SA-00239".to_owned()],
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
    /// MRSIGNER, product, and minimum version fails if the advisory isn't
    /// accounted for as both config and sw.
    #[test]
    fn mrsigner_fail_config_sw_no_sw() {
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
            http_body: IAS_CONFIG_SW.trim().to_owned(),
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
        assert!(!verifier.verify(&data))
    }

    /// Ensure a CONFIGURATION_AND_SW_HARDENING_NEEDED result with the expected
    /// MRSIGNER, product, and minimum version fails if the advisory isn't
    /// accounted for as both config and sw.
    #[test]
    fn mrsigner_fail_multi_config_sw_no_sw() {
        let verifier = MrSignerVerifier {
            mr_signer: MrSigner::from(&MR_SIGNER),
            product_id: 0,
            minimum_svn: 0,
            config_ids: vec!["INTEL-SA-00334".to_owned(), "INTEL-SA-00615".to_owned()],
            sw_ids: vec![],
        };

        let report = VerificationReport {
            sig: Default::default(),
            chain: vec![],
            http_body: IAS_CONFIG_SW_334_615.trim().to_owned(),
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
            mr_signer: MrSigner::from(&MR_SIGNER),
            product_id: 0,
            minimum_svn: 0,
            config_ids: vec!["INTEL-SA-00615".to_owned()],
            sw_ids: vec![],
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
    /// MRSIGNER, product, and minimum version fails, if the advisory isn't
    /// accounted for in both config and sw.
    #[test]
    fn mrsigner_fail_multi_config_sw_no_config() {
        let verifier = MrSignerVerifier {
            mr_signer: MrSigner::from(&MR_SIGNER),
            product_id: 0,
            minimum_svn: 0,
            config_ids: vec![],
            sw_ids: vec!["INTEL-SA-00334".to_owned(), "INTEL-SA-00615".to_owned()],
        };

        let report = VerificationReport {
            sig: Default::default(),
            chain: vec![],
            http_body: IAS_CONFIG_SW_334_615.trim().to_owned(),
        };

        let data = VerificationReportData::try_from(&report).expect("Could not parse IAS result");
        assert!(!verifier.verify(&data))
    }

    /// Ensure a CONFIGURATION_AND_SW_HARDENING_NEEDED result with the expected
    /// MRSIGNER, product, and minimum version fails, if the advisory isn't
    /// accounted for in both config and sw.
    #[test]
    fn mrsigner_fail_multi_config_sw_short_config() {
        let verifier = MrSignerVerifier {
            mr_signer: MrSigner::from(&MR_SIGNER),
            product_id: 0,
            minimum_svn: 0,
            config_ids: vec!["INTEL-SA-00334".to_owned()],
            sw_ids: vec!["INTEL-SA-00334".to_owned(), "INTEL-SA-00615".to_owned()],
        };

        let report = VerificationReport {
            sig: Default::default(),
            chain: vec![],
            http_body: IAS_CONFIG_SW_334_615.trim().to_owned(),
        };

        let data = VerificationReportData::try_from(&report).expect("Could not parse IAS result");
        assert!(!verifier.verify(&data))
    }

    /// Ensure a CONFIGURATION_AND_SW_HARDENING_NEEDED result with the expected
    /// MRSIGNER, and minimum version, but the wrong product fails, even if
    /// the advisory is accounted for.
    #[test]
    fn mrsigner_fail_sw_config_sw_for_product() {
        let verifier = MrSignerVerifier {
            mr_signer: MrSigner::from(&MR_SIGNER),
            product_id: 1,
            minimum_svn: 0,
            config_ids: vec!["INTEL-SA-00239".to_owned()],
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
    /// MRSIGNER, and minimum version, but the wrong product fails, even if
    /// all advisories are accounted for.
    #[test]
    fn mrsigner_fail_multi_sw_config_sw_for_product() {
        let verifier = MrSignerVerifier {
            mr_signer: MrSigner::from(&MR_SIGNER),
            product_id: 1,
            minimum_svn: 0,
            config_ids: vec!["INTEL-SA-00334".to_owned(), "INTEL-SA-00615".to_owned()],
            sw_ids: vec!["INTEL-SA-00334".to_owned(), "INTEL-SA-00615".to_owned()],
        };

        let report = VerificationReport {
            sig: Default::default(),
            chain: vec![],
            http_body: IAS_CONFIG_SW_334_615.trim().to_owned(),
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
            mr_signer: MrSigner::from(&MR_SIGNER),
            product_id: 0,
            minimum_svn: 1,
            config_ids: vec!["INTEL-SA-00239".to_owned()],
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
    fn mrsigner_fail_multi_config_sw_for_version() {
        let verifier = MrSignerVerifier {
            mr_signer: MrSigner::from(&MR_SIGNER),
            product_id: 0,
            minimum_svn: 1,
            config_ids: vec!["INTEL-SA-00334".to_owned(), "INTEL-SA-00615".to_owned()],
            sw_ids: vec!["INTEL-SA-00334".to_owned(), "INTEL-SA-00615".to_owned()],
        };

        let report = VerificationReport {
            sig: Default::default(),
            chain: vec![],
            http_body: IAS_CONFIG_SW_334_615.trim().to_owned(),
        };

        let data = VerificationReportData::try_from(&report).expect("Could not parse IAS result");
        assert!(!verifier.verify(&data))
    }
}
