// Copyright (c) 2023 The MobileCoin Foundation

//! Verify the contents of a Quote3.

use crate::{DCAP_ROOT_ANCHOR, DEBUG_ENCLAVE};
use alloc::{format, vec::Vec};
use core::fmt::Formatter;
use der::DateTime;
use hex_fmt::HexFmt;
use mc_attest_verifier_types::EnclaveReportDataContents;
use mc_attestation_verifier::{
    choice_to_status_message, Accessor, And, AndOutput, AttributesVerifier, Evidence,
    EvidenceValue, EvidenceVerifier, MbedTlsCertificateChainVerifier, ReportDataVerifier,
    TrustAnchor, TrustedIdentity, VerificationMessage, VerificationOutput, Verifier,
    MESSAGE_INDENT,
};
use mc_sgx_core_types::{AttributeFlags, Attributes, ReportData};

#[derive(Debug)]
pub struct DcapVerifier {
    verifier: And<
        EvidenceVerifier<MbedTlsCertificateChainVerifier>,
        And<ReportDataHashVerifier, AttributesVerifier>,
    >,
}

type DcapVerifierOutput = AndOutput<EvidenceValue, AndOutput<ReportData, Attributes>>;

impl DcapVerifier {
    /// Create a new instance of the DcapVerifier.
    ///
    /// # Arguments
    /// * `trusted_identities` - The allowed identities that can be used in an
    ///   enclave. Verification will succeed if any of these match.
    /// * `time` - The time to use to verify the validity of the certificates
    ///   and collateral. If time is provided, verification will fail if this
    ///   time is before or after any of the validity periods. Otherwise, time
    ///   validation of certificates will be skipped.
    pub fn new<I, ID>(
        trusted_identities: I,
        time: impl Into<Option<DateTime>>,
        report_data: EnclaveReportDataContents,
    ) -> Self
    where
        I: IntoIterator<Item = ID>,
        ID: Into<TrustedIdentity>,
    {
        let trust_anchor =
            TrustAnchor::try_from_pem(DCAP_ROOT_ANCHOR).expect("Failed to parse root cert");
        let certificate_verifier = MbedTlsCertificateChainVerifier::new(trust_anchor);
        let verifier = And::new(
            EvidenceVerifier::new(certificate_verifier, trusted_identities, time),
            And::new(
                ReportDataHashVerifier::new(report_data),
                debug_attribute_verifier(DEBUG_ENCLAVE),
            ),
        );
        Self { verifier }
    }

    /// Verify the `evidence`
    pub fn verify(&self, evidence: &Evidence<Vec<u8>>) -> VerificationOutput<DcapVerifierOutput> {
        self.verifier.verify(evidence)
    }
}

impl VerificationMessage<DcapVerifierOutput> for DcapVerifier {
    fn fmt_padded(
        &self,
        f: &mut Formatter<'_>,
        pad: usize,
        result: &VerificationOutput<DcapVerifierOutput>,
    ) -> core::fmt::Result {
        let is_success = result.is_success();
        let status = choice_to_status_message(is_success);

        writeln!(f, "{:pad$}{status} DCAP evidence:", "")?;
        self.verifier.fmt_padded(f, pad + MESSAGE_INDENT, result)
    }
}

/// Create an attributes verifier that will only allow the DEBUG flag to be set
/// if `debug_allowed` is true.
///
/// As documented in
/// <https://download.01.org/intel-sgx/sgx-dcap/1.17/linux/docs/Intel_SGX_ECDSA_QuoteLibReference_DCAP_API.pdf>
///
/// Production enclaves should not have the REPORT.Attribute.Debug flag set
/// to 1. When the Debug flag is set a debugger can read the enclave
/// memory and should not be provisioned with production secrets.
fn debug_attribute_verifier(debug_allowed: bool) -> AttributesVerifier {
    // The default bits are all 0 meaning a non debug build.
    let attributes = Attributes::default();

    // We only enforce checking the Debug bit when debug isn't allowed.
    // There is no harm in verifying a production enclave when debug is allowed.
    let mut mask = Attributes::default();
    if !debug_allowed {
        mask = mask.set_flags(AttributeFlags::DEBUG);
    }

    AttributesVerifier::new(attributes, mask)
}

#[derive(Debug, Clone)]
pub struct ReportDataHashVerifier {
    report_data: EnclaveReportDataContents,
    report_data_verifier: ReportDataVerifier,
}

impl ReportDataHashVerifier {
    pub fn new(report_data: EnclaveReportDataContents) -> Self {
        let mut expected_report_data_bytes = [0u8; 64];
        expected_report_data_bytes[..32].copy_from_slice(report_data.sha256().as_ref());
        let mut mask = [0u8; 64];
        mask[..32].copy_from_slice([0xffu8; 32].as_ref());
        let report_data_verifier =
            ReportDataVerifier::new(expected_report_data_bytes.into(), mask.into());

        Self {
            report_data,
            report_data_verifier,
        }
    }
}

impl<E: Accessor<ReportData>> Verifier<E> for ReportDataHashVerifier {
    type Value = ReportData;

    fn verify(&self, evidence: &E) -> VerificationOutput<Self::Value> {
        self.report_data_verifier.verify(evidence)
    }
}

impl VerificationMessage<ReportData> for ReportDataHashVerifier {
    fn fmt_padded(
        &self,
        f: &mut Formatter<'_>,
        pad: usize,
        result: &VerificationOutput<ReportData>,
    ) -> core::fmt::Result {
        let is_success = result.is_success();
        let status = mc_attestation_verifier::choice_to_status_message(is_success);
        let hash = HexFmt(self.report_data.sha256());
        writeln!(
            f,
            "{:pad$}{status} The ReportData hash should be {hash:X} for:",
            ""
        )?;
        let pad = pad + MESSAGE_INDENT;
        writeln!(f, "{:pad$}- QuoteNonce: {}", "", self.report_data.nonce())?;

        writeln!(f, "{:pad$}- Public key:", "")?;
        let key_string = format!("{:?}", self.report_data.key());
        for line in key_string.lines() {
            writeln!(f, "{:pad$}  {line}", "")?;
        }

        write!(f, "{:pad$}- Custom identity: ", "")?;
        match self.report_data.custom_identity() {
            Some(value) => {
                let hex = HexFmt(value);
                writeln!(f, "{hex:X}")?
            }
            None => writeln!(f, "<None>")?,
        }

        self.report_data_verifier.fmt_padded(f, pad, result)
    }
}

#[cfg(test)]
mod test {
    extern crate std;
    use super::*;
    use mc_attest_untrusted::DcapQuotingEnclave;
    use mc_attestation_verifier::{TrustedMrEnclaveIdentity, VerificationTreeDisplay};
    use mc_common::time::{SystemTimeProvider, TimeProvider};
    use mc_sgx_core_types::Report;

    fn report_and_report_data() -> (Report, EnclaveReportDataContents) {
        let mut report = Report::default();
        let report_data_contents = EnclaveReportDataContents::new(
            [0x42u8; 16].into(),
            [0x11u8; 32].as_slice().try_into().expect("bad key"),
            [0xAAu8; 32],
        );
        report.as_mut().body.report_data.d[..32].copy_from_slice(&report_data_contents.sha256());
        (report, report_data_contents)
    }

    #[test]
    fn report_data_hash_verifier_succeeds() {
        let report_data_contents = EnclaveReportDataContents::new(
            [1u8; 16].into(),
            [2u8; 32].as_slice().try_into().expect("bad key"),
            [3u8; 32],
        );

        let hash_verifier = ReportDataHashVerifier::new(report_data_contents.clone());

        let mut report_data_bytes = [0u8; 64];
        report_data_bytes[..32].copy_from_slice(report_data_contents.sha256().as_ref());
        let verification = hash_verifier.verify(&ReportData::from(report_data_bytes));
        assert_eq!(verification.is_success().unwrap_u8(), 1);

        let displayable = VerificationTreeDisplay::new(&hash_verifier, verification);
        let expected = r#"
            - [x] The ReportData hash should be C33924B6D47F16A85882721C8CAEC78C4A61F797E0F4F9B415CD2829A8D085C5 for:
              - QuoteNonce: 0x0101_0101_0101_0101_0101_0101_0101_0101
              - Public key:
                -----BEGIN PUBLIC KEY-----
                MCowBQYDK2VuAyEAAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=
                -----END PUBLIC KEY-----
              - Custom identity: 0303030303030303030303030303030303030303030303030303030303030303
              - [x] The expected report data is 0xC339_24B6_D47F_16A8_5882_721C_8CAE_C78C_4A61_F797_E0F4_F9B4_15CD_2829_A8D0_85C5_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000 with mask 0xFFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000"#;
        assert_eq!(format!("\n{displayable}"), textwrap::dedent(expected));
    }

    #[test]
    fn report_data_hash_verifier_fails() {
        let report_data_contents = EnclaveReportDataContents::new(
            [1u8; 16].into(),
            [2u8; 32].as_slice().try_into().expect("bad key"),
            [3u8; 32],
        );

        let hash_verifier = ReportDataHashVerifier::new(report_data_contents.clone());

        let mut report_data_bytes = [0u8; 64];
        report_data_bytes[..32].copy_from_slice(report_data_contents.sha256().as_ref());
        report_data_bytes[0] += 1;
        let verification = hash_verifier.verify(&ReportData::from(report_data_bytes));
        assert_eq!(verification.is_success().unwrap_u8(), 0);

        let displayable = VerificationTreeDisplay::new(&hash_verifier, verification);
        let expected = r#"
            - [ ] The ReportData hash should be C33924B6D47F16A85882721C8CAEC78C4A61F797E0F4F9B415CD2829A8D085C5 for:
              - QuoteNonce: 0x0101_0101_0101_0101_0101_0101_0101_0101
              - Public key:
                -----BEGIN PUBLIC KEY-----
                MCowBQYDK2VuAyEAAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=
                -----END PUBLIC KEY-----
              - Custom identity: 0303030303030303030303030303030303030303030303030303030303030303
              - [ ] The expected report data is 0xC339_24B6_D47F_16A8_5882_721C_8CAE_C78C_4A61_F797_E0F4_F9B4_15CD_2829_A8D0_85C5_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000 with mask 0xFFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000, but the actual report data was 0xC439_24B6_D47F_16A8_5882_721C_8CAE_C78C_4A61_F797_E0F4_F9B4_15CD_2829_A8D0_85C5_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000"#;
        assert_eq!(format!("\n{displayable}"), textwrap::dedent(expected));
    }

    #[test]
    fn debug_with_debug_not_allowed_fails() {
        let debug_attributes = Attributes::default().set_flags(AttributeFlags::DEBUG);
        let verifier = debug_attribute_verifier(false);
        let verification = verifier.verify(&debug_attributes);
        assert_eq!(verification.is_success().unwrap_u8(), 0);
    }

    #[test]
    fn debug_with_debug_allowed_succeeds() {
        let debug_attributes = Attributes::default().set_flags(AttributeFlags::DEBUG);
        let verifier = debug_attribute_verifier(true);
        let verification = verifier.verify(&debug_attributes);
        assert_eq!(verification.is_success().unwrap_u8(), 1);
    }

    #[test]
    fn release_with_debug_allowed_succeeds() {
        // This case shouldn't normally happen, but there is no harm in
        // verifying a release enclave when debug is allowed.
        let release_attributes = Attributes::default();
        let verifier = debug_attribute_verifier(true);
        let verification = verifier.verify(&release_attributes);
        assert_eq!(verification.is_success().unwrap_u8(), 1);
    }

    #[test]
    fn successful_verification() {
        let (report, report_data_contents) = report_and_report_data();
        let quote = DcapQuotingEnclave::quote_report(&report).expect("Failed to get quote");
        let collateral = DcapQuotingEnclave::collateral(&quote).expect("Failed to get collateral");
        let mr_enclave = quote.app_report_body().mr_enclave();
        let identities =
            &[TrustedMrEnclaveIdentity::new(mr_enclave, [] as [&str; 0], [] as [&str; 0]).into()];
        let evidence = Evidence::new(quote, collateral).expect("Failed to get evidence");

        // The certs, TCB info, and QE identity are generated at build time, so `now()`
        // should be alright to use in testing.
        let now = SystemTimeProvider
            .since_epoch()
            .expect("Failed to get duration since epoch");
        let time =
            DateTime::from_unix_duration(now).expect("Failed to convert duration to DateTime");
        let verifier = DcapVerifier::new(identities, time, report_data_contents);
        let verification = verifier.verify(&evidence);
        assert_eq!(verification.is_success().unwrap_u8(), 1);

        let displayable = VerificationTreeDisplay::new(&verifier, verification);
        let expected = r#"
            - [x] DCAP evidence:
              - [x] Both of the following must be true:
                - [x] all of the following must be true:
                  - [x] The TCB issuer chain was verified.
                  - [x] The QE identity issuer chain was verified.
                  - [x] The Quote issuer chain was verified.
                  - [x] The TCB info was verified for the provided key
                  - [x] The QE identity was verified for the provided key
                  - [x] QE Report Body all of the following must be true:
                    - [x] The MRSIGNER key hash should be 1234567890abcdeffedcba09876543211234567890abcdeffedcba0987654321
                    - [x] The ISV product ID should be 0
                    - [x] The expected miscellaneous select is 0x0000_0000 with mask 0xFFFF_FFFF
                    - [x] The expected attributes is Flags: (none) Xfrm: (none) with mask Flags: 0xFFFF_FFFF_FFFF_FFFF Xfrm: LEGACY | AVX | AVX_512 | MPX | PKRU | AMX | RESERVED
                    - [x] The ISV SVN should correspond to an `UpToDate` level with no advisories, from: [TcbLevel { tcb: Tcb { isv_svn: 0 }, tcb_date: "2021-11-10T00:00:00Z", tcb_status: UpToDate, advisory_ids: [] }]
                  - [x] The quote was signed with the provided key
                  - [x] Both of the following must be true:
                    - [x] The MRENCLAVE should be 0000000000000000000000000000000000000000000000000000000000000000
                    - [x] The allowed advisories are IDs: (none) Status: UpToDate
                - [x] Both of the following must be true:
                  - [x] The ReportData hash should be CDA9694852475320FD7110D9B50164369A7622A00AA7CC83DBC4D66BF078870B for:
                    - QuoteNonce: 0x4242_4242_4242_4242_4242_4242_4242_4242
                    - Public key:
                      -----BEGIN PUBLIC KEY-----
                      MCowBQYDK2VuAyEAERERERERERERERERERERERERERERERERERERERERERE=
                      -----END PUBLIC KEY-----
                    - Custom identity: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
                    - [x] The expected report data is 0xCDA9_6948_5247_5320_FD71_10D9_B501_6436_9A76_22A0_0AA7_CC83_DBC4_D66B_F078_870B_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000 with mask 0xFFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000
                  - [x] The expected attributes is Flags: (none) Xfrm: (none) with mask Flags: (none) Xfrm: (none)"#;
        assert_eq!(format!("\n{displayable}"), textwrap::dedent(expected));
    }

    #[test]
    fn failed_verification() {
        let (mut report, report_data_contents) = report_and_report_data();

        report.as_mut().body.report_data.d[0] += 1;

        let quote = DcapQuotingEnclave::quote_report(&report).expect("Failed to get quote");
        let collateral = DcapQuotingEnclave::collateral(&quote).expect("Failed to get collateral");
        let mr_enclave = quote.app_report_body().mr_enclave();
        let identities =
            &[TrustedMrEnclaveIdentity::new(mr_enclave, [] as [&str; 0], [] as [&str; 0]).into()];
        let evidence = Evidence::new(quote, collateral).expect("Failed to get evidence");

        // The certs, TCB info, and QE identity are generated at build time, so `now()`
        // should be alright to use in testing.
        let now = SystemTimeProvider
            .since_epoch()
            .expect("Failed to get duration since epoch");
        let time =
            DateTime::from_unix_duration(now).expect("Failed to convert duration to DateTime");
        let verifier = DcapVerifier::new(identities, time, report_data_contents);
        let verification = verifier.verify(&evidence);
        assert_eq!(verification.is_success().unwrap_u8(), 0);

        let displayable = VerificationTreeDisplay::new(&verifier, verification);
        let expected = r#"
            - [ ] DCAP evidence:
              - [ ] Both of the following must be true:
                - [x] all of the following must be true:
                  - [x] The TCB issuer chain was verified.
                  - [x] The QE identity issuer chain was verified.
                  - [x] The Quote issuer chain was verified.
                  - [x] The TCB info was verified for the provided key
                  - [x] The QE identity was verified for the provided key
                  - [x] QE Report Body all of the following must be true:
                    - [x] The MRSIGNER key hash should be 1234567890abcdeffedcba09876543211234567890abcdeffedcba0987654321
                    - [x] The ISV product ID should be 0
                    - [x] The expected miscellaneous select is 0x0000_0000 with mask 0xFFFF_FFFF
                    - [x] The expected attributes is Flags: (none) Xfrm: (none) with mask Flags: 0xFFFF_FFFF_FFFF_FFFF Xfrm: LEGACY | AVX | AVX_512 | MPX | PKRU | AMX | RESERVED
                    - [x] The ISV SVN should correspond to an `UpToDate` level with no advisories, from: [TcbLevel { tcb: Tcb { isv_svn: 0 }, tcb_date: "2021-11-10T00:00:00Z", tcb_status: UpToDate, advisory_ids: [] }]
                  - [x] The quote was signed with the provided key
                  - [x] Both of the following must be true:
                    - [x] The MRENCLAVE should be 0000000000000000000000000000000000000000000000000000000000000000
                    - [x] The allowed advisories are IDs: (none) Status: UpToDate
                - [ ] Both of the following must be true:
                  - [ ] The ReportData hash should be CDA9694852475320FD7110D9B50164369A7622A00AA7CC83DBC4D66BF078870B for:
                    - QuoteNonce: 0x4242_4242_4242_4242_4242_4242_4242_4242
                    - Public key:
                      -----BEGIN PUBLIC KEY-----
                      MCowBQYDK2VuAyEAERERERERERERERERERERERERERERERERERERERERERE=
                      -----END PUBLIC KEY-----
                    - Custom identity: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
                    - [ ] The expected report data is 0xCDA9_6948_5247_5320_FD71_10D9_B501_6436_9A76_22A0_0AA7_CC83_DBC4_D66B_F078_870B_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000 with mask 0xFFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000, but the actual report data was 0xCEA9_6948_5247_5320_FD71_10D9_B501_6436_9A76_22A0_0AA7_CC83_DBC4_D66B_F078_870B_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000
                  - [x] The expected attributes is Flags: (none) Xfrm: (none) with mask Flags: (none) Xfrm: (none)"#;
        assert_eq!(format!("\n{displayable}"), textwrap::dedent(expected));
    }
}
