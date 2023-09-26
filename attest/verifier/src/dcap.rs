// Copyright (c) 2023 The MobileCoin Foundation

//! Verify the contents of a Quote3.

use crate::{DEBUG_ENCLAVE, IAS_SIGNING_ROOT_CERT_PEM};
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
    ///   and collateral. Verification will fail if this time is before or after
    ///   any of the validity periods.
    pub fn new<I, ID>(
        trusted_identities: I,
        time: DateTime,
        report_data: EnclaveReportDataContents,
    ) -> Self
    where
        I: IntoIterator<Item = ID>,
        ID: Into<TrustedIdentity>,
    {
        let trust_anchor = TrustAnchor::try_from_pem(IAS_SIGNING_ROOT_CERT_PEM)
            .expect("Failed to parse root cert");
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
/// <https://download.01.org/intel-sgx/sgx-dcap/1.17/linux/docs/Intel_SGX_ECDSA_QuoteLibReference_DCAP_API.pdf#%5B%7B%22num%22%3A64%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22XYZ%22%7D%2C69%2C283%2C0%5D>
///
///     Production enclaves should not have the REPORT.Attribute.Debug flag set
///     to 1. When the Debug flag is set, a debugger can read the enclave’s
///     memory and should not be provisioned with production secrets.
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
    use super::*;
    use mc_attestation_verifier::VerificationTreeDisplay;

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
}
