// Copyright (c) 2023 The MobileCoin Foundation

//! Verify the contents of a Quote3.

use crate::IAS_SIGNING_ROOT_CERT_PEM;
use alloc::{format, vec::Vec};
use core::fmt::Formatter;
use der::DateTime;
use hex_fmt::HexFmt;
use mc_attest_verifier_types::EnclaveReportDataContents;
use mc_attestation_verifier::{
    Accessor, And, AndOutput, Evidence, EvidenceValue, EvidenceVerifier,
    MbedTlsCertificateChainVerifier, ReportDataVerifier, TrustAnchor, TrustedIdentity,
    VerificationMessage, VerificationOutput, Verifier, MESSAGE_INDENT,
};
use mc_sgx_core_types::ReportData;

#[derive(Debug)]
pub struct DcapVerifier {
    verifier: And<EvidenceVerifier<MbedTlsCertificateChainVerifier>, ReportDataHashVerifier>,
}

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
            ReportDataHashVerifier::new(report_data),
        );
        Self { verifier }
    }

    /// Verify the `evidence`
    pub fn verify(
        &self,
        evidence: Evidence<Vec<u8>>,
    ) -> VerificationOutput<AndOutput<EvidenceValue, ReportData>> {
        self.verifier.verify(&evidence)
    }
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

        let hex = HexFmt(self.report_data.custom_identity());
        writeln!(f, "{:pad$}- Custom identity: {hex:X}", "")?;

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
}
