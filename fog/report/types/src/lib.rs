// Copyright (c) 2018-2022 The MobileCoin Foundation

#![no_std]
#![deny(missing_docs)]

//! This crate provides prost versions of some types from fog report server
//! proto One reason that these prost versions are needed is so that
//! mc-fog-report-validation doesn't depend on grpcio, as `mc-fog-api` does.

extern crate alloc;

use ::prost::Message;
use alloc::{collections::BTreeMap, string::String, vec::Vec};
use mc_attest_verifier_types::{prost, VerificationReport};
use mc_crypto_digestible::Digestible;
use serde::{Deserialize, Serialize};

/// The attestation evidence variants for a report.
#[derive(Clone, ::prost::Oneof, Deserialize, Eq, PartialEq, Serialize, Digestible)]
#[digestible(transparent)]
pub enum AttestationEvidence {
    /// The attestation evidence is a [VerificationReport].
    #[prost(message, tag = 2)]
    VerificationReport(VerificationReport),
    /// DCAP evidence
    #[prost(message, tag = 4)]
    DcapEvidence(prost::DcapEvidence),
}

impl From<VerificationReport> for AttestationEvidence {
    fn from(report: VerificationReport) -> Self {
        Self::VerificationReport(report)
    }
}

impl From<prost::DcapEvidence> for AttestationEvidence {
    fn from(evidence: prost::DcapEvidence) -> Self {
        Self::DcapEvidence(evidence)
    }
}

/// A one of container for AttestationEvidence.
/// One cannot decode a oneof directly, so this is used to wrap the oneof to get
/// that behavior
#[derive(Clone, Digestible, Eq, PartialEq, Serialize, Deserialize, Message)]
pub struct AttestationEvidenceOneOf {
    /// Attestation evidence for the enclave.
    #[prost(oneof = "AttestationEvidence", tags = "2, 4")]
    pub evidence: Option<AttestationEvidence>,
}

impl From<AttestationEvidence> for AttestationEvidenceOneOf {
    fn from(evidence: AttestationEvidence) -> Self {
        Self {
            evidence: Some(evidence),
        }
    }
}

/// A fog report from the report server
#[derive(Clone, Digestible, Eq, PartialEq, Serialize, Deserialize, Message)]
pub struct Report {
    /// The fog_report_id of the report
    #[prost(string, tag = "1")]
    #[digestible(never_omit)]
    pub fog_report_id: String,
    /// Attestation evidence for the enclave.
    #[prost(oneof = "AttestationEvidence", tags = "2, 4")]
    #[digestible(name = "report")]
    pub attestation_evidence: Option<AttestationEvidence>,
    /// The pubkey expiry value (a block index)
    #[prost(fixed64, tag = "3")]
    pub pubkey_expiry: u64,
}

/// An entire response from the report server
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize, Message)]
pub struct ReportResponse {
    /// A list of reports provided by the server.
    #[prost(message, repeated, tag = "1")]
    pub reports: Vec<Report>,
    /// A chain of DER-encoded X.509 Certificates, from root to leaf.
    ///
    /// The key type of the last certificate in the chain determines
    /// the correct parsing of the signature.
    #[prost(bytes, repeated, tag = "2")]
    pub chain: Vec<Vec<u8>>,
    /// A signature over the reports.
    #[prost(bytes, tag = "3")]
    pub signature: Vec<u8>,
}

/// Represents a set of unvalidated responses from Fog report servers
/// Key = Fog-url that was contacted, must match the string in user's public
/// address Value = The complete response from the fog report server
///
/// When constructing a transaction, the fog-url for each recipient should be
/// extracted from their public address, then a request to that report server
/// should be made. The responses should be collected in a map-structure (like
/// this). This should be done for each recipient.
///
/// This map structure is ultimately consumed by the TransactionBuilder object,
/// which validates the responses against the fog data in the public addresses
/// when building the transaction.
///
/// This map structure should not be cached, because the fog pubkeys have an
/// expiry date and don't live that long. They can be cached for a short time,
/// but the transaction builder enforces that the tombstone block for the
/// transaction is limited by the pubkey expiry value of any fog pubkey that is
/// used, so if these are cached too long, the transaction will be rejected by
/// consensus.
///
/// In the case of constructing off-line transactions with Fog recipients, the
/// flow is: (1) Take fog-urls from (offline) public addresses to the online
/// machine (2) Hit the fog report servers (online machine), producing
/// FogReportResponses (3) Take FogReportResponses to the offline machine, and
/// use with transaction builder,     to create the transaction offline.
/// (4) Take the constructed transaction to the online machine and submit to
/// consensus.
///
/// Note: there is no particular reason for this to be BTreeMap instead of
/// HashMap, except that it is slightly more portable, only requiring the alloc
/// crate.
pub type FogReportResponses = BTreeMap<String, ReportResponse>;

#[cfg(test)]
mod test {
    use super::*;
    use mc_crypto_digestible::MerlinTranscript;
    use mc_util_test_helper::{Rng, RngCore};

    /// A fog report used with EPID attestation, prior to DCAP attestation
    #[derive(Clone, Digestible, Eq, PartialEq, Serialize, Deserialize, Message)]
    #[digestible(name = "Report")]
    pub struct EpidReport {
        /// The fog_report_id of the report
        #[prost(string, tag = "1")]
        #[digestible(never_omit)]
        pub fog_report_id: String,
        /// The bytes of the verification report
        #[prost(message, required, tag = "2")]
        pub report: VerificationReport,
        /// The pubkey expiry value (a block index)
        #[prost(fixed64, tag = "3")]
        pub pubkey_expiry: u64,
    }

    #[test]
    fn empty_report_back_and_forth() {
        let epid_report = EpidReport::default();
        let bytes = mc_util_serial::encode(&epid_report);
        let dcap_report = Report::decode(bytes.as_slice()).expect("failed to decode");
        assert_eq!(epid_report.fog_report_id, dcap_report.fog_report_id);
        assert_eq!(
            Some(AttestationEvidence::VerificationReport(
                epid_report.report.clone()
            )),
            dcap_report.attestation_evidence
        );
        assert_eq!(epid_report.pubkey_expiry, dcap_report.pubkey_expiry);

        let epid_digest = epid_report.digest32::<MerlinTranscript>(b"");
        let dcap_digest = dcap_report.digest32::<MerlinTranscript>(b"");
        assert_eq!(epid_digest, dcap_digest);
    }

    #[test]
    fn epid_report_works_with_new_dcap_report() {
        mc_util_test_helper::run_with_several_seeds(|mut rng| {
            let string_length = rng.gen_range(1..=100);
            let epid_report = EpidReport {
                fog_report_id: mc_util_test_helper::random_str(string_length, &mut rng),
                report: mc_blockchain_test_utils::make_verification_report(&mut rng),
                pubkey_expiry: rng.next_u64(),
            };

            let bytes = mc_util_serial::encode(&epid_report);
            let dcap_report = Report::decode(bytes.as_slice()).expect("failed to decode");
            assert_eq!(epid_report.fog_report_id, dcap_report.fog_report_id);
            assert_eq!(
                Some(AttestationEvidence::VerificationReport(
                    epid_report.report.clone()
                )),
                dcap_report.attestation_evidence
            );
            assert_eq!(epid_report.pubkey_expiry, dcap_report.pubkey_expiry);

            let epid_digest = epid_report.digest32::<MerlinTranscript>(b"");
            let dcap_digest = dcap_report.digest32::<MerlinTranscript>(b"");
            assert_eq!(epid_digest, dcap_digest);
        })
    }
}
