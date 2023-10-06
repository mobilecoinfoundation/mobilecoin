// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Attestation Verification Report type.

use crate::prost;
use ::prost::{
    bytes::{Buf, BufMut},
    encoding::{self, DecodeContext, WireType},
    DecodeError, Message,
};
use alloc::{string::String, vec::Vec};
use base64::{engine::general_purpose::STANDARD as BASE64_ENGINE, Engine};
use core::fmt::{Debug, Display};
use hex_fmt::{HexFmt, HexList};
use mc_crypto_digestible::Digestible;
use mc_crypto_keys::X25519Public;
use mc_sgx_core_types::QuoteNonce;
use mc_sgx_dcap_types::{Collateral, Quote3};
use mc_util_encodings::{Error as EncodingError, FromBase64, FromHex};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DcapEvidence {
    pub quote: Quote3<Vec<u8>>,
    pub collateral: Collateral,
    pub report_data: EnclaveReportDataContents,
}

#[derive(Clone, Debug, PartialEq, Deserialize, Serialize)]
pub enum EvidenceKind {
    Epid(VerificationReport),
    Dcap(prost::DcapEvidence),
}

// We default to `EvidenceKind::Epid` as that was the original kind of
// `VerificationReport`.
impl Default for EvidenceKind {
    fn default() -> Self {
        EvidenceKind::Epid(Default::default())
    }
}

impl From<VerificationReport> for EvidenceKind {
    fn from(report: VerificationReport) -> Self {
        EvidenceKind::Epid(report)
    }
}

impl From<prost::DcapEvidence> for EvidenceKind {
    fn from(evidence: prost::DcapEvidence) -> Self {
        EvidenceKind::Dcap(evidence)
    }
}

// The first tag for a `VerificationReport`, this needs to match that defined
// in `VerificationReport`.
const TAG_VERIFICATION_REPORT_FIRST: u32 = 1;

// The last tag for a `VerificationReport`, this needs to match that defined
// in `VerificationReport`.
const TAG_VERIFICATION_REPORT_LAST: u32 = 3;

// The tag to indicate a `DcapEvidence` variant. For backwards compatibility
// this must be outside the range of tags used by `VerificationReport`.
const TAG_DCAP_EVIDENCE: u32 = 4;

/// In order to make `EvidenceKind` backwards compatible with the previous
/// logic which would send `VerificationReport`'s, the protobuf tags that
/// correspond to tags defined in `VerificationReport` will decode to the
/// `EvidenceKind::Epid()` variant. Tags outside of a `VerificationReport`'s
/// will be treated as other variants.
impl Message for EvidenceKind {
    fn encode_raw<B>(&self, buf: &mut B)
    where
        B: BufMut,
        Self: Sized,
    {
        match self {
            EvidenceKind::Dcap(evidence) => {
                encoding::message::encode(TAG_DCAP_EVIDENCE, evidence, buf);
            }
            EvidenceKind::Epid(report) => {
                report.encode_raw(buf);
            }
        }
    }

    fn merge_field<B>(
        &mut self,
        tag: u32,
        wire_type: WireType,
        buf: &mut B,
        ctx: DecodeContext,
    ) -> Result<(), DecodeError>
    where
        B: Buf,
        Self: Sized,
    {
        match tag {
            TAG_VERIFICATION_REPORT_FIRST..=TAG_VERIFICATION_REPORT_LAST => {
                let mut report = match self {
                    EvidenceKind::Epid(report) => report.clone(),
                    _ => Default::default(),
                };
                report.merge_field(tag, wire_type, buf, ctx)?;
                *self = EvidenceKind::Epid(report);
                Ok(())
            }
            TAG_DCAP_EVIDENCE => {
                let mut evidence = prost::DcapEvidence::default();
                encoding::message::merge(wire_type, &mut evidence, buf, ctx).map(|_| {
                    *self = EvidenceKind::Dcap(evidence);
                })
            }
            _ => encoding::skip_field(wire_type, tag, buf, ctx),
        }
    }

    fn encoded_len(&self) -> usize {
        match self {
            EvidenceKind::Dcap(evidence) => {
                encoding::message::encoded_len(TAG_DCAP_EVIDENCE, evidence)
            }
            EvidenceKind::Epid(report) => report.encoded_len(),
        }
    }

    fn clear(&mut self) {
        *self = Default::default();
    }
}

/// Container for holding the quote verification sent back from IAS.
///
/// The fields correspond to the data sent from IAS in the
/// [Attestation Verification Report](https://software.intel.com/sites/default/files/managed/7e/3b/ias-api-spec.pdf).
///
/// This structure is supposed to be filled in from the results of an IAS
/// web request and then validated directly or serialized into an enclave for
/// validation.
#[derive(
    Clone, Deserialize, Digestible, Eq, Hash, Message, Ord, PartialEq, PartialOrd, Serialize,
)]
pub struct VerificationReport {
    /// Report Signature bytes, from the X-IASReport-Signature HTTP header.
    #[prost(message, required, tag = 1)]
    pub sig: VerificationSignature,

    /// Attestation Report Signing Certificate Chain, as an array of
    /// DER-formatted bytes, from the X-IASReport-Signing-Certificate HTTP
    /// header.
    #[prost(bytes, repeated, tag = 2)]
    pub chain: Vec<Vec<u8>>,

    /// The raw report body JSON, as a byte sequence
    #[prost(string, required, tag = 3)]
    #[digestible(never_omit)]
    pub http_body: String,
}

impl Display for VerificationReport {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("VerificationReport")
            .field("sig", &HexFmt(&self.sig))
            .field("chain", &HexList(&self.chain))
            .field("http_body", &self.http_body)
            .finish()
    }
}

/// A type containing the bytes of the VerificationReport signature
#[derive(
    Clone, Default, Deserialize, Digestible, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize,
)]
#[repr(transparent)]
pub struct VerificationSignature(#[digestible(never_omit)] Vec<u8>);

impl Debug for VerificationSignature {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "VerificationSignature({})", HexFmt(&self))
    }
}

impl Display for VerificationSignature {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", HexFmt(&self))
    }
}

impl AsRef<[u8]> for VerificationSignature {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl From<VerificationSignature> for Vec<u8> {
    fn from(src: VerificationSignature) -> Vec<u8> {
        src.0
    }
}

impl From<Vec<u8>> for VerificationSignature {
    fn from(src: Vec<u8>) -> Self {
        Self(src)
    }
}

impl From<&[u8]> for VerificationSignature {
    fn from(src: &[u8]) -> Self {
        src.to_vec().into()
    }
}

impl FromHex for VerificationSignature {
    type Error = EncodingError;

    fn from_hex(s: &str) -> Result<Self, EncodingError> {
        // 2 hex chars per byte
        Ok(hex::decode(s)?.into())
    }
}

impl FromBase64 for VerificationSignature {
    type Error = EncodingError;

    fn from_base64(s: &str) -> Result<Self, EncodingError> {
        Ok(BASE64_ENGINE.decode(s)?.into())
    }
}

const TAG_SIGNATURE_CONTENTS: u32 = 1;

impl Message for VerificationSignature {
    fn encode_raw<B>(&self, buf: &mut B)
    where
        B: BufMut,
        Self: Sized,
    {
        encoding::bytes::encode(TAG_SIGNATURE_CONTENTS, &self.0, buf);
    }

    fn merge_field<B>(
        &mut self,
        tag: u32,
        wire_type: WireType,
        buf: &mut B,
        ctx: DecodeContext,
    ) -> Result<(), DecodeError>
    where
        B: Buf,
        Self: Sized,
    {
        if tag == TAG_SIGNATURE_CONTENTS {
            encoding::bytes::merge(wire_type, &mut self.0, buf, ctx)
        } else {
            encoding::skip_field(wire_type, tag, buf, ctx)
        }
    }

    fn encoded_len(&self) -> usize {
        encoding::bytes::encoded_len(TAG_SIGNATURE_CONTENTS, &self.0)
    }

    fn clear(&mut self) {
        self.0.clear()
    }
}

/// Structure for holding the contents of the Enclave's Report Data.
/// The Enclave Quote's ReportData member contains a SHA256 hash of this
/// structure's contents.
#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct EnclaveReportDataContents {
    nonce: QuoteNonce,
    key: X25519Public,
    custom_identity: Option<[u8; 32]>,
}

impl EnclaveReportDataContents {
    /// Create a new EnclaveReportDataContents.
    ///
    /// # Arguments
    /// * `nonce` - The nonce provided from the enclave when generating the
    ///   Report.
    /// * `key` - The public key of the enclave. Previously this was bytes 0..32
    ///   of the enclave's [`ReportData`](mc-sgx-core-types::ReportData).
    /// * `custom_identity` - The custom identity of the enclave. Previously
    ///   this was bytes 32..64 of the enclave's
    ///   [`ReportData`](mc-sgx-core-types::ReportData).
    pub fn new(
        nonce: QuoteNonce,
        key: X25519Public,
        custom_identity: impl Into<Option<[u8; 32]>>,
    ) -> Self {
        Self {
            nonce,
            key,
            custom_identity: custom_identity.into(),
        }
    }

    /// Get the nonce
    pub fn nonce(&self) -> &QuoteNonce {
        &self.nonce
    }

    /// Get the public key
    pub fn key(&self) -> &X25519Public {
        &self.key
    }

    ///  Get the custom identity
    pub fn custom_identity(&self) -> Option<&[u8; 32]> {
        self.custom_identity.as_ref()
    }

    /// Returns a SHA256 hash of the contents of this structure.
    ///
    /// This is the value that is stored in bytes 0..32 of the enclave's
    /// [`ReportData`](mc-sgx-core-types::ReportData).
    pub fn sha256(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(&self.nonce);
        hasher.update(&self.key);
        if let Some(custom_identity) = &self.custom_identity {
            hasher.update(custom_identity);
        }
        hasher.finalize().into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::{format, vec};
    use mc_attest_untrusted::DcapQuotingEnclave;
    use mc_sgx_core_types::Report;
    use mc_util_test_helper::Rng;

    #[test]
    fn test_signature_debug() {
        let sig = VerificationSignature(vec![0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE]);
        assert_eq!(format!("{:?}", &sig), "VerificationSignature(deadbeefcafe)");
    }

    #[test]
    fn test_report_display() {
        let report = VerificationReport {
            sig: vec![0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE].into(),
            chain: vec![vec![0xAB, 0xCD], vec![0xCD, 0xEF], vec![0x12, 0x34]],
            http_body: "some_body".into(),
        };
        assert_eq!(
            format!("{}", &report),
            "VerificationReport { sig: deadbeefcafe, chain: [abcd, cdef, 1234], http_body: \"some_body\" }"
        );
    }

    #[test]
    fn enclave_report_data_contents_sha256_without_custom_id() {
        let nonce: QuoteNonce = [0x2u8; 16].into();
        let key_bytes = [0x33u8; 32];
        let key: X25519Public = key_bytes.as_slice().try_into().expect("bad key");
        let zeroed_custom_identity = [0x0u8; 32];
        let report_data_without_custom_id =
            EnclaveReportDataContents::new(nonce.clone(), key.clone(), None);

        let report_data_with_zeroed_custom_id =
            EnclaveReportDataContents::new(nonce, key, zeroed_custom_identity);

        assert_ne!(
            report_data_without_custom_id.sha256(),
            report_data_with_zeroed_custom_id.sha256()
        );
    }

    #[test]
    fn empty_evidence_kind_decodes_to_verification_report() {
        let empty_evidence_kind = EvidenceKind::default();
        let bytes = empty_evidence_kind.encode_to_vec();
        let decoded_evidence_kind =
            EvidenceKind::decode(bytes.as_slice()).expect("Failed to decode empty evidence kind");
        assert_eq!(
            EvidenceKind::Epid(Default::default()),
            decoded_evidence_kind
        );
    }

    #[test]
    fn evidence_kind_to_from_verification_report() {
        mc_util_test_helper::run_with_several_seeds(|mut rng| {
            let string_length = rng.gen_range(1..=100);
            let chain_len = rng.gen_range(2..42);
            let report = VerificationReport {
                sig: mc_util_test_helper::random_bytes_vec(32, &mut rng).into(),
                chain: (1..=chain_len)
                    .map(|n| mc_util_test_helper::random_bytes_vec(n as usize, &mut rng))
                    .collect(),
                http_body: mc_util_test_helper::random_str(string_length, &mut rng),
            };
            let bytes = report.encode_to_vec();

            // For backwards compatibility `EvidenceKind` should decode directly
            // from a `VerificationReport` byte stream
            let evidence =
                EvidenceKind::decode(bytes.as_slice()).expect("Failed to decode to EvidenceKind");
            assert_eq!(EvidenceKind::Epid(report.clone()), evidence);

            // For backwards compatibility the encoding of `EvidenceKind` when
            // it's a `VerificationReport` should be able to decode to a
            // `VerificationReport`.
            let evidence_bytes = evidence.encode_to_vec();
            let decoded_report = VerificationReport::decode(evidence_bytes.as_slice())
                .expect("Failed to decode to VerificationReport");
            assert_eq!(report, decoded_report);
        })
    }

    #[test]
    fn evidence_kind_dcap_encode_and_decode() {
        let report_data = EnclaveReportDataContents::new(
            [0x20u8; 16].into(),
            [0x63u8; 32].as_slice().try_into().expect("bad key"),
            [0xAEu8; 32],
        );
        let mut report = Report::default();
        report.as_mut().body.report_data.d[..32].copy_from_slice(&report_data.sha256());

        let quote = DcapQuotingEnclave::quote_report(&report).expect("Failed to create quote");
        let collateral = DcapQuotingEnclave::collateral(&quote).expect("Failed to get collateral");
        let dcap_evidence = prost::DcapEvidence {
            quote: Some((&quote).into()),
            collateral: Some(
                (&collateral)
                    .try_into()
                    .expect("Failed to convert collateral"),
            ),
            report_data: Some((&report_data).into()),
        };

        let evidence_kind = EvidenceKind::Dcap(dcap_evidence);

        let bytes = evidence_kind.encode_to_vec();

        let decoded_evidence_kind =
            EvidenceKind::decode(bytes.as_slice()).expect("Failed to decode to EvidenceKind");
        assert_eq!(evidence_kind, decoded_evidence_kind);
    }
}
