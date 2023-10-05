// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Attestation Verification Report type.

use crate::prost;
use ::prost::{
    bytes::{Buf, BufMut},
    encoding::{self, DecodeContext, WireType},
    DecodeError, Message, Oneof,
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

#[derive(Oneof,
Clone, Deserialize, Digestible, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize,
)]
pub enum EvidenceKind {
    #[prost(message, tag = "4")]
    Dcap(prost::DcapEvidence),
    #[prost(message, tag = "5")]
    verification_report(VerificationReport),
}

#[derive(Clone, Message)]
pub struct EvidenceMessage {
    #[prost(oneof = "EvidenceKind", tags = "4")]
    pub evidence: Option<EvidenceKind>,
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
}
