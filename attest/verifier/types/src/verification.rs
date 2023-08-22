// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Attestation Verification Report type.

use alloc::{string::String, vec::Vec};
use base64::{engine::general_purpose::STANDARD as BASE64_ENGINE, Engine};
use core::fmt::{Debug, Display};
use hex_fmt::{HexFmt, HexList};
use mc_crypto_digestible::Digestible;
use mc_sgx_dcap_types::{Collateral, Quote3};
use mc_util_encodings::{Error as EncodingError, FromBase64, FromHex};
use prost::{
    bytes::{Buf, BufMut},
    encoding::{self, DecodeContext, WireType},
    DecodeError, Message, Oneof,
};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct DcapEvidence {
    pub quote: Option<Quote3<Vec<u8>>>,
    pub collateral: Option<Collateral>,
}

const TAG_DCAP_EVIDENCE_QUOTE3: u32 = 1;
const TAG_DCAP_EVIDENCE_COLLATERAL: u32 = 2;

impl Message for DcapEvidence {
    fn encode_raw<B>(&self, buf: &mut B)
    where
        B: BufMut,
        Self: Sized,
    {
        let quote_bytes: Vec<u8> = mc_util_serial::serialize(&self.quote).unwrap();
        encoding::bytes::encode(TAG_DCAP_EVIDENCE_QUOTE3, &quote_bytes, buf);
        let collateral_bytes: Vec<u8> = mc_util_serial::serialize(&self.collateral).unwrap();
        encoding::bytes::encode(TAG_DCAP_EVIDENCE_COLLATERAL, &collateral_bytes, buf);
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
            TAG_DCAP_EVIDENCE_QUOTE3 => {
                let mut vbuf = Vec::new();
                encoding::bytes::merge(wire_type, &mut vbuf, buf, ctx)?;
                let quote: Option<Quote3<Vec<u8>>> =
                    mc_util_serial::deserialize(vbuf.as_slice())
                        .map_err(|_| DecodeError::new("Failed to deserialize quote3 from bytes"))?;
                self.quote = quote;
                Ok(())
            }
            TAG_DCAP_EVIDENCE_COLLATERAL => {
                let mut vbuf = Vec::new();
                encoding::bytes::merge(wire_type, &mut vbuf, buf, ctx)?;
                let collateral: Option<Collateral> = mc_util_serial::deserialize(vbuf.as_slice())
                    .map_err(|_| {
                    DecodeError::new("Failed to deserialize collateral from bytes")
                })?;
                self.collateral = collateral;
                Ok(())
            }
            _ => encoding::skip_field(wire_type, tag, buf, ctx),
        }
    }

    fn encoded_len(&self) -> usize {
        let quote_bytes: Vec<u8> = mc_util_serial::serialize(&self.quote).unwrap();
        let collateral_bytes: Vec<u8> = mc_util_serial::serialize(&self.collateral).unwrap();

        encoding::bytes::encoded_len(TAG_DCAP_EVIDENCE_QUOTE3, &quote_bytes)
            + encoding::bytes::encoded_len(TAG_DCAP_EVIDENCE_COLLATERAL, &collateral_bytes)
    }

    fn clear(&mut self) {
        let default: DcapEvidence = Default::default();
        self.quote = default.quote;
        self.collateral = default.collateral;
    }
}

#[derive(Clone, Oneof)]
pub enum EvidenceKind {
    #[prost(message, tag = "4")]
    Dcap(DcapEvidence),
}

#[derive(Clone, prost::Message)]
pub struct EvidenceMessage {
    #[prost(oneof = "EvidenceKind", tags = "4")]
    pub of: Option<EvidenceKind>,
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
}
