// Copyright (c) 2018-2021 The MobileCoin Foundation

//! Attestation Verification Report handling

use alloc::vec;

use super::json::JsonValue;
use crate::{
    error::{
        IasQuoteError, IasQuoteResult, JsonError, NonceError, PseManifestError,
        PseManifestHashError, PseManifestResult, RevocationCause, VerifyError,
    },
    nonce::IasNonce,
    quote::{Quote, QuoteSignType},
    types::{
        epid_group_id::EpidGroupId, measurement::Measurement, pib::PlatformInfoBlob,
        report_data::ReportDataMask,
    },
};
use alloc::{
    string::{String, ToString},
    vec::Vec,
};
use binascii::{b64decode, b64encode, hex2bin};
use core::{
    convert::{TryFrom, TryInto},
    f64::EPSILON,
    fmt::Debug,
    intrinsics::fabsf64,
    result::Result,
    str,
};
use mc_crypto_digestible::Digestible;
use mc_util_encodings::{Error as EncodingError, FromBase64, FromHex, ToBase64};
use prost::{
    bytes::{Buf, BufMut},
    encoding::{self, DecodeContext, WireType},
    DecodeError, Message,
};
use serde::{Deserialize, Serialize};

// The lengths of the two EPID Pseudonym chunks
const EPID_PSEUDONYM_B_LEN: usize = 64;
const EPID_PSEUDONYM_K_LEN: usize = 64;
const EPID_PSEUDONYM_LEN: usize = EPID_PSEUDONYM_B_LEN + EPID_PSEUDONYM_K_LEN;

/// A linkable EPID signature, used to link a quote to a given piece of
/// hardware.
///
/// When using linkable quotes, the report from IAS will contain this
/// structure, encoded as base64 bytes. If a requester requests a host
/// attest again, the EpidPseudonym should be unchanged. Pseudonym
/// change detection can be used to warn a node operator that a peer's
/// hardware has changed. If this change is unexpected, this indicates
/// an area of inquiry for the operator to chase down.
//
// This (AFAICT) comes from the [EPID signature scheme](https://eprint.iacr.org/2009/095.pdf)
// [presentation](https://csrc.nist.gov/csrc/media/events/meeting-on-privacy-enhancing-cryptography/documents/brickell.pdf),
// "K = B**f", or "pseudonym = named_base ** machine_privkey".
//
// Per the IAS API documentation:
//
// > Byte array representing EPID Pseudonym that consists of the
// > concatenation of EPID B (64 bytes) & EPID K (64 bytes) components
// > of EPID signature. If two linkable EPID signatures for an EPID Group
// > have the same EPID Pseudonym, the two signatures were generated
// > using the same EPID private key. This field is encoded using Base 64
// > encoding scheme.
#[derive(Clone, Debug, Deserialize, Hash, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct EpidPseudonym {
    b: Vec<u8>,
    k: Vec<u8>,
}

impl Default for EpidPseudonym {
    /// Create a zeroed EpidPseudonym
    fn default() -> Self {
        EpidPseudonym {
            b: vec![0u8; EPID_PSEUDONYM_B_LEN],
            k: vec![0u8; EPID_PSEUDONYM_K_LEN],
        }
    }
}

impl FromBase64 for EpidPseudonym {
    type Error = EncodingError;

    /// Parse a Base64-encoded string into a 128-byte EpidPseudonym
    fn from_base64(src: &str) -> Result<Self, EncodingError> {
        let mut buffer = [0u8; EPID_PSEUDONYM_LEN + 4];
        let buflen = {
            let output = b64decode(src.as_bytes(), &mut buffer[..])?;
            output.len()
        };
        if buflen != EPID_PSEUDONYM_LEN {
            return Err(EncodingError::InvalidInputLength);
        }
        let (left, right) = buffer.split_at(buflen / 2);
        Ok(Self {
            b: Vec::from(left),
            k: Vec::from(right),
        })
    }
}

impl ToBase64 for EpidPseudonym {
    fn to_base64(&self, dest: &mut [u8]) -> Result<usize, usize> {
        if dest.len() < EPID_PSEUDONYM_LEN + 4 {
            Err(EPID_PSEUDONYM_LEN + 4)
        } else {
            let mut inbuf = Vec::with_capacity(self.b.len() + self.k.len());
            inbuf.extend_from_slice(&self.b);
            inbuf.extend_from_slice(&self.k);
            match b64encode(&inbuf, dest) {
                Ok(buffer) => Ok(buffer.len()),
                Err(_e) => Err(EPID_PSEUDONYM_LEN + 4),
            }
        }
    }
}

/// The parsed Attestation Verification Report Data, parsed from
/// VerificationReport.http_body JSON after signature and chain validation.
#[derive(Clone, Debug, Deserialize, PartialEq, PartialOrd, Serialize)]
pub struct VerificationReportData {
    /// A unique ID of this report
    pub id: String,
    /// The timestamp this report was generated, as an ISO8601 string.
    pub timestamp: String,
    /// The version number of the API which generated this report.
    pub version: f64, // ugh.
    /// The quote status
    pub quote_status: IasQuoteResult,
    /// The quote body minus the signature
    pub quote: Quote,
    /// An optional string explaining the quote revocation, if quote_error is
    /// GroupRevoked
    pub revocation_reason: Option<RevocationCause>,
    /// An optional error used to indicate the results of IAS checking the PSE
    /// manifest
    pub pse_manifest_status: Option<PseManifestResult>,
    /// The hash of the PSE manifest, if provided.
    pub pse_manifest_hash: Option<Vec<u8>>,
    /// PSW-provided opaque data
    pub platform_info_blob: Option<PlatformInfoBlob>,
    /// The IAS request nonce
    pub nonce: Option<IasNonce>,
    /// A unique hardware ID returned when a linkable quote is requested
    pub epid_pseudonym: Option<EpidPseudonym>,
    /// The advisory URL, if any
    pub advisory_url: Option<String>,
    /// The ID strings of the advisories which caused a non-OK status.
    pub advisory_ids: Vec<String>,
}

impl VerificationReportData {
    /// Verify our contents, but not the quote
    pub fn verify_data(
        &self,
        expected_version: f64,
        expected_ias_nonce: Option<&IasNonce>,
        expected_pse_manifest_hash: Option<&[u8]>,
    ) -> Result<(), VerifyError> {
        // Dumbest. Possible. Timeline.
        if unsafe { fabsf64(expected_version - self.version) } > EPSILON {
            return Err(VerifyError::VersionMismatch(expected_version, self.version));
        }

        // Check the IAS nonce
        if let Some(ias_nonce) = expected_ias_nonce {
            // If we expect a particular IAS nonce, we should have one, and
            // it should match.
            if ias_nonce != self.nonce.as_ref().ok_or(NonceError::Missing)? {
                return Err(NonceError::Mismatch.into());
            }
        }

        // Manifest hash is a simple sanity check
        if let Some(expected_hash) = expected_pse_manifest_hash {
            // If we expect one, and we either don't have one, or what we have
            // doesn't match, then return an error.
            if let Some(current_hash) = self.pse_manifest_hash.as_ref() {
                if current_hash.as_slice() != expected_hash {
                    return Err(PseManifestHashError::Mismatch.into());
                }
            } else {
                return Err(PseManifestHashError::Mismatch.into());
            }
        }

        // Result<Option<Result<(), PseManifestError>>, IasQuoteError>
        match &self.quote_status {
            Ok(pse_manifest_status)
            | Err(IasQuoteError::SwHardeningNeeded {
                pse_manifest_status,
                ..
            }) => match pse_manifest_status {
                Some(pse_result) => match pse_result {
                    Ok(()) => Ok(()),
                    Err(e) => Err(e.clone().into()),
                },
                None => Ok(()),
            },
            Err(e) => Err(e.clone().into()),
        }
    }

    /// Perform verification checks on a parsed report, consuming self
    pub fn verify(
        &self,
        expected_version: f64,
        expected_ias_nonce: Option<&IasNonce>,
        expected_pse_manifest_hash: Option<&[u8]>,
        expected_gid: Option<EpidGroupId>,
        expected_type: QuoteSignType,
        allow_debug: bool,
        expected_measurements: &[Measurement],
        expected_product_id: u16,
        minimum_security_version: u16,
        expected_data: &ReportDataMask,
    ) -> Result<(), VerifyError> {
        self.verify_data(
            expected_version,
            expected_ias_nonce,
            expected_pse_manifest_hash,
        )?;

        self.quote.verify(
            expected_gid,
            expected_type,
            allow_debug,
            expected_measurements,
            expected_product_id,
            minimum_security_version,
            expected_data,
        )?;

        Ok(())
    }

    /// Try and parse the timestamp string into a chrono object.
    pub fn parse_timestamp(&self) -> Result<chrono::DateTime<chrono::Utc>, VerifyError> {
        // Intel provides the timestamp as ISO8601 (compatible with RFC3339) but without
        // the Z specifier, which is required for chrono to be happy.
        let timestamp =
            chrono::DateTime::parse_from_rfc3339(&[self.timestamp.as_str(), "Z"].concat())
                .map_err(|err| {
                    VerifyError::TimestampParse(self.timestamp.clone(), err.to_string())
                })?;
        Ok(timestamp.into())
    }
}

impl<'src> TryFrom<&'src VerificationReport> for VerificationReportData {
    type Error = VerifyError;

    /// Parse the JSON contents of a VerificationReport into a
    /// VerificationReportData object
    fn try_from(src: &'src VerificationReport) -> Result<Self, VerifyError> {
        // Parse the JSON into a hashmap
        let (chars_parsed, data) = super::json::parse(src.http_body.trim());
        if data.is_none() {
            return Err(JsonError::NoData.into());
        }

        if chars_parsed < src.http_body.trim().len() {
            return Err(JsonError::IncompleteParse(chars_parsed).into());
        }

        let mut data = match data.unwrap() {
            JsonValue::Object(o) => o,
            _ => return Err(JsonError::RootNotObject.into()),
        };

        // Actually parse the JSON into real fields
        let id = data
            .remove("id")
            .ok_or_else(|| JsonError::FieldMissing("id".to_string()))?
            .try_into()?;
        let timestamp = data
            .remove("timestamp")
            .ok_or_else(|| JsonError::FieldMissing("timestamp".to_string()))?
            .try_into()?;
        let version = data
            .remove("version")
            .ok_or_else(|| JsonError::FieldMissing("version".to_string()))?
            .try_into()?;

        // Get the PIB, used in IasQuoteError, PseManifestError
        let platform_info_blob = match data.remove("platformInfoBlob") {
            Some(v) => {
                let value: String = v.try_into()?;
                Some(PlatformInfoBlob::from_hex(&value).map_err(|e| VerifyError::Pib(e.into()))?)
            }
            None => None,
        };
        // Get the (optional) revocation reason, used in IasQuoteError
        let revocation_reason = match data.remove("revocationReason") {
            Some(v) => {
                let value: f64 = v.try_into()?;
                RevocationCause::from_bits(value as u64)
            }
            None => None,
        };

        let advisory_url = data
            .remove("advisoryURL")
            .map(TryInto::<String>::try_into)
            .transpose()?;

        let advisory_ids = data
            .remove("advisoryIDs")
            .map(TryInto::<Vec<JsonValue>>::try_into)
            .transpose()?
            .unwrap_or_default()
            .into_iter()
            .map(TryInto::<String>::try_into)
            .collect::<Result<Vec<String>, JsonError>>()?;

        // Get the PSE manifest status (parsed here since it may be used by
        // IasQuoteError)
        let pse_manifest_status = match data.remove("pseManifestStatus") {
            Some(v) => {
                let value: String = v.try_into()?;
                Some(match value.as_str() {
                    "OK" => Ok(()),
                    "INVALID" => Err(PseManifestError::Invalid),
                    "OUT_OF_DATE" => {
                        Err(PseManifestError::OutOfDate(platform_info_blob.ok_or_else(
                            || JsonError::FieldMissing("platformInfoBlob".to_string()),
                        )?))
                    }
                    "REVOKED" => Err(PseManifestError::Revoked(platform_info_blob.ok_or_else(
                        || JsonError::FieldMissing("platformInfoBlob".to_string()),
                    )?)),
                    "RL_VERSION_MISMATCH" => Err(PseManifestError::RlVersionMismatch(
                        platform_info_blob.ok_or_else(|| {
                            JsonError::FieldMissing("platformInfoBlob".to_string())
                        })?,
                    )),
                    _ => Err(PseManifestError::Unknown),
                })
            }
            None => None, // when the request doesn't contain a manifest
        };

        // Parse the quote status
        let quote_status_str: String = data
            .remove("isvEnclaveQuoteStatus")
            .ok_or_else(|| JsonError::FieldMissing("isvEnclaveQuoteStatus".to_string()))?
            .try_into()?;
        let quote_status = match quote_status_str.as_str() {
            "OK" => Ok(pse_manifest_status.clone()),
            "SIGNATURE_INVALID" => Err(IasQuoteError::SignatureInvalid),
            "GROUP_REVOKED" => Err(IasQuoteError::GroupRevoked(
                revocation_reason
                    .ok_or_else(|| JsonError::FieldMissing("revocationReason".to_string()))?,
                platform_info_blob
                    .ok_or_else(|| JsonError::FieldMissing("platformInfoBlob".to_string()))?,
            )),
            "SIGNATURE_REVOKED" => Err(IasQuoteError::SignatureRevoked),
            "KEY_REVOKED" => Err(IasQuoteError::KeyRevoked),
            "SIGRL_VERSION_MISMATCH" => Err(IasQuoteError::SigrlVersionMismatch),
            "GROUP_OUT_OF_DATE" => Err(IasQuoteError::GroupOutOfDate {
                pse_manifest_status: pse_manifest_status.clone(),
                platform_info_blob: platform_info_blob
                    .ok_or_else(|| JsonError::FieldMissing("platformInfoBlob".to_string()))?,
                advisory_url: advisory_url
                    .clone()
                    .ok_or_else(|| JsonError::FieldMissing("advisoryURL".to_string()))?,
                advisory_ids: advisory_ids.clone(),
            }),
            "CONFIGURATION_NEEDED" => Err(IasQuoteError::ConfigurationNeeded {
                pse_manifest_status: pse_manifest_status.clone(),
                platform_info_blob: platform_info_blob
                    .ok_or_else(|| JsonError::FieldMissing("platformInfoBlob".to_string()))?,
                advisory_url: advisory_url
                    .clone()
                    .ok_or_else(|| JsonError::FieldMissing("advisoryURL".to_string()))?,
                advisory_ids: advisory_ids.clone(),
            }),
            "SW_HARDENING_NEEDED" => Err(IasQuoteError::SwHardeningNeeded {
                pse_manifest_status: pse_manifest_status.clone(),
                advisory_url: advisory_url
                    .clone()
                    .ok_or_else(|| JsonError::FieldMissing("advisoryURL".to_string()))?,
                advisory_ids: advisory_ids.clone(),
            }),
            "CONFIGURATION_AND_SW_HARDENING_NEEDED" => {
                Err(IasQuoteError::ConfigurationAndSwHardeningNeeded {
                    pse_manifest_status: pse_manifest_status.clone(),
                    platform_info_blob: platform_info_blob
                        .ok_or_else(|| JsonError::FieldMissing("platformInfoBlob".to_string()))?,
                    advisory_url: advisory_url
                        .clone()
                        .ok_or_else(|| JsonError::FieldMissing("advisoryURL".to_string()))?,
                    advisory_ids: advisory_ids.clone(),
                })
            }
            s => Err(IasQuoteError::Other(s.to_string())),
        };

        // Parse the quote body
        let quote = {
            let s: String = data
                .remove("isvEnclaveQuoteBody")
                .ok_or_else(|| JsonError::FieldMissing("isvEnclaveQuoteBody".to_string()))?
                .try_into()?;
            Quote::from_base64(&s)?
        };
        let pse_manifest_hash = match data.remove("pseManifestHash") {
            Some(v) => {
                let value: String = v.try_into()?;
                let mut result = Vec::with_capacity(value.len() * 3 / 4 + 4);
                let result_len = {
                    let result_slice = hex2bin(value.as_bytes(), &mut result)
                        .map_err(|e| PseManifestHashError::Parse(e.into()))?;
                    result_slice.len()
                };
                result.truncate(result_len);
                Some(result)
            }
            None => None,
        };
        let nonce = match data.remove("nonce") {
            Some(v) => {
                let value: String = v.try_into()?;
                Some(IasNonce::from_hex(&value).map_err(|e| VerifyError::Nonce(e.into()))?)
            }
            None => None,
        };
        let epid_pseudonym = match data.remove("epidPseudonym") {
            Some(v) => {
                let value: String = v.try_into()?;
                Some(
                    EpidPseudonym::from_base64(&value)
                        .map_err(|e| VerifyError::EpidPseudonym(e.into()))?,
                )
            }
            None => None,
        };

        Ok(Self {
            id,
            timestamp,
            version,
            quote_status,
            quote,
            revocation_reason,
            pse_manifest_status,
            pse_manifest_hash,
            platform_info_blob,
            nonce,
            epid_pseudonym,
            advisory_url,
            advisory_ids,
        })
    }
}

/// A type containing the bytes of the VerificationReport signature
#[derive(
    Clone, Debug, Default, Deserialize, Digestible, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize,
)]
#[repr(transparent)]
pub struct VerificationSignature(Vec<u8>);

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
        // base64 strlength = 4 * (bytelen / 3) + padding
        let mut data = vec![0u8; 3 * ((s.len() + 4) / 4)];
        let buflen = {
            let buffer = b64decode(s.as_bytes(), data.as_mut_slice())?;
            buffer.len()
        };
        data.truncate(buflen);
        Ok(VerificationSignature::from(data))
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
    #[prost(message, required)]
    pub sig: VerificationSignature,
    /// Attestation Report Signing Certificate Chain, as an array of
    /// DER-formatted bytes, from the X-IASReport-Signing-Certificate HTTP
    /// header.
    #[prost(bytes, repeated)]
    pub chain: Vec<Vec<u8>>,
    /// The raw report body JSON, as a byte sequence
    #[prost(string, required)]
    pub http_body: String,
}

#[cfg(test)]
mod test {
    extern crate std;

    use super::*;

    const IAS_WITH_PIB: &str = include_str!("../../data/test/ias_with_pib.json");

    #[test]
    fn test_verification_report_with_pib() {
        let report = VerificationReport {
            sig: VerificationSignature::default(),
            chain: Vec::default(),
            http_body: String::from(IAS_WITH_PIB.trim()),
        };

        let data = VerificationReportData::try_from(&report)
            .expect("Could not parse IAS verification report");

        let timestamp = data.parse_timestamp().expect("failed parsing timestamp");
        assert_eq!(timestamp.to_rfc3339(), "2019-06-19T22:11:17.616333+00:00");
    }

    #[test]
    #[should_panic(
        expected = "failed parsing timestamp: TimestampParse(\"invalid\", \"input contains invalid characters\")"
    )]
    fn test_parse_timestamp_with_invalid_timestamp() {
        let report = VerificationReport {
            sig: VerificationSignature::default(),
            chain: Vec::default(),
            http_body: String::from(IAS_WITH_PIB),
        };

        let mut data = VerificationReportData::try_from(&report)
            .expect("Could not parse IAS verification report");

        data.timestamp = "invalid".to_string();

        // This is expected to fail.
        let _timestamp = data.parse_timestamp().expect("failed parsing timestamp");
    }
}
