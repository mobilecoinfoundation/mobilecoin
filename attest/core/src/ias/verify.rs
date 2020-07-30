// Copyright (c) 2018-2020 MobileCoin Inc.

//! Attestation Verification Report handling

use alloc::vec;

use super::json::JsonValue;
use crate::{
    error::{
        IasQuoteError, IasQuoteResult, JsonError, NonceError, PseManifestError,
        PseManifestHashError, PseManifestResult, RevocationCause, SignatureError, VerifyError,
    },
    nonce::IasNonce,
    quote::{Quote, QuoteSignType},
    types::{
        epid_group_id::EpidGroupId, measurement::Measurement, pib::PlatformInfoBlob,
        report_data::ReportDataMask,
    },
    IAS_SIGNING_ROOT_CERT_PEMS, IAS_VERSION,
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
use digest::Digest;
use mbedtls::{
    hash, pk,
    x509::{Certificate, Profile},
};
use mc_util_encodings::{Error as EncodingError, FromBase64, FromHex, ToBase64};
use prost::{
    bytes::{Buf, BufMut},
    encoding::{self, DecodeContext, WireType},
    DecodeError, Message,
};
use serde::{Deserialize, Serialize};
use sha2::Sha256;

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
        if buflen < EPID_PSEUDONYM_LEN {
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
    /// A unqiue ID of this report
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
#[derive(Clone, Debug, Default, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[repr(transparent)]
pub struct VerificationSignature(Vec<u8>);

impl AsRef<[u8]> for VerificationSignature {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl From<Vec<u8>> for VerificationSignature {
    fn from(src: Vec<u8>) -> Self {
        Self(src)
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

/// Arbitrary maximum depth for certificate chains
const MAX_CHAIN_DEPTH: usize = 5;

/// Container for holding the quote verification sent back from IAS.
///
/// The fields correspond to the data sent from IAS in the
/// [Attestation Verification Report](https://software.intel.com/sites/default/files/managed/7e/3b/ias-api-spec.pdf).
///
/// This structure is supposed to be filled in from the results of an IAS
/// web request and then validated directly or serialized into an enclave for
/// validation.
#[derive(Clone, Deserialize, Eq, Hash, Message, Ord, PartialEq, PartialOrd, Serialize)]
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

impl VerificationReport {
    /// A method to validate the signature of a verification report,
    /// and ensure the signatory is rooted in a trust anchor.
    pub fn verify_signature(
        &self,
        trust_anchors: Option<Vec<String>>,
    ) -> Result<(), SignatureError> {
        // Here's the background information for this code:
        //
        //  1. An X509 certificate can be signed by only one issuer.
        //  2. mbedtls' certificates-list API demands certs in the RFC5246
        //     order (endpoint cert first, every other cert signed the
        //     cert preceeding it in the list).
        //  3. I don't recall Intel's specification mentioning certificate
        //     ordering at all (meaning they can change it w/o warning).
        //  4. mbedtls' certificates-list API isn't actually exposed to us,
        //     anyways.
        //
        // As a result, we need to find the cert which signed the data (this
        // doubles as the signature check), then find a way back up the
        // derived chain until we either hit a max-height limit (and fail),
        // or top out at something that was itself signed by a trust_anchor.
        //
        // If we have the root CA that's in our trust_anchor list in the
        // provided chain, then it will pass the "signed by trust_anchor"
        // check, because all root CAs are self-signed by definition.
        //
        // If Intel doesn't provide the root CA in the chain, then the last
        // entry in the derived chain will still contain the intermediate CA,
        // which will (obviously) be signed by the root CA. Combined, these
        // two situations mean checking that the last cert in the list was
        // signed by a trust anchor will result in success.
        //
        // The third possible scenario, which is that one of the certs in the
        // middle of the chain is in our trust_anchors list. In this case, our
        // explicit trust of a cert makes any other issuer relationships
        // irrelevant, including relationships with blacklisted issuers.
        //
        // This scenario is less likely, but would occur when someone is
        // trying to deprecate an existing authority in favor of a new one. In
        // this case, they sign the old CA with the new CA, so things which
        // trust the new CA also trust the old CA "for free". When everyone
        // has the new CA in their trust list, they start issuing certs from
        // the new CA, and stop renewing certs from the old CA. The old CA is
        // gradually phased out of use as the certs it issued expire, and is
        // eventually allowed to expire itself, or revoked by the new CA.
        //
        // As a result, if any pubkey in the actual chain matches the pubkey
        // of a trust anchor, then we can consider the actual chain trusted.
        //
        // Lastly, it's possible that Intel provides multiple complete chains
        // terminating at different root CAs. That is, the signature is tied
        // to pubkey X, but there are multiple leaf certificates in the
        // provided certs for pubkey X, and each one has its own path back to
        // a trust anchor.

        if self.chain.is_empty() {
            return Err(SignatureError::NoCerts);
        }

        // Construct a verification profile for what kind of X509 chain we
        // will support
        let profile = Profile::new(
            vec![hash::Type::Sha256, hash::Type::Sha384, hash::Type::Sha512],
            vec![pk::Type::Rsa, pk::Type::Ecdsa],
            vec![
                pk::EcGroupId::Curve25519,
                pk::EcGroupId::SecP256K1,
                pk::EcGroupId::SecP256R1,
                pk::EcGroupId::SecP384R1,
                pk::EcGroupId::SecP521R1,
            ],
            2048,
        );

        // Load default anchors if none provided.
        let mut trust_anchors: Vec<Certificate> = if let Some(trust_anchors) = trust_anchors {
            trust_anchors
                .iter()
                .filter_map(|pem| Certificate::from_pem(pem.as_bytes()).ok())
                .collect()
        } else {
            IAS_SIGNING_ROOT_CERT_PEMS
                .iter()
                .filter_map(|pem| Certificate::from_pem(pem.as_bytes()).ok())
                .collect()
        };

        // Intel uses rsa-sha256 as their signature algorithm, which means
        // the signature is actually over the sha256 hash of the data, not
        // the data itself. mbedtls is primitive enough that we need to do
        // these steps ourselves.
        let hash = Sha256::digest(self.http_body.as_bytes());

        let parsed_chain: Vec<Certificate> = self
            .chain
            .iter()
            .filter_map(|maybe_der_bytes| Certificate::from_der(maybe_der_bytes).ok())
            .collect();

        parsed_chain
            .iter()
            // First, find any certs for the signer pubkey
            .filter_map(|src_cert| {
                let mut newcert = src_cert.clone();
                newcert
                    .public_key_mut()
                    .verify(hash::Type::Sha256, hash.as_slice(), self.sig.as_ref())
                    .and(Ok(newcert))
                    .ok()
            })
            // Then construct a set of chains, one for each signer certificate
            .filter_map(|cert| {
                let mut signer_chain: Vec<Certificate> = Vec::new();
                signer_chain.push(cert);
                'outer: loop {
                    // Exclude any signing changes greater than our max depth
                    if signer_chain.len() > MAX_CHAIN_DEPTH {
                        return None;
                    }

                    for chain_cert in &parsed_chain {
                        let mut chain_cert = chain_cert.clone();
                        let existing_cert = signer_chain
                            .last_mut()
                            .expect("Somehow our per-signer chain was empty");
                        if existing_cert.public_key_mut().write_public_der_vec()
                            != chain_cert.public_key_mut().write_public_der_vec()
                            && existing_cert
                                .verify_with_profile(&mut chain_cert, None, Some(&profile), None)
                                .is_ok()
                        {
                            signer_chain.push(chain_cert);
                            continue 'outer;
                        }
                    }

                    break;
                }
                Some(signer_chain)
            })
            // Then see if any of those chains are connected to a trust anchor
            .find_map(|mut signer_chain| {
                let signer_toplevel = signer_chain
                    .last_mut()
                    .expect("Signer chain was somehow emptied before use.");
                // First, check if the last element in the chain is signed by a trust anchor
                for cacert in &mut trust_anchors {
                    if signer_toplevel
                        .verify_with_profile(cacert, None, Some(&profile), None)
                        .is_ok()
                    {
                        return Some(());
                    }
                }

                // Otherwise, check if any of the pubkeys in the chain are a trust anchor
                for cert in &mut signer_chain {
                    for cacert in &mut trust_anchors {
                        if cert.public_key_mut().write_public_der_vec()
                            == cacert.public_key_mut().write_public_der_vec()
                        {
                            return Some(());
                        }
                    }
                }
                None
            })
            .ok_or(SignatureError::BadSignature)
    }

    /// Wrap up all the relevant validity checks against the this report
    /// and it's parsed contents.
    ///
    /// This method is a convenience to allow us to check signatures,
    /// parse the JSON, check the data, including the quote body inside
    /// the data.
    pub fn verify(
        &self,
        trust_anchors: Option<Vec<String>>,
        expected_ias_nonce: Option<&IasNonce>,
        expected_pse_manifest_hash: Option<&[u8]>,
        expected_gid: Option<EpidGroupId>,
        expected_type: QuoteSignType,
        allow_debug: bool,
        expected_measurements: &[Measurement],
        expected_product_id: u16,
        minimum_security_version: u16,
        expected_data: &ReportDataMask,
    ) -> Result<VerificationReportData, VerifyError> {
        // Check signature
        self.verify_signature(trust_anchors)?;

        // Parse the JSON
        let report_data: VerificationReportData = self.try_into()?;

        // Check the report contains
        report_data.verify(
            IAS_VERSION,
            expected_ias_nonce,
            expected_pse_manifest_hash,
            expected_gid,
            expected_type,
            allow_debug,
            expected_measurements,
            expected_product_id,
            minimum_security_version,
            expected_data,
        )?;

        Ok(report_data)
    }
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
