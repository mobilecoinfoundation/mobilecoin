// Copyright (c) 2018-2020 MobileCoin Inc.

//! Parsed IAS JSON contents

use crate::{
    json::{parse, Error as JsonError, Value},
    nonce::Nonce,
    pseudonym::EpidPseudonym,
    quote::Quote,
    report::Report,
};
use alloc::{
    borrow::ToOwned,
    collections::BTreeSet,
    string::{String, ToString},
    vec::Vec,
};
use bitflags::bitflags;
#[cfg(feature = "use_prost")]
use bytes::{Buf, BufMut};
use chrono::{DateTime, NaiveDateTime, Utc};
use core::{
    convert::{TryFrom, TryInto},
    fmt::{Debug, Display, Formatter, Result as FmtResult},
};
use displaydoc::Display;
use hex::FromHex;
use mc_sgx_epid_types::PlatformInfo;
use mc_util_encodings::{Error as EncodingError, FromBase64};
use mc_util_repr_bytes::ReprBytes;
#[cfg(feature = "use_prost")]
use prost::{
    encoding::{message, string, uint64, DecodeContext, WireType},
    DecodeError, Message,
};
use prost_types::Timestamp;
#[cfg(feature = "use_serde")]
use serde::{Deserialize, Serialize};

/// The protobuf tag number of the ID field
const TAG_ID: u32 = 1;
/// The protobuf tag number of the timestamp field
const TAG_TIMESTAMP: u32 = 2;
/// The protobuf tag number of the version field
const TAG_VERSION: u32 = 3;
/// The protobuf tag number of the platform info field
const TAG_PLATFORM_INFO: u32 = 4;
/// The protobuf tag number of the revocation cause field
const TAG_REVOCATION_REASON: u32 = 5;
/// The protobuf tag number of the manifest status field
const TAG_PSE_MANIFEST_STATUS: u32 = 6;
/// The protobuf tag number of the enclave quote status field
const TAG_ISV_ENCLAVE_QUOTE_STATUS: u32 = 7;
/// The protobuf tag number of the enclave quote body field
const TAG_ISV_ENCLAVE_QUOTE_BODY: u32 = 8;
/// The protobuf tag number of the PSE manifest hash field
const TAG_PSE_MANIFEST_HASH: u32 = 9;
/// The protobuf tag number of the nonce field
const TAG_NONCE: u32 = 10;
/// The protobuf tag number of the EPID pseudonym field
const TAG_EPID_PSEUDONYM: u32 = 11;
/// The protobuf tag number of the advisory URL field
const TAG_ADVISORY_URL: u32 = 12;
/// The protobuf tag number of the advisory IDs array field
const TAG_ADVISORY_IDS: u32 = 13;

/// A private trait used to encode our complex option/result stuff as IAS-JSON-compatible protobuf.
trait EncodeProtobuf {
    fn encode(&self, buf: &mut B);
}

/// An enumeration of Platform Services Enclave manifest errors returned by IAS
/// as part of the signed quote.
///
/// This is defined in the [IAS API v4, S4.2.1](https://api.trustedservices.intel.com/documents/sgx-attestation-api-spec.pdf).
#[cfg_attr(feature = "use_serde", derive(Deserialize, Serialize))]
#[derive(Clone, Debug, Display, Hash, Eq, Ord, PartialEq, PartialOrd)]
pub enum PseError {
    /// The PSE manifest provided was invalid
    Invalid,
    /// The PSE manifest is out of date
    OutOfDate(PlatformInfo),
    /// The PSE manifest signing key has been revoked, and must be updated
    Revoked(PlatformInfo),
    /// The PSE is using an out-of-date revocation list and must be updated
    RlVersionMismatch(PlatformInfo),
    /// The IAS server returned an unknown value: {0}
    Unknown(String),
}

/// The PSE manifest status
#[cfg_attr(feature = "use_serde", derive(Deserialize, Serialize))]
#[derive(Clone, Debug, Hash, Eq, Ord, PartialEq, PartialOrd)]
pub struct PseStatus {
    /// The PSE manifest hash
    pub hash: Vec<u8>,
    /// Any PSE manifest errors which occurred
    pub error: Option<PseError>,
}

impl PseStatus {
    pub fn from_ok(hash: Vec<u8>) -> Self {
        Self { hash, error: None }
    }

    pub fn from_err(hash: Vec<u8>, error: PseError) -> Self {
        Self {
            hash,
            error: Some(error),
        }
    }

    pub fn from_str<S: AsRef<str>>(
        value: &S,
        hash: Vec<u8>,
        platform_info: Option<&PlatformInfo>,
    ) -> Result<Self, ()> {
        match value.as_ref() {
            "OK" => Ok(PseStatus::from_ok(hash)),
            "INVALID" => Ok(PseStatus::from_err(hash, PseError::Invalid)),
            "OUT_OF_DATE" => {
                if let Some(pib) = platform_info {
                    Ok(PseStatus::from_err(
                        hash,
                        PseError::OutOfDate((*pib).clone()),
                    ))
                } else {
                    Err(())
                }
            }
            "REVOKED" => {
                if let Some(pib) = platform_info {
                    Ok(PseStatus::from_err(hash, PseError::Revoked((*pib).clone())))
                } else {
                    Err(())
                }
            }
            "RL_VERSION_MISMATCH" => {
                if let Some(pib) = platform_info {
                    Ok(PseStatus::from_err(
                        hash,
                        PseError::RlVersionMismatch((*pib).clone()),
                    ))
                } else {
                    Err(())
                }
            }
            other => Ok(PseStatus::from_err(
                hash,
                PseError::Unknown(other.to_owned()),
            )),
        }
    }
}

impl EncodeProtobuf for PlatformInfo {
    fn encode<B: BufMut>(&self, buf: &mut B) {
        string::encode(TAG_PLATFORM_INFO, &hex::encode(self.as_ref()), buf);
    }
}

impl EncodeProtobuf for Option<PseStatus> {
    fn encode<B: BufMut>(&self, buf: &mut B) {
        if let Some(status) = self {
            let strval = match status.error.as_ref() {
                None => "OK",
                Some(PseError::Invalid) => "INVALID",
                Some(PseError::OutOfDate(pib)) => {
                    pib.encode(buf);
                    "OUT_OF_DATE"
                },
                Some(PseError::Revoked(pib)) => {
                    pib.encode(buf);
                    "REVOKED"
                },
                Some(PseError::RlVersionMismatch(pib)) => {
                    pib.encode(buf);
                    "RL_VERSION_MISMATCH"
                },
                Some(PseError::Unknown(value)) => value.as_str(),
            };
            string::encode(TAG_PSE_MANIFEST_STATUS, &strval.to_owned(), buf);
            string::encode(TAG_PSE_MANIFEST_HASH, &hex::encode(&status.hash), buf);
        }
    }
}

/// The rust-friendly version of the IAS QuoteStatus field.
pub type QuoteResult = Result<Option<PseStatus>, QuoteError>;

impl EncodeProtobuf for QuoteResult {
    fn encode<B: BufMut>(&self, buf: &mut B) {
        if let Ok(pse_status) = &self {
            pse_status.encode_protobuf(mut);
        } else if let Err(quote_err) = &self {

        }
        if let Some(status) = self {
            let strval = match status.error.as_ref() {
                None => "OK",
                Some(PseError::Invalid) => "INVALID",
                Some(PseError::OutOfDate(_pib)) => "OUT_OF_DATE",
                Some(PseError::Revoked(_pib)) => "REVOKED",
                Some(PseError::RlVersionMismatch(_pib)) => "RL_VERSION_MISMATCH",
                Some(PseError::Unknown(value)) => value.as_str(),
            };
            string::encode(TAG_PSE_MANIFEST_STATUS, &strval.to_owned(), buf);
            string::encode(TAG_PSE_MANIFEST_HASH, &hex::encode(&status.hash), buf);
        }
    }
}

impl AsIasStr for QuoteResult {
    fn as_ias_str(&self) -> &str {
        match self {
            Ok(_pse_status) => "OK",
            Err(QuoteError::SignatureInvalid) => "SIGNATURE_INVALID",
            Err(QuoteError::GroupRevoked { .. }) => "GROUP_REVOKED",
            Err(QuoteError::SignatureRevoked(_cause)) => "SIGNATURE_REVOKED",
            Err(QuoteError::KeyRevoked(_cause)) => "KEY_REVOKED",
            Err(QuoteError::SigrlVersionMismatch) => "SIGRL_VERSION_MISMATCH",
            Err(QuoteError::GroupOutOfDate { .. }) => "GROUP_OUT_OF_DATE",
            Err(QuoteError::ConfigurationNeeded { .. }) => "CONFIGURATION_NEEDED",
            Err(QuoteError::SwHardeningNeeded { .. }) => "SW_HARDENING_NEEDED",
            Err(QuoteError::ConfigurationAndSwHardeningNeeded { .. }) => {
                "CONFIGURATION_AND_SW_HARDENING_NEEDED"
            }
            Err(QuoteError::Other(value)) => value.as_str(),
        }
    }
}

bitflags! {
    /// Revocation cause flags
    #[cfg_attr(feature = "use_serde", derive(Deserialize, Serialize))]
    pub struct RevocationCause: u64 {
        /// Cause reason was not given (but still revoked)
        const UNSPECIFIED = 0;
        /// The private key for the EPID was compromised
        const KEY_COMPROMISE = 1;
        /// The CA which signed the EPID key was compromised
        const CERT_AUTHORITY_COMPROMISE = 1 << 1;
        /// X509-specific, probably never used in our environment
        const AFFILIATION_CHANGED = 1 << 2;
        /// The EPID group key has been replaced with a new key.
        ///
        /// Probably never used in our environment, unless you can replace EPID keys via microcode update...
        const SUPERSEDED = 1 << 3;
        /// Nothing should still be using the cert in question, but there's no indication it was
        /// compromised. Probably never used in our environment
        const CESSATION_OF_OPERATION = 1 << 4;
        /// Indicates a certificate should not be trusted right now, but may be deemed trustworthy
        /// again, in the future.
        ///
        /// This will probably never be used in our environment.
        const CERTIFICATE_HOLD = 1 << 5;
        /// Used to remove a certificate from a CRL via deltaCRL.
        ///
        /// This would be done to lift a certificateHold, or remove an expired cert from a CRL, and probably never used in our
        /// environment.
        const REMOVE_FROM_CRL = 1 << 6;
        /// X509-specific, indicates that the cert was revoked because a keyUsage-like attribute was
        /// changed. Probably never used in our environment
        const PRIVILEGE_WITHDRAWN = 1 << 7;
        /// The CA delegated the ability to publish CRLs to another authority, but that authority was
        /// compromised
        const ATTRIBUTE_AUTHORITY_COMPROMISE = 1 << 8;
    }
}

impl Display for RevocationCause {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        let mut strings = Vec::new();
        if self.contains(RevocationCause::UNSPECIFIED) {
            strings.push("Unspecified");
        }
        if self.contains(RevocationCause::KEY_COMPROMISE) {
            strings.push("Key compromise");
        }
        if self.contains(RevocationCause::CERT_AUTHORITY_COMPROMISE) {
            strings.push("Certificate authority compromise");
        }
        if self.contains(RevocationCause::AFFILIATION_CHANGED) {
            strings.push("Affiliation changed");
        }
        if self.contains(RevocationCause::SUPERSEDED) {
            strings.push("Superseded");
        }
        if self.contains(RevocationCause::CESSATION_OF_OPERATION) {
            strings.push("Cessation of operation")
        }
        if self.contains(RevocationCause::CERTIFICATE_HOLD) {
            strings.push("Certificate hold");
        }
        if self.contains(RevocationCause::REMOVE_FROM_CRL) {
            strings.push("Removed from revocation list");
        }
        if self.contains(RevocationCause::PRIVILEGE_WITHDRAWN) {
            strings.push("Privilege withdrawn");
        }
        if self.contains(RevocationCause::ATTRIBUTE_AUTHORITY_COMPROMISE) {
            strings.push("Attribute authority compromise");
        }

        write!(f, "{}", strings.join(", "))
    }
}

/// An enumeration of errors returned by IAS as part of the signed quote.
///
/// This is defined in the [IAS API v6, S4.2.1](https://software.intel.com/sites/default/files/managed/7e/3b/ias-api-spec.pdf).
#[cfg_attr(feature = "use_serde", derive(Deserialize, Serialize))]
#[derive(Clone, Debug, Display, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum QuoteError {
    /// EPID signature of the ISV enclave QUOTE was invalid
    SignatureInvalid,

    /// The SigRL used for the quote is out of date
    SigrlVersionMismatch,

    /// The EPID group has been revoked: {cause}
    GroupRevoked {
        cause: RevocationCause,
        platform_info: PlatformInfo,
    },

    /// The EPID private key used to sign the QUOTE has been revoked by signature: {0}
    SignatureRevoked(RevocationCause),

    /// The EPID private key used to sign the QUOTE has been directly revoked (not by signature): {0}
    KeyRevoked(RevocationCause),

    /// The TCB level of the SGX platform must be updated to mitigate {", ".join(advisory_ids)}, see {advisory_url}
    GroupOutOfDate {
        /// The PSE status
        pse_status: Option<PseStatus>,
        /// The platform info blob which can bring the group into compliance
        platform_info: PlatformInfo,
        /// The string URL of the advisory website
        url: String,
        /// A set of string IDs for advisories affecting this platform
        ids: BTreeSet<String>,
    },

    /// The enclave requires configuration changes to mitigate {", ".join(ids)}, see {url}
    ConfigurationNeeded {
        /// The PSE status
        pse_status: Option<PseStatus>,
        /// The platform info blob indicating the presence of updates
        platform_info: PlatformInfo,
        /// The string URL of the advisory website
        url: String,
        /// A set of string IDs for advisories affecting this platform
        ids: BTreeSet<String>,
    },

    /// The enclave requires software mitigation for {", ".join(ids)}, see {url}
    SwHardeningNeeded {
        /// The PSE status
        pse_status: Option<PseStatus>,
        /// The string URL of the advisory website
        url: String,
        /// A set of string IDs for advisories affecting this platform
        ids: BTreeSet<String>,
    },

    /// The enclave requires configuration changes and software mitigation for {", ".join(advisory_ids)}, see {advisory_url}
    ConfigurationAndSwHardeningNeeded {
        /// The PSE status
        pse_status: Option<PseStatus>,
        /// The platform info blob indicating the presence of updates
        platform_info: PlatformInfo,
        /// The string URL of the advisory website
        url: String,
        /// A set of string IDs for advisories affecting this platform
        ids: BTreeSet<String>,
    },

    /// Unknown error: {0}
    Other(String),
}

/// An enumeration of report parsing errors
#[cfg_attr(feature = "use_serde", derive(Deserialize, Serialize))]
#[derive(Clone, Debug, Display, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum Error {
    /// The JSON data could not be parsed: {0}
    Json(JsonError),
    /// The timestamp could not be parsed: {0}
    Timestamp(String),
    /// The platform info could not be decoded: {0}
    PlatformInfo(EncodingError),
    /// The query nonce could not be parsed: {0}
    Nonce(String),
    /// The quote data could not be parsed: {0}
    Quote(EncodingError),
    /// The PSE manifest could not be parsed: {0}
    PseManifest(String),
    /// The EPID pseudonym could not be parsed: {0}
    EpidPseudonym(String),
}

impl From<JsonError> for Error {
    fn from(src: JsonError) -> Error {
        Error::Json(src)
    }
}

/// The parsed Attestation Verification Report Data.
///
/// This is parsed from the [`Report`] after signature and cert validation has succeeded.
#[cfg_attr(feature = "use_serde", derive(Deserialize, Serialize))]
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ReportBody {
    /// A unqiue ID of this report.
    pub id: String,

    /// The timestamp this report was generated.
    pub timestamp: DateTime<Utc>,

    /// The version number of the API which generated this report.
    pub version: u64,

    /// The quote status.
    pub quote_result: QuoteResult,

    /// The quote body minus the signature.
    pub quote: Quote,

    /// The IAS request nonce.
    pub nonce: Option<Nonce>,

    /// A unique hardware ID returned when a linkable quote is requested.
    pub epid_pseudonym: Option<EpidPseudonym>,
}

impl ReportBody {
    fn unwrap_opt<T: Sized>(src: Option<T>, name: &str) -> Result<T, JsonError> {
        src.ok_or_else(|| JsonError::FieldMissing(name.to_owned()))
    }
}

#[cfg(feature = "use_prost")]
impl Message for ReportBody {
    fn encode_raw<B>(&self, buf: &mut B)
    where
        B: BufMut,
        Self: Sized,
    {
        string::encode(TAG_ID, &self.id, buf);

        let naive = self.timestamp.naive_utc();
        let timestamp = Timestamp {
            seconds: naive.timestamp(),
            nanos: naive.timestamp_subsec_nanos() as i32,
        };
        message::encode(TAG_TIMESTAMP, &timestamp, buf);

        uint64::encode(TAG_VERSION, &self.version, buf);

        self.quote_result.encode(buf);

        let quote_bytes = self.quote.to_bytes();
        let quote_base64 = base64::encode_config(&quote_bytes, base64::STANDARD);
        string::encode(TAG_ISV_ENCLAVE_QUOTE_BODY, &quote_base64, buf);

        if let Some(nonce) = &self.nonce {
            string::encode(TAG_NONCE, &hex::encode(nonce), buf);
        }

        if let Some(epid_pseudonym) = &self.epid_pseudonym {
            string::encode(
                TAG_EPID_PSEUDONYM,
                &base64::encode_config(epid_pseudonym.as_ref(), base64::STANDARD),
                buf,
            );
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
        unimplemented!()
    }

    fn encoded_len(&self) -> usize {
        unimplemented!()
    }

    fn clear(&mut self) {
        unimplemented!()
    }
}

impl<'src> TryFrom<&'src Report> for ReportBody {
    type Error = Error;

    /// Parse the JSON contents of a VerificationReport into a
    /// VerificationReportData object
    fn try_from(src: &'src Report) -> Result<Self, Error> {
        // Parse the JSON into a hashmap
        let (chars_parsed, data) = parse(&src.http_body);
        if data.is_none() {
            return Err(JsonError::NoData.into());
        }

        if chars_parsed < src.http_body.len() {
            return Err(JsonError::IncompleteParse(chars_parsed).into());
        }

        let mut data = match data.unwrap() {
            Value::Object(o) => o,
            _ => return Err(JsonError::RootNotObject.into()),
        };

        // Actually parse the JSON into real fields
        let id = data
            .remove("id")
            .ok_or_else(|| JsonError::FieldMissing("id".to_owned()))?
            .try_into()?;
        let string_timestamp: String = data
            .remove("timestamp")
            .ok_or_else(|| JsonError::FieldMissing("timestamp".to_owned()))?
            .try_into()?;
        let naive_timestamp = NaiveDateTime::parse_from_str(&string_timestamp, "%Y-%m-%d %H:%M:%S")
            .map_err(|e| Error::Timestamp(e.to_string()))?;
        let timestamp = DateTime::from_utc(naive_timestamp, Utc);
        let version = data
            .remove("version")
            .ok_or_else(|| JsonError::FieldMissing("version".to_owned()))?
            .try_into()?;

        // Get the PIB, used in QuoteError, PseManifestError
        let platform_info: Option<PlatformInfo> = data
            .remove("platformInfoBlob")
            .map(TryInto::<String>::try_into)
            .transpose()?
            .map(|value| PlatformInfo::from_hex(&value).map_err(Error::PlatformInfo))
            .transpose()?;

        // Get the (optional) revocation reason, used in QuoteError
        let cause = data
            .remove("revocationReason")
            .map(TryInto::<u64>::try_into)
            .transpose()?
            .map(|v| RevocationCause::from_bits(v as u64))
            .flatten();

        // PSW manifest hash
        let pse_hash = data
            .remove("pseManifestHash")
            .map(TryInto::<String>::try_into)
            .transpose()?
            .map(|value| hex::decode(&value).map_err(|err| Error::PseManifest(err.to_string())))
            .transpose()?;

        // Get the PSE manifest status, used later
        //
        // 1. Start with Option<Value>
        // 2. TryInto<String> -> Option<Result<String, JsonError>>
        // 3. transpose() -> Result<Option<String>, JsonError>
        // 4. ? operator -> Option<String>
        // 5. map() -> Option<Result<PseStatus, JsonError>
        // 6. transpose -> Result<Option<PseStatus>, JsonError>
        // 7. ? operator() - Option<PseStatus>
        let pse_status = data
            .remove("pseManifestStatus")
            .map(TryInto::<String>::try_into)
            .transpose()?
            .map(|value| {
                if let Some(pse_hash) = pse_hash {
                    PseStatus::from_str(&value, pse_hash, platform_info.as_ref())
                        .map_err(|_e| JsonError::FieldMissing("platformInfoBlob".to_owned()))
                } else {
                    Err(JsonError::FieldMissing("pseManifestHash".to_owned()))
                }
            })
            .transpose()?;

        let url = data
            .remove("advisoryURL")
            .map(TryInto::<String>::try_into)
            .transpose()?;

        let ids = data
            .remove("advisoryIDs")
            .map(TryInto::<Vec<Value>>::try_into)
            .transpose()?
            .map(|ids| {
                ids.into_iter()
                    .map(TryInto::<String>::try_into)
                    .collect::<Result<BTreeSet<String>, JsonError>>()
            })
            .transpose()?
            .unwrap_or_default();

        // 1. Start with Option<Value>
        // 2. TryInto<String> -> Option<Result<String, JsonError>>
        // 3. transpose() -> Result<Option<String>, JsonError>
        // 4. ? operator -> Option<String>
        // 4. ok_or_else() -> Result<String, Error>
        // 5. and_then() -> Result<Result<Option<PseStatus>, QuoteError>, Error>
        // 6. ? operator -> Result<Option<PseStatus>, QuoteError> (aka QuoteResult)
        let quote_result = data
            .remove("isvEnclaveQuoteStatus")
            .map(TryInto::<String>::try_into)
            .transpose()?
            .ok_or_else(|| Error::Json(JsonError::FieldMissing("isvEnclaveQuoteStatus".to_owned())))
            .and_then(|quote_status_str| match quote_status_str.as_ref() {
                "OK" => Ok(Ok(pse_status.clone())),
                "SIGNATURE_INVALID" => Ok(Err(QuoteError::SignatureInvalid)),
                "GROUP_REVOKED" => Ok(Err(QuoteError::GroupRevoked {
                    cause: Self::unwrap_opt(cause, "revocationReason")?,
                    platform_info: Self::unwrap_opt(platform_info, "platformInfoBlob")?,
                })),
                "SIGNATURE_REVOKED" => Ok(Err(QuoteError::SignatureRevoked(Self::unwrap_opt(
                    cause,
                    "revocationReason",
                )?))),
                "KEY_REVOKED" => Ok(Err(QuoteError::KeyRevoked(Self::unwrap_opt(
                    cause,
                    "revocationReason",
                )?))),
                "SIGRL_VERSION_MISMATCH" => Ok(Err(QuoteError::SigrlVersionMismatch)),
                "GROUP_OUT_OF_DATE" => Ok(Err(QuoteError::GroupOutOfDate {
                    pse_status,
                    platform_info: Self::unwrap_opt(platform_info, "platformInfoBlob")?,
                    url: Self::unwrap_opt(url, "advisoryURL")?,
                    ids,
                })),
                "CONFIGURATION_NEEDED" => Ok(Err(QuoteError::ConfigurationNeeded {
                    pse_status,
                    platform_info: Self::unwrap_opt(platform_info, "platformInfoBlob")?,
                    url: Self::unwrap_opt(url, "advisoryURL")?,
                    ids,
                })),
                "SW_HARDENING_NEEDED" => Ok(Err(QuoteError::SwHardeningNeeded {
                    pse_status,
                    url: Self::unwrap_opt(url, "advisoryURL")?,
                    ids,
                })),
                "CONFIGURATION_AND_SW_HARDENING_NEEDED" => {
                    Ok(Err(QuoteError::ConfigurationAndSwHardeningNeeded {
                        pse_status,
                        platform_info: Self::unwrap_opt(platform_info, "platformInfoBlob")?,
                        url: Self::unwrap_opt(url, "advisoryURL")?,
                        ids,
                    }))
                }
                s => Ok(Err(QuoteError::Other(s.to_owned()))),
            })?;

        // Parse the quote body
        let quote = data
            .remove("isvEnclaveQuoteBody")
            .map(TryInto::<String>::try_into)
            .transpose()?
            .map(|string_value| Quote::from_base64(&string_value).map_err(Error::Quote))
            .transpose()?
            .ok_or_else(|| JsonError::FieldMissing("isvEnclaveQuoteBody".to_owned()))?;

        // Nonce
        let nonce = data
            .remove("nonce")
            .map(TryInto::<String>::try_into)
            .transpose()?
            .map(|value| Nonce::from_hex(&value).map_err(|err| Error::Nonce(err.to_string())))
            .transpose()?;

        // EPID pseudonym
        let epid_pseudonym = data
            .remove("epidPseudonym")
            .map(TryInto::<String>::try_into)
            .transpose()?
            .map(|value| {
                EpidPseudonym::from_base64(&value)
                    .map_err(|err| Error::EpidPseudonym(err.to_string()))
            })
            .transpose()?;

        Ok(Self {
            id,
            timestamp,
            version,
            quote_result,
            quote,
            nonce,
            epid_pseudonym,
        })
    }
}
