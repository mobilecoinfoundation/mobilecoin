// Copyright (c) 2018-2020 MobileCoin Inc.

//! Parsed IAS JSON contents

use crate::{
    json::{parse, Error as JsonError, Value},
    nonce::Nonce,
    pseudonym::EpidPseudonym,
    quote::{Error as ParseQuoteError, Quote},
    report::Report as IasReport,
};
use alloc::{borrow::ToOwned, collections::BTreeSet, string::String, vec::Vec};
use base64::DecodeError;
use bitflags::bitflags;
use chrono::{DateTime, NaiveDateTime, ParseError as ChronoError, Utc};
use core::{
    convert::{TryFrom, TryInto},
    fmt::Debug,
};
use displaydoc::Display;
use hex::{decode, FromHex, FromHexError};
use mc_sgx_epid_types::PlatformInfo;
use mc_util_encodings::{Error as EncodingError, FromBase64, FromHex as EncodingFromHex};
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// A PSE manifest status
pub type PseManifestResult = Result<(), PseManifestError>;

/// An enumeration of Platform Services Enclave manifest errors returned by IAS
/// as part of the signed quote.
///
/// This is defined in the [IAS API v4, S4.2.1](https://api.trustedservices.intel.com/documents/sgx-attestation-api-spec.pdf).
#[cfg_attr(feature = "serde", derive(Deserialize, Serialize))]
#[derive(Clone, Debug, Display, Hash, Eq, Ord, PartialEq, PartialOrd)]
pub enum PseManifestError {
    /// Security properties of the PSW cannot be verified due to unrecognized PSE Manifest
    Unknown,
    /// Security properties of the PSW are invalid
    Invalid,
    /// TCB level of PSW is outdated but not identified as compromised
    OutOfDate(PlatformInfo),
    /// Hardware/firmware component involved in the PSW has been revoked
    Revoked(PlatformInfo),
    /// The PSW revocation list is out of date, use the included PIB to force an update
    RlVersionMismatch(PlatformInfo),
    /// The PSE status was not returned by IAS
    Missing,
}

/// The rust-friendly version of the IAS QuoteStatus field.
pub type QuoteResult = Result<Option<PseManifestResult>, QuoteError>;

bitflags! {
    /// Revocation cause flags
    #[cfg_attr(feature = "serde", derive(Deserialize, Serialize))]
    pub struct RevocationCause: u64 {
        /// Cause reason was not given (but still revoked)
        const UNSPECIFIED = 0;
        /// The private key for the EPID was compromised
        const KEY_COMRPOMISE = 1;
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

/// An enumeration of errors returned by IAS as part of the signed quote.
///
/// This is defined in the [IAS API v6, S4.2.1](https://software.intel.com/sites/default/files/managed/7e/3b/ias-api-spec.pdf).
#[cfg_attr(feature = "serde", derive(Deserialize, Serialize))]
#[derive(Clone, Debug, Display, Hash, Eq, Ord, PartialEq, PartialOrd)]
pub enum QuoteError {
    /// EPID signature of the ISV enclave QUOTE was invalid
    SignatureInvalid,

    /// The EPID group has been revoked. See RevocationCause
    GroupRevoked(RevocationCause, PlatformInfo),

    /// The EPID private key used to sign the QUOTE has been revoked by signature
    SignatureRevoked,

    /// The EPID private key used to sign the QUOTE has been directly revoked (not by signature)
    KeyRevoked,

    /// The SigRL used for the quote is out of date
    SigrlVersionMismatch,

    /// The TCB level of the SGX platform is out of date
    GroupOutOfDate(Option<PseManifestResult>, PlatformInfo),

    /// The enclave requires additional BIOS configuration
    ConfigurationNeeded(Option<PseManifestResult>, PlatformInfo),

    /// The enclave requires software mitigation
    SwHardeningNeeded(Option<PseManifestResult>),

    /// The enclave requires additional BIOS configuration and software mitigation
    ConfigurationAndSwHardeningNeeded(Option<PseManifestResult>, PlatformInfo),

    /// Unknown error: {0}
    Other(String),
}

pub enum Error {
    Json(JsonError),
    Timestamp(ChronoError),
    PlatformInfo(EncodingError),
    Nonce(FromHexError),
    Quote(ParseQuoteError),
    PseManifest(FromHexError),
    EpidPseudonym(DecodeError),
}

impl From<JsonError> for Error {
    fn from(src: JsonError) -> Error {
        Error::Json(src)
    }
}

impl From<ParseQuoteError> for Error {
    fn from(src: ParseQuoteError) -> Error {
        Error::Quote(src)
    }
}

/// The parsed Attestation Verification Report Data, parsed from Report.http_body JSON after
/// signature and cert validation.
#[cfg_attr(feature = "serde", derive(Deserialize, Serialize))]
#[derive(Clone, Debug, PartialEq, PartialOrd)]
pub struct Report {
    /// A unqiue ID of this report.
    pub id: String,

    /// The timestamp this report was generated, as the duration since time::SystemTime::UNIX_EPOCH
    // FIXME: It would be nice to parse this into something useful, but it's not usable at this time
    pub timestamp: DateTime<Utc>,

    /// The version number of the API which generated this report.
    pub version: f64,

    /// The quote status.
    pub quote_status: QuoteResult,

    /// The quote body minus the signature.
    pub quote: Quote,

    /// An optional string explaining the quote revocation, if quote_error is GroupRevoked.
    pub revocation_reason: Option<RevocationCause>,

    /// An optional error used to indicate the results of IAS checking the PSE manifest.
    pub pse_manifest_status: Option<PseManifestResult>,

    /// The hash of the PSE manifest, if provided.
    pub pse_manifest_hash: Option<Vec<u8>>,

    /// PSW-provided opaque data.
    pub platform_info: Option<PlatformInfo>,

    /// The IAS request nonce.
    pub nonce: Option<Nonce>,

    /// A unique hardware ID returned when a linkable quote is requested.
    pub epid_pseudonym: Option<EpidPseudonym>,

    /// The String URL of an Intel security advisory page.
    pub advisory_url: Option<String>,

    /// A set of advisory identifier strings applicable to this platform, as returned by IAS
    pub advisory_ids: BTreeSet<String>,
}

impl<'src> TryFrom<&'src IasReport> for Report {
    type Error = Error;

    /// Parse the JSON contents of a VerificationReport into a
    /// VerificationReportData object
    fn try_from(src: &'src IasReport) -> Result<Self, Error> {
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
            .map_err(Error::Timestamp)?;
        let timestamp = DateTime::from_utc(naive_timestamp, Utc);
        let version = data
            .remove("version")
            .ok_or_else(|| JsonError::FieldMissing("version".to_owned()))?
            .try_into()?;

        // Get the PIB, used in QuoteError, PseManifestError
        let platform_info = match data.remove("platformInfoBlob") {
            Some(v) => {
                let value: String = v.try_into()?;
                Some(PlatformInfo::from_hex(&value).map_err(Error::PlatformInfo)?)
            }
            None => None,
        };

        // Get the (optional) revocation reason, used in QuoteError
        let revocation_reason = match data.remove("revocationReason") {
            Some(v) => {
                let value: f64 = v.try_into()?;
                RevocationCause::from_bits(value as u64)
            }
            None => None,
        };

        // Get the PSE manifest status (parsed here since it may be used by QuoteError)
        let pse_manifest_status = match data.remove("pseManifestStatus") {
            Some(v) => {
                let value: String = v.try_into()?;
                Some(match value.as_str() {
                    "OK" => Ok(()),
                    "INVALID" => Err(PseManifestError::Invalid),
                    "OUT_OF_DATE" => Err(PseManifestError::OutOfDate(
                        platform_info.clone().ok_or_else(|| {
                            JsonError::FieldMissing("platformInfoBlob".to_owned())
                        })?,
                    )),
                    "REVOKED" => Err(PseManifestError::Revoked(
                        platform_info.clone().ok_or_else(|| {
                            JsonError::FieldMissing("platformInfoBlob".to_owned())
                        })?,
                    )),
                    "RL_VERSION_MISMATCH" => Err(PseManifestError::RlVersionMismatch(
                        platform_info.clone().ok_or_else(|| {
                            JsonError::FieldMissing("platformInfoBlob".to_owned())
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
            .ok_or_else(|| JsonError::FieldMissing("isvEnclaveQuoteStatus".to_owned()))?
            .try_into()?;
        let quote_status = match quote_status_str.as_str() {
            "OK" => Ok(pse_manifest_status.clone()),
            "SIGNATURE_INVALID" => Err(QuoteError::SignatureInvalid),
            "GROUP_REVOKED" => Err(QuoteError::GroupRevoked(
                revocation_reason
                    .ok_or_else(|| JsonError::FieldMissing("revocationReason".to_owned()))?,
                platform_info
                    .clone()
                    .ok_or_else(|| JsonError::FieldMissing("platformInfoBlob".to_owned()))?,
            )),
            "SIGNATURE_REVOKED" => Err(QuoteError::SignatureRevoked),
            "KEY_REVOKED" => Err(QuoteError::KeyRevoked),
            "SIGRL_VERSION_MISMATCH" => Err(QuoteError::SigrlVersionMismatch),
            "GROUP_OUT_OF_DATE" => Err(QuoteError::GroupOutOfDate(
                pse_manifest_status.clone(),
                platform_info
                    .clone()
                    .ok_or_else(|| JsonError::FieldMissing("platformInfoBlob".to_owned()))?,
            )),
            "CONFIGURATION_NEEDED" => Err(QuoteError::ConfigurationNeeded(
                pse_manifest_status.clone(),
                platform_info
                    .clone()
                    .ok_or_else(|| JsonError::FieldMissing("platformInfoBlob".to_owned()))?,
            )),
            "SW_HARDENING_NEEDED" => {
                Err(QuoteError::SwHardeningNeeded(pse_manifest_status.clone()))
            }
            "CONFIGURATION_AND_SW_HARDENING_NEEDED" => {
                Err(QuoteError::ConfigurationAndSwHardeningNeeded(
                    pse_manifest_status.clone(),
                    platform_info
                        .clone()
                        .ok_or_else(|| JsonError::FieldMissing("platformInfoBlob".to_owned()))?,
                ))
            }
            s => Err(QuoteError::Other(s.to_owned())),
        };

        // Parse the quote body
        let quote = {
            let s: String = data
                .remove("isvEnclaveQuoteBody")
                .ok_or_else(|| JsonError::FieldMissing("isvEnclaveQuoteBody".to_owned()))?
                .try_into()?;
            Quote::from_base64(&s)?
        };

        // PSW manifest hash
        let pse_manifest_hash = match data.remove("pseManifestHash") {
            Some(v) => {
                let value: String = v.try_into()?;
                Some(decode(&value).map_err(Error::PseManifest)?)
            }
            None => None,
        };

        // Nonce
        let nonce = match data.remove("nonce") {
            Some(v) => {
                let value: String = v.try_into()?;
                Some(Nonce::from_hex(&value).map_err(Error::Nonce)?)
            }
            None => None,
        };

        // EPID pseudonym
        let epid_pseudonym = match data.remove("epidPseudonym") {
            Some(v) => {
                let value: String = v.try_into()?;
                Some(EpidPseudonym::from_base64(&value).map_err(Error::EpidPseudonym)?)
            }
            None => None,
        };

        let advisory_url = match data.remove("advisoryURL") {
            Some(v) => Some(v.try_into()?),
            None => None,
        };

        let advisory_ids = if let Some(v) = data.remove("advisoryIDs") {
            let values: Vec<Value> = v.try_into()?;
            values
                .into_iter()
                .map(Value::try_into)
                .collect::<Result<BTreeSet<String>, JsonError>>()?
        } else {
            BTreeSet::<String>::default()
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
            platform_info,
            nonce,
            epid_pseudonym,
            advisory_url,
            advisory_ids,
        })
    }
}
