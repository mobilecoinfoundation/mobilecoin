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
    string::{String, ToString},
    vec::Vec,
};
use bitflags::bitflags;
use chrono::{format::ParseError, DateTime, NaiveDateTime, Utc};
use core::{
    convert::{TryFrom, TryInto},
    fmt::{Debug, Display, Formatter, Result as FmtResult},
};
use displaydoc::Display;
use hex::FromHex;
use mc_sgx_epid_types::PlatformInfo;
use mc_util_encodings::{Error as EncodingError, FromBase64};
#[cfg(feature = "use_prost")]
use prost::Message;
#[cfg(feature = "use_prost")]
use prost_types::Timestamp;

/// An enumeration of Platform Services Enclave manifest errors returned by IAS
/// as part of the signed quote.
///
/// This is defined in the [IAS API v4, S4.2.1](https://api.trustedservices.intel.com/documents/sgx-attestation-api-spec.pdf).
#[derive(Clone, Debug, Display, Hash, Eq, Ord, PartialEq, PartialOrd)]
pub enum PseError<'report> {
    /// Security properties of the SGX Platform Service cannot be verified due
    /// to unrecognized PSE Manifest.
    Unknown,

    /// Security properties of the SGX Platform Service are invalid.
    ///
    /// SP should assume the SGX Platform Service utilized by the ISV enclave is
    /// invalid.
    Invalid,

    /// TCB level of SGX Platform Service is outdated but the Service has not
    /// been identified as compromised and thus it is not revoked.
    ///
    /// It is up to the SP to decide whether or not to assume the SGX Platform
    /// Service utilized by the ISV enclave is valid.
    OutOfDate,

    /// The hardware/firmware component involved in the SGX Platform Service has
    /// been revoked.
    ///
    /// SP should assume the SGX Platform Service utilized by the ISV enclave is
    /// invalid.
    Revoked,

    /// A specific type of Revocation List used to verify the hardware/firmware
    /// component involved in the SGX Platform Service during the SGX
    /// Platform Service initialization process is out of date.
    ///
    /// If the SP rejects the remote attestation and forwards the Platform Info
    /// Blob to the SGX Platform SW through the ISV SGX Application, the SGX
    /// Platform SW will attempt to refresh the SGX Platform Service.
    RlVersionMismatch,

    /// The IAS server returned an unknown value: {0}
    Other(&'report str),
}

/// A flyweight structure repesenting a PSE Status
type PseResult<'report> = Result<&'report [u8], PseError<'report>>;

/// An enumeration of errors returned by IAS as part of the signed quote.
///
/// This is defined in the [IAS API v6, S4.2.1](https://software.intel.com/sites/default/files/managed/7e/3b/ias-api-spec.pdf).
#[derive(Clone, Debug, Display, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum QuoteError<'report> {
    /// EPID signature of the ISV enclave QUOTE was invalid.
    ///
    /// The content of the QUOTE is not trustworthy.
    SignatureInvalid,

    /// The EPID group has been revoked.
    ///
    /// When this value is returned, [`ReportBody::revocation_reason`] will
    /// contain the revocation reason code for this EPID group as reported
    /// in the EPID Group CRL. The content of the QUOTE is not trustworthy.
    GroupRevoked(RevocationReason),

    /// The EPID private key used to sign the QUOTE has been revoked by
    /// signature.
    ///
    /// The content of the QUOTE is not trustworthy.
    SignatureRevoked,

    /// The EPID private key used to sign the QUOTE has been directly revoked
    /// (not by signature).
    ///
    /// The content of the QUOTE is not trustworthy.
    KeyRevoked,

    /// SigRL version in ISV enclave QUOTE does not match the most recent
    /// version of the SigRL.
    ///
    /// In rare situations, after SP retrieved the SigRL from IAS and provided
    /// it to the platform, a newer version of the SigRL is made available.
    /// As a result, the Attestation Verification Report will indicate
    /// SIGRL_VERSION_MISMATCH. SP can retrieve the most recent version of
    /// SigRL from the IAS and request the platform to perform remote
    /// attestation again with the most recent version of SigRL. If the
    /// platform keeps failing to provide a valid QUOTE matching with the
    /// most recent version of the SigRL, the content of the QUOTE is not
    /// trustworthy.
    SigrlVersionMismatch,

    /// The EPID signature of the ISV enclave QUOTE has been verified correctly,
    /// but the TCB level of SGX platform is outdated (for further details
    /// see Advisory IDs).
    ///
    /// The platform has not been identified as compromised and thus it is not
    /// revoked. It is up to the Service Provider to decide whether or not
    /// to trust the content of the QUOTE, and whether or not to trust the
    /// platform performing the attestation to protect specific
    /// sensitive information.
    GroupOutOfDate(QuoteErrorData<'report>),

    /// The EPID signature of the ISV enclave QUOTE has been verified correctly,
    /// but additional configuration of SGX platform may be needed (for further
    /// details see Advisory IDs).
    ///
    /// The platform has not been identified as compromised and thus it is not
    /// revoked. It is up to the Service Provider to decide whether or not to
    /// trust the content of the QUOTE, and whether or not to trust the platform
    /// performing the attestation to protect specific sensitive information.
    ConfigurationNeeded(QuoteErrorData<'report>),

    /// The enclave requires software mitigation
    SwHardeningNeeded {
        pse_result: Option<PseResult<'report>>,
        advisory_url: &'report str,
        advisory_ids: &'report [String],
    },

    /// The enclave requires configuration changes and software mitigation
    ConfigurationAndSwHardeningNeeded(QuoteErrorData<'report>),

    /// Unknown error: {0}
    Other(&'report str),
}

/// A view of additional data supplied by IAS when an error is returned.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct QuoteErrorData<'report> {
    /// An optional PSE result, if [`Evidence::pse_manifest`] was provided.
    pub pse_result: Option<PseResult<'report>>,
    /// An optional platform info blob.
    pub platform_info_blob: &'report PlatformInfo,
    /// The advisory URL string.
    pub advisory_url: &'report str,
    /// A slice of advisory ID strings
    pub advisory_ids: &'report [String],
}

bitflags! {
    /// Revocation cause flags
    pub struct RevocationReason: u64 {
        /// Reason was not given (but still revoked)
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

impl Display for RevocationReason {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        let mut strings = Vec::new();
        if self.contains(RevocationReason::UNSPECIFIED) {
            strings.push("Unspecified");
        }
        if self.contains(RevocationReason::KEY_COMPROMISE) {
            strings.push("Key compromise");
        }
        if self.contains(RevocationReason::CERT_AUTHORITY_COMPROMISE) {
            strings.push("Certificate authority compromise");
        }
        if self.contains(RevocationReason::AFFILIATION_CHANGED) {
            strings.push("Affiliation changed");
        }
        if self.contains(RevocationReason::SUPERSEDED) {
            strings.push("Superseded");
        }
        if self.contains(RevocationReason::CESSATION_OF_OPERATION) {
            strings.push("Cessation of operation")
        }
        if self.contains(RevocationReason::CERTIFICATE_HOLD) {
            strings.push("Certificate hold");
        }
        if self.contains(RevocationReason::REMOVE_FROM_CRL) {
            strings.push("Removed from revocation list");
        }
        if self.contains(RevocationReason::PRIVILEGE_WITHDRAWN) {
            strings.push("Privilege withdrawn");
        }
        if self.contains(RevocationReason::ATTRIBUTE_AUTHORITY_COMPROMISE) {
            strings.push("Attribute authority compromise");
        }

        write!(f, "{}", strings.join(", "))
    }
}

/// An enumeration of report parsing errors
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

impl From<ParseError> for Error {
    fn from(src: ParseError) -> Error {
        Error::Timestamp(src.to_string())
    }
}

/// The parsed Attestation Verification Report returned by IAS.
///
/// This should be parsed from the [`Report`] after signature and cert
/// validation has succeeded, and is defined in the [IAS API v4, S4.2.1](https://api.trustedservices.intel.com/documents/sgx-attestation-api-spec.pdf).
#[cfg_attr(feature = "use_prost", derive(Message))]
#[derive(Clone, PartialEq)]
pub struct ReportBody {
    /// Representation of unique identifier of the Attestation Verification
    /// Report.
    #[cfg_attr(feature = "use_prost", prost(string, required))]
    id: String,

    /// Representation of date and time the Attestation Verification Report was
    /// created.
    ///
    /// In JSON, the time shall be in UTC and the encoding shall be compliant to
    /// ISO 8601 standard. In this structure, it's the number of seconds since
    /// EPOCH.
    #[cfg_attr(feature = "use_prost", prost(message, required))]
    timestamp: Timestamp,

    /// Integer that denotes the version of the Verification Attestation
    /// Evidence API that has been used to generate the report (currently
    /// set to 4).
    ///
    /// Service Providers should verify this field to confirm that the report
    /// was generated by the intended API version, instead of a different
    /// API version with potentially different security properties.
    #[cfg_attr(feature = "use_prost", prost(uint64, required))]
    version: u64,

    /// The quote status.
    #[cfg_attr(feature = "use_prost", prost(string, required))]
    quote_status: String,

    /// Base 64-encoded BODY of QUOTE structure (i.e., QUOTE structure without
    /// signature related fields: SIG_LEN and SIG) as received in
    /// Attestation Evidence Payload.
    #[cfg_attr(feature = "use_prost", prost(message, required))]
    quote_body: Quote,

    /// Integer corresponding to revocation reason code for a revoked EPID group
    /// listed in EPID Group CRL.
    ///
    /// Allowed values are described in RFC 5280. This field is optional, it
    /// will only be present if value of [`ReportBody::quote_status`] is
    /// equal to [`QuoteError::GroupRevoked`].
    #[cfg_attr(feature = "use_prost", prost(uint64, optional))]
    revocation_reason: Option<u64>,

    /// The status of the platform service.
    ///
    /// This field is optional, it will only be present if
    /// [`Evidence::pse_manifest`] is provided and [`ReportBody::
    /// quote_status`] is one of to Ok, [`QuoteError::GroupOutOfDate`],
    /// [`QuoteError::ConfigurationNeeded`], [`QuoteError::SwHardeningNeeded`],
    /// or [`QuoteError::ConfigurationAndSwHardeningNeeded`].
    #[cfg_attr(feature = "use_prost", prost(string, optional))]
    pse_manifest_status: Option<String>,

    /// SHA-256 calculated over [`Evidence::pse_manifest`].
    ///
    /// In JSON, this field is encoded using Base 16 encoding scheme. This field
    /// is optional, it will only be present if the pseManifest field was
    /// provided in Attestation Evidence Payload.
    #[cfg_attr(feature = "use_prost", prost(bytes, optional))]
    pse_manifest_hash: Option<Vec<u8>>,

    /// A TLV containing an opaque binary blob that the Service Provider and the
    /// ISV SGX Application are supposed to forward to SGX Platform SW.
    ///
    /// This field is optional, it will only be present if one the following
    /// conditions is met:
    ///  * [`ReportBody::quote_status`] is equal to
    ///    [`QuoteError::GroupRevoked`], [`QuoteError::GroupOutOfDate`],
    ///    [`QuoteError::ConfigurationNeeded`],
    ///    [`QuoteError::SwHardeningNeeded`], or
    ///    [`QuoteError::ConfigurationAndSwHardeningNeeded`]
    ///  * [`ReportBody::pse_manifest_status`] is equal to one of the following
    ///    values: [`PseError::OutOfDate`], [`PseError::Revoked`], or
    ///    [`PseError::RlVersionMismatch`].
    #[cfg_attr(feature = "use_prost", prost(message, optional))]
    platform_info_blob: Option<PlatformInfo>,

    /// The nonce value provided by SP in [`Evidence::nonce`].
    ///
    /// This field is optional, it will only be present if nonce field is
    /// provided in Attestation Evidence Payload.
    #[cfg_attr(feature = "use_prost", prost(message, optional))]
    nonce: Option<Nonce>,

    /// Byte array representing EPID Pseudonym that consists of the
    /// concatenation of EPID B (64 bytes) & EPID K (64 bytes) components of
    /// EPID signature.
    ///
    /// If two linkable EPID signatures for an EPID Group have the same EPID
    /// Pseudonym, the two signatures were generated using the same EPID
    /// private key. This field is encoded using Base 64 encoding scheme.
    ///
    /// This field is optional, it will only be present if Attestation
    /// Evidence Payload contains Quote with linkable EPID signature.
    #[cfg_attr(feature = "use_prost", prost(message, optional))]
    epid_pseudonym: Option<EpidPseudonym>,

    /// URL to Intel® Product Security Center Advisories page that provides
    /// additional information on SGX-related security issues.
    ///
    /// IDs of advisories for specific issues that may affect the attested
    /// platform are conveyed in advisoryIDs field. This field is optional,
    /// it will only be present if HTTP status code is 200 and
    /// [`ReportBody::quote_status`] is equal to [`QuoteError::GroupOutOfDate`],
    /// [`QuoteError::ConfigurationNeeded`], [`QuoteError::SwHardeningNeeded`],
    /// or [`QuoteError::ConfigurationAndSwHardeningNeeded`].
    #[cfg_attr(feature = "use_prost", prost(string, optional))]
    advisory_url: Option<String>,

    /// Array of Advisory IDs that can be searched on a page indicated by URL
    /// included in [`ReportBody::advisory_url`] field.
    ///
    /// Advisory IDs refer to articles providing insight into SGX-related
    /// security issues that may affect attested platform. This field is
    /// optional, it will only be present if HTTP status code is 200 and
    /// [`ReportBody::quote_status`] is equal to [`QuoteError::GroupOutOfDate`],
    /// [`QuoteError::ConfigurationNeeded`], [`QuoteError::SwHardeningNeeded`],
    /// or [`QuoteError::ConfigurationAndSwHardeningNeeded`].
    #[cfg_attr(feature = "use_prost", prost(string, repeated))]
    advisory_ids: Vec<String>,
}

impl ReportBody {
    /// Retrieve the string ID
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Retrieve the timestamp
    pub fn timestamp(&self) -> DateTime<Utc> {
        DateTime::from_utc(
            NaiveDateTime::from_timestamp(self.timestamp.seconds, self.timestamp.nanos as u32),
            Utc,
        )
    }

    /// Retrieve the version
    pub fn version(&self) -> u64 {
        self.version
    }

    /// Retrieve the quote body
    pub fn quote_body(&self) -> &Quote {
        &self.quote_body
    }

    /// Helper method, constructs a result from the hash and status.
    fn status_hash_to_result(&self) -> Result<Option<PseResult>, QuoteError> {
        let hash = self
            .pse_manifest_hash
            .as_ref()
            .ok_or(QuoteError::Other(
                "IAS did not provide both our hash and our status",
            ))?
            .as_slice();
        match self
            .pse_manifest_status
            .as_ref()
            .expect("PSE manifest status is both Some and None")
            .as_str()
        {
            "OK" => Ok(Some(Ok(hash))),
            "UNKNOWN" => Ok(Some(Err(PseError::Unknown))),
            "INVALID" => Ok(Some(Err(PseError::Invalid))),
            "OUT_OF_DATE" => Ok(Some(Err(PseError::OutOfDate))),
            "REVOKED" => Ok(Some(Err(PseError::Revoked))),
            "RL_VERSION_MISMATCH" => Ok(Some(Err(PseError::RlVersionMismatch))),
            other => Ok(Some(Err(PseError::Other(other)))),
        }
    }

    /// Helper method to unwrap or do a quote error based on a string.
    #[inline]
    fn unwrap_option<'report, T>(
        value: &'report Option<T>,
        err_msg: &'report str,
    ) -> Result<&'report T, QuoteError<'report>> {
        value.as_ref().ok_or(QuoteError::Other(err_msg))
    }

    fn quote_error_data(&self) -> Result<QuoteErrorData, QuoteError> {
        Ok(QuoteErrorData {
            pse_result: self.status_hash_to_result()?,
            platform_info_blob: Self::unwrap_option(
                &self.platform_info_blob,
                "Platform Info Blob missing",
            )?,
            advisory_url: Self::unwrap_option(&self.advisory_url, "Advisory URL missing")?,
            advisory_ids: self.advisory_ids.as_slice(),
        })
    }

    /// Retrieve the IAS evaluation results from IAS
    pub fn result(&self) -> Result<Option<PseResult>, QuoteError> {
        match self.quote_status.as_str() {
            "OK" => self.status_hash_to_result(),
            "SIGNATURE_INVALID" => Err(QuoteError::SignatureInvalid),
            "GROUP_REVOKED" => Err(QuoteError::GroupRevoked(
                RevocationReason::from_bits(
                    self.revocation_reason
                        .ok_or(QuoteError::Other("Revocation reason missing"))?,
                )
                .ok_or(QuoteError::Other("Unknown revocation reason"))?,
            )),
            "KEY_REVOKED" => Err(QuoteError::KeyRevoked),
            "SIGRL_VERSION_MISMATCH" => Err(QuoteError::SigrlVersionMismatch),
            "GROUP_OUT_OF_DATE" => Err(QuoteError::GroupOutOfDate(self.quote_error_data()?)),
            "CONFIGURATION_NEEDED" => {
                Err(QuoteError::ConfigurationNeeded(self.quote_error_data()?))
            }
            "SW_HARDENING_NEEDED" => Err(QuoteError::SwHardeningNeeded {
                pse_result: self.status_hash_to_result()?,
                advisory_url: Self::unwrap_option(&self.advisory_url, "Advisory URL missing")?,
                advisory_ids: self.advisory_ids.as_slice(),
            }),
            "CONFIGURATION_AND_SW_HARDENING_NEEDED" => Err(
                QuoteError::ConfigurationAndSwHardeningNeeded(self.quote_error_data()?),
            ),
            other => Err(QuoteError::Other(other)),
        }
    }

    /// Retrieve the EPID pseudonym of the enclave's current hardware
    pub fn pseudonym(&self) -> Option<&EpidPseudonym> {
        self.epid_pseudonym.as_ref()
    }

    /// Retrieve the nonce provided to IAS.
    pub fn nonce(&self) -> Option<&Nonce> {
        self.nonce.as_ref()
    }
}

/// Parse the JSON contents of a VerificationReport into a
/// VerificationReportData object
impl<'src> TryFrom<&'src Report> for ReportBody {
    type Error = Error;

    fn try_from(src: &'src Report) -> Result<Self, Error> {
        // Parse the JSON into a hashmap
        let (chars_parsed, data) = parse(&src.http_body);
        if data.is_none() {
            return Err(JsonError::NoData.into());
        }

        if chars_parsed < src.http_body.len() {
            return Err(JsonError::IncompleteParse(chars_parsed).into());
        }

        // Parse the JSON into a DOM object
        let mut data = match data.unwrap() {
            Value::Object(o) => o,
            _ => return Err(JsonError::RootNotObject.into()),
        };

        let id = data
            .remove("id")
            .ok_or_else(|| JsonError::FieldMissing("id".to_owned()))?
            .try_into()?;

        let timestamp = data
            .remove("timestamp")
            .map(TryInto::<String>::try_into)
            .transpose()?
            .map(|value| {
                NaiveDateTime::parse_from_str(&value, "%Y-%m-%d %H:%M:%S").map(|ndt| Timestamp {
                    seconds: ndt.timestamp(),
                    nanos: ndt.timestamp_subsec_nanos() as i32,
                })
            })
            .transpose()?
            .ok_or_else(|| JsonError::FieldMissing("timestamp".to_owned()))?;

        let version = data
            .remove("version")
            .map(TryInto::<f64>::try_into)
            .transpose()?
            .map(|version| version as u64)
            .ok_or_else(|| JsonError::FieldMissing("version".to_owned()))?;

        // Get the PIB, used in QuoteError, PseManifestError
        let platform_info_blob: Option<PlatformInfo> = data
            .remove("platformInfoBlob")
            .map(TryInto::<String>::try_into)
            .transpose()?
            .map(|value| PlatformInfo::from_hex(&value).map_err(Error::PlatformInfo))
            .transpose()?;

        // Get the (optional) revocation reason, used in QuoteError
        let revocation_reason = data
            .remove("revocationReason")
            .map(TryInto::<f64>::try_into)
            .transpose()?
            .map(|reason| reason as u64);

        // PSW manifest hash
        let pse_manifest_hash = data
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
        let pse_manifest_status = data
            .remove("pseManifestStatus")
            .map(TryInto::<String>::try_into)
            .transpose()?;

        // 1. Start with Option<Value>
        // 2. TryInto<String> -> Option<Result<String, JsonError>>
        // 3. transpose() -> Result<Option<String>, JsonError>
        // 4. ? operator -> Option<String>
        // 4. ok_or_else() -> Result<String, Error>
        // 5. ? operator -> String
        let quote_status = data
            .remove("isvEnclaveQuoteStatus")
            .map(TryInto::<String>::try_into)
            .transpose()?
            .ok_or_else(|| {
                Error::Json(JsonError::FieldMissing("isvEnclaveQuoteStatus".to_owned()))
            })?;

        // Parse the quote body
        let quote_body = data
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

        let advisory_url = data
            .remove("advisoryURL")
            .map(TryInto::<String>::try_into)
            .transpose()?;

        let advisory_ids = data
            .remove("advisoryIDs")
            .map(TryInto::<Vec<Value>>::try_into)
            .transpose()?
            .map(|values| {
                values
                    .into_iter()
                    .map(TryInto::<String>::try_into)
                    .collect::<Result<Vec<String>, JsonError>>()
            })
            .transpose()?
            .unwrap_or_default();

        Ok(Self {
            id,
            timestamp,
            version,
            quote_status,
            quote_body,
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
