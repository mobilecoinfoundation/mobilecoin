// Copyright (c) 2018-2021 The MobileCoin Foundation

//! Errors which can occur during the attestation process

use crate::{
    quote::QuoteSignType,
    types::{
        epid_group_id::EpidGroupId,
        measurement::{Measurement, MrEnclave, MrSigner},
        pib::PlatformInfoBlob,
        update_info::UpdateInfo,
    },
};
use alloc::{string::String, vec::Vec};
use binascii::ConvertError;
use bitflags::bitflags;
use core::{
    fmt::{Display, Error as FmtError, Formatter, Result as FmtResult},
    hash::{Hash, Hasher},
};
use displaydoc::Display;
use mc_sgx_types::sgx_status_t;
use mc_util_encodings::Error as EncodingError;
use serde::{Deserialize, Serialize};

/// A collection of errors surrounding the EPID pseudonym
#[derive(
    Clone, Copy, Debug, Deserialize, Display, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize,
)]
pub enum EpidPseudonymError {
    /// The quote body could not be decoded
    Decode(EncodingError),
    /// The size of the data does not match the expected size
    SizeMismatch,
}

impl From<ConvertError> for EpidPseudonymError {
    fn from(src: ConvertError) -> Self {
        EpidPseudonymError::Decode(src.into())
    }
}

impl From<EncodingError> for EpidPseudonymError {
    fn from(src: EncodingError) -> Self {
        EpidPseudonymError::Decode(src)
    }
}

/// The rust-friendly version of the IAS QuoteStatus field.
pub type IasQuoteResult = Result<Option<PseManifestResult>, IasQuoteError>;

/// An enumeration of errors returned by IAS as part of the signed quote
///
/// This is defined in the [IAS API v3, S4.2.1](https://software.intel.com/sites/default/files/managed/7e/3b/ias-api-spec.pdf).
#[derive(Clone, Debug, Deserialize, Display, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub enum IasQuoteError {
    /// EPID signature of the ISV enclave QUOTE was invalid
    SignatureInvalid,
    /// The EPID group has been revoked. See RevocationCause
    GroupRevoked(RevocationCause, PlatformInfoBlob),
    /**
     * The EPID private key used to sign the QUOTE has been revoked by
     * signature
     */
    SignatureRevoked,
    /**
     * The EPID private key used to sign the QUOTE has been directly revoked
     * (not by signature)
     */
    KeyRevoked,
    /// The SigRL used for the quote is out of date
    SigrlVersionMismatch,
    /**
     * The EPID group must be updated to mitigate {advisory_ids:?}, see
     * {advisory_url}
     */
    GroupOutOfDate {
        pse_manifest_status: Option<PseManifestResult>,
        platform_info_blob: PlatformInfoBlob,
        advisory_url: String,
        advisory_ids: Vec<String>,
    },
    /** The enclave requires additional BIOS configuration to mitigate
     * {advisory_ids:?}, see {advisory_url}
     */
    ConfigurationNeeded {
        pse_manifest_status: Option<PseManifestResult>,
        platform_info_blob: PlatformInfoBlob,
        advisory_url: String,
        advisory_ids: Vec<String>,
    },
    /**
     * The enclave requires software mitigation for {advisory_ids:?}, see
     *  {advisory_url}
     */
    SwHardeningNeeded {
        pse_manifest_status: Option<PseManifestResult>,
        advisory_url: String,
        advisory_ids: Vec<String>,
    },
    /** The enclave requires additional BIOS configuration and software
     * mitigation for {advisory_ids:?}, see {advisory_url}
     */
    ConfigurationAndSwHardeningNeeded {
        pse_manifest_status: Option<PseManifestResult>,
        platform_info_blob: PlatformInfoBlob,
        advisory_url: String,
        advisory_ids: Vec<String>,
    },
    /// Unknown error: {0}
    Other(String),
}

/// An enumeration of errors which can occur while parsing the JSON of a
/// verification report
#[derive(Clone, Debug, Deserialize, Display, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub enum JsonError {
    /// There was no non-whitespace data to parse.
    NoData,
    /// Not all data could be read, error at position: {0}
    IncompleteParse(usize),
    /// The root of the JSON is not an object
    RootNotObject,
    /// The '{0}' field was missing from the IAS JSON"
    FieldMissing(String),
    /// A field within the JSON contained an unexpected type
    FieldType,
}

/// An enumeration of possible errors while working with nonce values
#[derive(Clone, Debug, Deserialize, Display, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub enum NonceError {
    /// The nonce was not returned
    Missing,
    /// The nonce does not match the expected value
    Mismatch,
    /// There was an error deserializing the nonce from bytes or a string: {0}
    Convert(EncodingError),
}

impl From<EncodingError> for NonceError {
    fn from(src: EncodingError) -> NonceError {
        NonceError::Convert(src)
    }
}

/// An enumeration of possible errors while working with a PlatformInfoBase
/// object
#[derive(Clone, Debug, Deserialize, Display, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub enum PibError {
    /// There was an SGX error while updating the TCB: {0}
    Sgx(SgxError),
    /// SGX must be updated: {0}
    UpdateNeeded(UpdateInfo),
    /// There was an error deserializing a PIB from bytes or a string
    Convert(EncodingError),
}

impl From<ConvertError> for PibError {
    fn from(src: ConvertError) -> PibError {
        PibError::Convert(src.into())
    }
}

impl From<EncodingError> for PibError {
    fn from(src: EncodingError) -> PibError {
        PibError::Convert(src)
    }
}

impl From<sgx_status_t> for PibError {
    fn from(src: sgx_status_t) -> PibError {
        PibError::Sgx(src.into())
    }
}

impl From<SgxError> for PibError {
    fn from(src: SgxError) -> PibError {
        PibError::Sgx(src)
    }
}

impl From<UpdateInfo> for PibError {
    fn from(src: UpdateInfo) -> PibError {
        PibError::UpdateNeeded(src)
    }
}

/// A PSE manifest status
pub type PseManifestResult = Result<(), PseManifestError>;

/// An enumeration of Platform Services Enclave manifest errors returned by IAS
/// as part of the signed quote.
///
/// This is defined in the [IAS API v3, S4.2.1](https://software.intel.com/sites/default/files/managed/7e/3b/ias-api-spec.pdf).
#[derive(Clone, Debug, Deserialize, Display, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub enum PseManifestError {
    /**
     * Security properties of the PSW cannot be verified due to unrecognized
     * PSE Manifest
     */
    Unknown,
    /// Security properties of the PSW are invalid
    Invalid,
    /// TCB level of PSW is outdated but not identified as compromised
    OutOfDate(PlatformInfoBlob),
    /// Hardware/firmware component involved in the PSW has been revoked
    Revoked(PlatformInfoBlob),
    /**
     * The PSW revocation list is out of date, use the included PIB to force
     * an update
     */
    RlVersionMismatch(PlatformInfoBlob),
    /// The PSE status was not returned by IAS
    Missing,
}

/// An enumeration of errors which can occur related to a PSE Manifest Hash
#[derive(Clone, Debug, Deserialize, Display, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub enum PseManifestHashError {
    /// There was a problem parsing the PSE manifest hash
    Parse(EncodingError),
    /// The PSE manifest hash does not match the expected value
    Mismatch,
}

/// An enumeration of failure conditions when creating or handling quotes.
#[derive(Clone, Debug, Deserialize, Display, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub enum QuoteError {
    /// SGX error: {0}
    Sgx(SgxError),
    /// Text or binary conversion error: {0}
    Encoding(EncodingError),
    /// The quote could not be verified: {0}
    QuoteVerify(QuoteVerifyError),
    /// The size '{0}' is not valid for a quote
    InvalidSize(u32),
    /// The base64 encoder did not output valid UTF-8 data
    InvalidUtf8,
}

impl From<ConvertError> for QuoteError {
    fn from(src: ConvertError) -> Self {
        QuoteError::Encoding(src.into())
    }
}

impl From<EncodingError> for QuoteError {
    fn from(src: EncodingError) -> Self {
        QuoteError::Encoding(src)
    }
}

impl From<QuoteVerifyError> for QuoteError {
    fn from(src: QuoteVerifyError) -> Self {
        QuoteError::QuoteVerify(src)
    }
}

impl From<QuoteSignTypeError> for QuoteError {
    fn from(src: QuoteSignTypeError) -> Self {
        QuoteError::QuoteVerify(src.into())
    }
}

impl From<ReportBodyVerifyError> for QuoteError {
    fn from(src: ReportBodyVerifyError) -> Self {
        QuoteError::QuoteVerify(src.into())
    }
}

impl From<SgxError> for QuoteError {
    fn from(src: SgxError) -> Self {
        QuoteError::Sgx(src)
    }
}

impl From<sgx_status_t> for QuoteError {
    fn from(src: sgx_status_t) -> Self {
        QuoteError::Sgx(src.into())
    }
}

/// An enumeration of failure conditions when converting a foreign value into a
/// QuoteSignType
#[derive(Clone, Debug, Deserialize, Display, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub enum QuoteSignTypeError {
    /// Expected quote signature type {0}, got {1}
    Mismatch(QuoteSignType, QuoteSignType),
    /// Unknown quote sign type: {0}
    Unknown(u64),
    /// There was an encoding error: {0}
    Encoding(EncodingError),
}

impl From<QuoteSignTypeError> for FmtError {
    fn from(_src: QuoteSignTypeError) -> FmtError {
        FmtError
    }
}

impl From<EncodingError> for QuoteSignTypeError {
    fn from(src: EncodingError) -> QuoteSignTypeError {
        QuoteSignTypeError::Encoding(src)
    }
}

/// An enumeration of failure conditions when verifying a Quote
#[derive(Clone, Debug, Deserialize, Display, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub enum QuoteVerifyError {
    /// The quote body could not be decoded: {0}
    Decode(EncodingError),
    /// The quote's GID, {0}, was not the expected {1}
    GidMismatch(EpidGroupId, EpidGroupId),
    /// The quote's linkable vs. unlinkable type was incorrect
    QuoteSignType(QuoteSignTypeError),
    /// The quote's report could not be verified: {0}
    ReportBodyVerify(ReportBodyVerifyError),
    /// The QE version in the quote and the one in the QE's report don't match.
    QeVersionMismatch,
    /// The quote appears valid, but the report is not expected.
    QuotedReportMismatch,
}

impl From<ConvertError> for QuoteVerifyError {
    fn from(src: ConvertError) -> Self {
        QuoteVerifyError::Decode(src.into())
    }
}

impl From<EncodingError> for QuoteVerifyError {
    fn from(src: EncodingError) -> Self {
        QuoteVerifyError::Decode(src)
    }
}

impl From<QuoteSignTypeError> for QuoteVerifyError {
    fn from(src: QuoteSignTypeError) -> Self {
        QuoteVerifyError::QuoteSignType(src)
    }
}

impl From<ReportBodyVerifyError> for QuoteVerifyError {
    fn from(src: ReportBodyVerifyError) -> Self {
        QuoteVerifyError::ReportBodyVerify(src)
    }
}

/// An enumeration of failure conditions
#[derive(Clone, Debug, Deserialize, Display, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub enum ReportBodyVerifyError {
    /// The enclave was running in debug mode
    DebugNotAllowed,
    /// Product ID mismatch, expected {0}, got {1}
    ProductId(u16, u16),
    /// The enclave's security version was not at least {0}
    SecurityVersion(u16),
    /**
     * Measurement error, expected one of {0:0x?}, got MRENCLAVE {1}, and
     * MRSIGNER {2}
     */
    MrMismatch(Vec<Measurement>, MrEnclave, MrSigner),
    /// Report data mismatch
    DataMismatch,
}

/// An enumeration of possible errors related to handling a ReportDetails
/// structure
///
/// This is soon-to-be-deprecated.
#[derive(
    Clone, Copy, Debug, Deserialize, Display, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize,
)]
pub enum ReportDetailsError {
    /// The key type provided was unknown
    UnknownKeyType,
    /// Provided output buffer is too short, must be {0} bytes
    InsufficientBuffer(usize),
    /// Our public key was not as part of the report details
    PubkeyMismatch,
    /// Our nonce was not the one indicated in the report details
    NonceMismatch,
}

bitflags! {
    /// Revocation cause flags
    #[derive(Deserialize, Serialize)]
    pub struct RevocationCause: u64 {
        /// Cause reason was not given (but still revoked)
        const UNSPECIFIED = 0;
        /// The private key for the EPID was compromised
        const KEY_COMRPOMISE = 1;
        /// The CA which signed the EPID key was compromised
        const CERT_AUTHORITY_COMPROMISE = 1 << 1;
        /// X509-specific, probably never used in our environment.
        const AFFILIATION_CHANGED = 1 << 2;
        /// The EPID group key has been replaced with a new key. Probably never used in our
        /// environment, unless you can replace EPID keys via microcode update...
        const SUPERSEDED = 1 << 3;
        /// Nothing should still be using the cert in question, but there's no indication it was
        /// compromised. Probably never used in our environment.
        const CESSATION_OF_OPERATION = 1 << 4;
        /// Indicates a certificate should not be trusted right now, but may be deemed trustworthy
        /// again, in the future. Probably never used in our environment.
        const CERTIFICATE_HOLD = 1 << 5;
        /// Used to remove a certificate from a CRL via deltaCRL. This would be done to lift a
        /// certificateHold, or remove an expired cert from a CRL. Probably never used in our
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

/// An enumeration of errors which can occur when verifying report from IAS
#[derive(
    Clone, Copy, Debug, Deserialize, Display, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize,
)]
pub enum SignatureError {
    /// No certificates were provided to validate against
    NoCerts,
    /// There was an error taking the hash of the data
    Hash,
    /// The signature is invalid, or the signer is untrusted
    BadSignature,
    /// There was another error inside the certificate library
    Tls,
}

/// A type alias for a result containing an SgxError
pub type SgxResult<T> = Result<T, SgxError>;

mod sgx_status_t_serde {
    use core::fmt::{Formatter, Result as FmtResult};
    use mc_sgx_types::sgx_status_t;
    use serde::{
        de::{Deserializer, Error, Visitor},
        ser::Serializer,
    };

    // We ignore this clippy error to comply with Serde's serialize API.
    #[allow(clippy::trivially_copy_pass_by_ref)]
    pub fn serialize<S: Serializer>(src: &sgx_status_t, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_u32(*src as u32)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<sgx_status_t, D::Error> {
        struct StatusVisitor;

        impl<'de> Visitor<'de> for StatusVisitor {
            type Value = sgx_status_t;

            fn expecting(&self, formatter: &mut Formatter) -> FmtResult {
                formatter.write_str("a u64 sgx_status_t")
            }

            fn visit_u32<E: Error>(self, value: u32) -> Result<Self::Value, E> {
                // This needs to be kept in sync with the sgx_status_t enum
                match value {
                    0x0000_0000 => Ok(sgx_status_t::SGX_SUCCESS),
                    0x0000_0001 => Ok(sgx_status_t::SGX_ERROR_UNEXPECTED),
                    0x0000_0002 => Ok(sgx_status_t::SGX_ERROR_INVALID_PARAMETER),
                    0x0000_0003 => Ok(sgx_status_t::SGX_ERROR_OUT_OF_MEMORY),
                    0x0000_0004 => Ok(sgx_status_t::SGX_ERROR_ENCLAVE_LOST),
                    0x0000_0005 => Ok(sgx_status_t::SGX_ERROR_INVALID_STATE),
                    0x0000_0008 => Ok(sgx_status_t::SGX_ERROR_FEATURE_NOT_SUPPORTED),

                    0x0000_1001 => Ok(sgx_status_t::SGX_ERROR_INVALID_FUNCTION),
                    0x0000_1003 => Ok(sgx_status_t::SGX_ERROR_OUT_OF_TCS),
                    0x0000_1006 => Ok(sgx_status_t::SGX_ERROR_ENCLAVE_CRASHED),
                    0x0000_1007 => Ok(sgx_status_t::SGX_ERROR_ECALL_NOT_ALLOWED),
                    0x0000_1008 => Ok(sgx_status_t::SGX_ERROR_OCALL_NOT_ALLOWED),
                    0x0000_1009 => Ok(sgx_status_t::SGX_ERROR_STACK_OVERRUN),

                    0x0000_2000 => Ok(sgx_status_t::SGX_ERROR_UNDEFINED_SYMBOL),
                    0x0000_2001 => Ok(sgx_status_t::SGX_ERROR_INVALID_ENCLAVE),
                    0x0000_2002 => Ok(sgx_status_t::SGX_ERROR_INVALID_ENCLAVE_ID),
                    0x0000_2003 => Ok(sgx_status_t::SGX_ERROR_INVALID_SIGNATURE),
                    0x0000_2004 => Ok(sgx_status_t::SGX_ERROR_NDEBUG_ENCLAVE),
                    0x0000_2005 => Ok(sgx_status_t::SGX_ERROR_OUT_OF_EPC),
                    0x0000_2006 => Ok(sgx_status_t::SGX_ERROR_NO_DEVICE),
                    0x0000_2007 => Ok(sgx_status_t::SGX_ERROR_MEMORY_MAP_CONFLICT),
                    0x0000_2009 => Ok(sgx_status_t::SGX_ERROR_INVALID_METADATA),
                    0x0000_200c => Ok(sgx_status_t::SGX_ERROR_DEVICE_BUSY),
                    0x0000_200d => Ok(sgx_status_t::SGX_ERROR_INVALID_VERSION),
                    0x0000_200e => Ok(sgx_status_t::SGX_ERROR_MODE_INCOMPATIBLE),
                    0x0000_200f => Ok(sgx_status_t::SGX_ERROR_ENCLAVE_FILE_ACCESS),
                    0x0000_2010 => Ok(sgx_status_t::SGX_ERROR_INVALID_MISC),
                    0x0000_2011 => Ok(sgx_status_t::SGX_ERROR_INVALID_LAUNCH_TOKEN),

                    0x0000_3001 => Ok(sgx_status_t::SGX_ERROR_MAC_MISMATCH),
                    0x0000_3002 => Ok(sgx_status_t::SGX_ERROR_INVALID_ATTRIBUTE),
                    0x0000_3003 => Ok(sgx_status_t::SGX_ERROR_INVALID_CPUSVN),
                    0x0000_3004 => Ok(sgx_status_t::SGX_ERROR_INVALID_ISVSVN),
                    0x0000_3005 => Ok(sgx_status_t::SGX_ERROR_INVALID_KEYNAME),

                    0x0000_4001 => Ok(sgx_status_t::SGX_ERROR_SERVICE_UNAVAILABLE),
                    0x0000_4002 => Ok(sgx_status_t::SGX_ERROR_SERVICE_TIMEOUT),
                    0x0000_4003 => Ok(sgx_status_t::SGX_ERROR_AE_INVALID_EPIDBLOB),
                    0x0000_4004 => Ok(sgx_status_t::SGX_ERROR_SERVICE_INVALID_PRIVILEGE),
                    0x0000_4005 => Ok(sgx_status_t::SGX_ERROR_EPID_MEMBER_REVOKED),
                    0x0000_4006 => Ok(sgx_status_t::SGX_ERROR_UPDATE_NEEDED),
                    0x0000_4007 => Ok(sgx_status_t::SGX_ERROR_NETWORK_FAILURE),
                    0x0000_4008 => Ok(sgx_status_t::SGX_ERROR_AE_SESSION_INVALID),
                    0x0000_400a => Ok(sgx_status_t::SGX_ERROR_BUSY),
                    0x0000_400c => Ok(sgx_status_t::SGX_ERROR_MC_NOT_FOUND),
                    0x0000_400d => Ok(sgx_status_t::SGX_ERROR_MC_NO_ACCESS_RIGHT),
                    0x0000_400e => Ok(sgx_status_t::SGX_ERROR_MC_USED_UP),
                    0x0000_400f => Ok(sgx_status_t::SGX_ERROR_MC_OVER_QUOTA),
                    0x0000_4011 => Ok(sgx_status_t::SGX_ERROR_KDF_MISMATCH),
                    0x0000_4012 => Ok(sgx_status_t::SGX_ERROR_UNRECOGNIZED_PLATFORM),

                    0x0000_5002 => Ok(sgx_status_t::SGX_ERROR_NO_PRIVILEGE),

                    /* SGX Protected Code Loader Error codes */
                    0x0000_6001 => Ok(sgx_status_t::SGX_ERROR_PCL_ENCRYPTED),
                    0x0000_6002 => Ok(sgx_status_t::SGX_ERROR_PCL_NOT_ENCRYPTED),
                    0x0000_6003 => Ok(sgx_status_t::SGX_ERROR_PCL_MAC_MISMATCH),
                    0x0000_6004 => Ok(sgx_status_t::SGX_ERROR_PCL_SHA_MISMATCH),
                    0x0000_6005 => Ok(sgx_status_t::SGX_ERROR_PCL_GUID_MISMATCH),

                    /* SGX errors are only used in the file API when there is no appropriate EXXX
                     * (EINVAL, EIO etc.) error code */
                    0x0000_7001 => Ok(sgx_status_t::SGX_ERROR_FILE_BAD_STATUS),
                    0x0000_7002 => Ok(sgx_status_t::SGX_ERROR_FILE_NO_KEY_ID),
                    0x0000_7003 => Ok(sgx_status_t::SGX_ERROR_FILE_NAME_MISMATCH),
                    0x0000_7004 => Ok(sgx_status_t::SGX_ERROR_FILE_NOT_SGX_FILE),
                    0x0000_7005 => Ok(sgx_status_t::SGX_ERROR_FILE_CANT_OPEN_RECOVERY_FILE),
                    0x0000_7006 => Ok(sgx_status_t::SGX_ERROR_FILE_CANT_WRITE_RECOVERY_FILE),
                    0x0000_7007 => Ok(sgx_status_t::SGX_ERROR_FILE_RECOVERY_NEEDED),
                    0x0000_7008 => Ok(sgx_status_t::SGX_ERROR_FILE_FLUSH_FAILED),
                    0x0000_7009 => Ok(sgx_status_t::SGX_ERROR_FILE_CLOSE_FAILED),

                    0x0000_F001 => Ok(sgx_status_t::SGX_INTERNAL_ERROR_ENCLAVE_CREATE_INTERRUPTED),

                    0x0F00_F001 => Ok(sgx_status_t::SGX_ERROR_WASM_BUFFER_TOO_SHORT),
                    0x0F00_F002 => Ok(sgx_status_t::SGX_ERROR_WASM_INTERPRETER_ERROR),
                    0x0F00_F003 => Ok(sgx_status_t::SGX_ERROR_WASM_LOAD_MODULE_ERROR),
                    0x0F00_F004 => Ok(sgx_status_t::SGX_ERROR_WASM_TRY_LOAD_ERROR),
                    0x0F00_F005 => Ok(sgx_status_t::SGX_ERROR_WASM_REGISTER_ERROR),
                    0x0F00_E001 => Ok(sgx_status_t::SGX_ERROR_FAAS_BUFFER_TOO_SHORT),
                    0x0F00_E002 => Ok(sgx_status_t::SGX_ERROR_FAAS_INTERNAL_ERROR),

                    _ => Err(E::custom(
                        "Unknown value for sgx_status_t, code out of date?",
                    )),
                }
            }
        }

        deserializer.deserialize_u32(StatusVisitor)
    }
}

/// A simple wrapper around sgx_status_t to provide serde and display support
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialOrd, Serialize)]
pub struct SgxError(#[serde(with = "sgx_status_t_serde")] sgx_status_t);

impl AsRef<sgx_status_t> for SgxError {
    fn as_ref(&self) -> &sgx_status_t {
        &self.0
    }
}

impl Display for SgxError {
    fn fmt(&self, formatter: &mut Formatter) -> FmtResult {
        write!(formatter, "sgx_status_t: {}", self.0)
    }
}

impl From<sgx_status_t> for SgxError {
    fn from(src: sgx_status_t) -> SgxError {
        Self(src)
    }
}

impl Hash for SgxError {
    fn hash<H: Hasher>(&self, hasher: &mut H) {
        (self.0 as u32).hash(hasher)
    }
}

impl From<SgxError> for sgx_status_t {
    fn from(src: SgxError) -> sgx_status_t {
        src.0
    }
}

impl PartialEq for SgxError {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

impl PartialEq<sgx_status_t> for SgxError {
    fn eq(&self, other: &sgx_status_t) -> bool {
        self.0 == *other
    }
}

#[derive(Clone, Debug, Deserialize, Display, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub enum TargetInfoError {
    /// SGX error: {0}
    Sgx(SgxError),
    /// Quoting enclave busy
    QeBusy,
    /// Error retrying: {0}
    Retry(String),
    /// String or binary conversion error: {0}
    Convert(EncodingError),
}

impl From<ConvertError> for TargetInfoError {
    fn from(src: ConvertError) -> Self {
        TargetInfoError::Convert(src.into())
    }
}

impl From<EncodingError> for TargetInfoError {
    fn from(src: EncodingError) -> Self {
        TargetInfoError::Convert(src)
    }
}

impl From<SgxError> for TargetInfoError {
    fn from(src: SgxError) -> Self {
        TargetInfoError::Sgx(src)
    }
}

impl From<sgx_status_t> for TargetInfoError {
    fn from(src: sgx_status_t) -> TargetInfoError {
        TargetInfoError::Sgx(src.into())
    }
}

/// An enumeration of errors while parsing or verifying contents of a
/// verification report
#[derive(Clone, Debug, Deserialize, Display, PartialEq, PartialOrd, Serialize)]
pub enum VerifyError {
    /// There was an error verifying the signature: {0}
    Signature(SignatureError),
    /// JSON parsing error: {0}
    Json(JsonError),
    /// Expected IAS API version {0}, found {1}
    VersionMismatch(f64, f64),
    /// IAS nonce error: {0}
    Nonce(NonceError),
    /// Error verifying the quote contents: {0}
    Quote(QuoteError),
    /// IAS returned an error: {0}
    IasQuote(IasQuoteError),
    /// IAS returned a PSE manifest error: {0}
    PseManifest(PseManifestError),
    /// There was an error decoding the manifest hash: {0}
    PseManifestHash(PseManifestHashError),
    /// There was an error decoding the platform info blob: {0}
    Pib(PibError),
    /// The EPID psuedonym could not be parsed: {0}
    EpidPseudonym(EpidPseudonymError),
    /// The quote in a verification report does not match the expected quote.
    IasQuoteMismatch,
    /// There was an error parsing the timestamp {0}: {1}
    TimestampParse(String, String),
    /// There was an unknown error
    Unknown,
}

impl From<SignatureError> for VerifyError {
    fn from(src: SignatureError) -> VerifyError {
        VerifyError::Signature(src)
    }
}

impl From<JsonError> for VerifyError {
    fn from(src: JsonError) -> VerifyError {
        VerifyError::Json(src)
    }
}

impl From<IasQuoteError> for VerifyError {
    fn from(src: IasQuoteError) -> VerifyError {
        VerifyError::IasQuote(src)
    }
}

impl From<QuoteError> for VerifyError {
    fn from(src: QuoteError) -> VerifyError {
        VerifyError::Quote(src)
    }
}

impl From<PseManifestError> for VerifyError {
    fn from(src: PseManifestError) -> VerifyError {
        VerifyError::PseManifest(src)
    }
}

impl From<PseManifestHashError> for VerifyError {
    fn from(src: PseManifestHashError) -> VerifyError {
        VerifyError::PseManifestHash(src)
    }
}

impl From<NonceError> for VerifyError {
    fn from(src: NonceError) -> VerifyError {
        VerifyError::Nonce(src)
    }
}

impl From<EpidPseudonymError> for VerifyError {
    fn from(src: EpidPseudonymError) -> VerifyError {
        VerifyError::EpidPseudonym(src)
    }
}
