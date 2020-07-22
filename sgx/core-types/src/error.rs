// Copyright (c) 2018-2020 MobileCoin Inc.

//! SGX Error types

use core::{convert::TryFrom, result::Result as StdResult};
use displaydoc::Display;
use mc_sgx_core_types_sys::{
    sgx_status_t, SGX_ERROR_AE_INVALID_EPIDBLOB, SGX_ERROR_AE_SESSION_INVALID,
    SGX_ERROR_ATT_KEY_CERTIFICATION_FAILURE, SGX_ERROR_ATT_KEY_UNINITIALIZED, SGX_ERROR_BUSY,
    SGX_ERROR_DEVICE_BUSY, SGX_ERROR_ECALL_NOT_ALLOWED, SGX_ERROR_ENCLAVE_CRASHED,
    SGX_ERROR_ENCLAVE_FILE_ACCESS, SGX_ERROR_ENCLAVE_LOST, SGX_ERROR_EPID_MEMBER_REVOKED,
    SGX_ERROR_FEATURE_NOT_SUPPORTED, SGX_ERROR_FILE_BAD_STATUS,
    SGX_ERROR_FILE_CANT_OPEN_RECOVERY_FILE, SGX_ERROR_FILE_CANT_WRITE_RECOVERY_FILE,
    SGX_ERROR_FILE_CLOSE_FAILED, SGX_ERROR_FILE_FLUSH_FAILED, SGX_ERROR_FILE_NAME_MISMATCH,
    SGX_ERROR_FILE_NOT_SGX_FILE, SGX_ERROR_FILE_NO_KEY_ID, SGX_ERROR_FILE_RECOVERY_NEEDED,
    SGX_ERROR_INVALID_ATTRIBUTE, SGX_ERROR_INVALID_ATT_KEY_CERT_DATA, SGX_ERROR_INVALID_CPUSVN,
    SGX_ERROR_INVALID_ENCLAVE, SGX_ERROR_INVALID_ENCLAVE_ID, SGX_ERROR_INVALID_FUNCTION,
    SGX_ERROR_INVALID_ISVSVN, SGX_ERROR_INVALID_KEYNAME, SGX_ERROR_INVALID_LAUNCH_TOKEN,
    SGX_ERROR_INVALID_METADATA, SGX_ERROR_INVALID_MISC, SGX_ERROR_INVALID_PARAMETER,
    SGX_ERROR_INVALID_SIGNATURE, SGX_ERROR_INVALID_STATE, SGX_ERROR_INVALID_VERSION,
    SGX_ERROR_KDF_MISMATCH, SGX_ERROR_MAC_MISMATCH, SGX_ERROR_MC_NOT_FOUND,
    SGX_ERROR_MC_NO_ACCESS_RIGHT, SGX_ERROR_MC_OVER_QUOTA, SGX_ERROR_MC_USED_UP,
    SGX_ERROR_MEMORY_MAP_CONFLICT, SGX_ERROR_MODE_INCOMPATIBLE, SGX_ERROR_NDEBUG_ENCLAVE,
    SGX_ERROR_NETWORK_FAILURE, SGX_ERROR_NO_DEVICE, SGX_ERROR_NO_PRIVILEGE,
    SGX_ERROR_OCALL_NOT_ALLOWED, SGX_ERROR_OUT_OF_EPC, SGX_ERROR_OUT_OF_MEMORY,
    SGX_ERROR_OUT_OF_TCS, SGX_ERROR_PCL_ENCRYPTED, SGX_ERROR_PCL_GUID_MISMATCH,
    SGX_ERROR_PCL_MAC_MISMATCH, SGX_ERROR_PCL_NOT_ENCRYPTED, SGX_ERROR_PCL_SHA_MISMATCH,
    SGX_ERROR_PLATFORM_CERT_UNAVAILABLE, SGX_ERROR_SERVICE_INVALID_PRIVILEGE,
    SGX_ERROR_SERVICE_TIMEOUT, SGX_ERROR_SERVICE_UNAVAILABLE, SGX_ERROR_STACK_OVERRUN,
    SGX_ERROR_UNDEFINED_SYMBOL, SGX_ERROR_UNEXPECTED, SGX_ERROR_UNRECOGNIZED_PLATFORM,
    SGX_ERROR_UNSUPPORTED_ATT_KEY_ID, SGX_ERROR_UNSUPPORTED_CONFIG, SGX_ERROR_UPDATE_NEEDED,
    SGX_INTERNAL_ERROR_ENCLAVE_CREATE_INTERRUPTED, SGX_PTHREAD_EXIT, SGX_SUCCESS,
};
#[cfg(feature = "use_serde")]
use serde::{Deserialize, Serialize};

/// A type alias for an SGX result.
pub type Result<T> = StdResult<T, Error>;

/// A trait which supports converting one's self into a [`Result`].
pub trait SgxStatusToResult<T> {
    /// Convert one's self into a Result.
    fn into_result(self, success: T) -> Result<T>;
}

impl<T> SgxStatusToResult<T> for sgx_status_t {
    fn into_result(self, success: T) -> Result<T> {
        match self {
            SGX_SUCCESS => Ok(success),
            other => {
                Err(Error::try_from(other).expect("Invalid SGX result, rust SDK is out of date"))
            }
        }
    }
}

/// A enumeration of SGX errors.
///
/// Those listed here are the ones which are identified in the
/// [`sgx_status_t`](mc_sgx_core_types_sys::sgx_status_t) enum, in order of the actual value. Note
/// that values are grouped (numerically) into the following general sections:
///
///  1. `0x0000`: Unknown (Success in `sgx_status_t`)
///  1. `0x0001-0x0fff`: Generic errors.
///  2. `0x1000-0x1fff`: Fatal runtime errors.
///  3. `0x2000-0x2fff`: Enclave creation errors.
///  4. `0x3000-0x3fff`: Local attestation/report verification errors.
///  5. `0x4000-0x4fff`: Errors when communicating with the Architectural Enclave Service Manager (AESM).
///  6. `0x5000-0x5fff`: Errors internal to AESM.
///  7. `0x6000-0x6fff`: Errors with the encrypted enclave loader.
///  8. `0x7000-0x7fff`: Errors with the "SGX Encrypted FS" utility.
///  9. `0x8000-0x8fff`: Attestation key errors.
/// 10. `0xf000-0xffff`: Internal (to SGX) errors.
#[cfg_attr(feature = "use_serde", derive(Deserialize, Serialize))]
#[derive(Copy, Clone, Debug, Display, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(u32)]
pub enum Error {
    /// A catch-all for unknown error messages
    Unknown = 0,

    // 0x0001 - 0x0fff: Generic errors
    /// An unexpected error (`0x0001`)
    Unexpected = SGX_ERROR_UNEXPECTED,
    /// The parameter is incorrect (`0x0002`)
    InvalidParameter = SGX_ERROR_INVALID_PARAMETER,
    /// There is not enough memory available to complete this operation (`0x0003`)
    OutOfMemory = SGX_ERROR_OUT_OF_MEMORY,
    /// The enclave was lost after power transition or used in a child process created by fork() (`0x0004`)
    EnclaveLost = SGX_ERROR_ENCLAVE_LOST,
    /// The API is invoked in incorrect order or state (`0x0005`)
    InvalidState = SGX_ERROR_INVALID_STATE,
    /// The feature is not supported (`0x0008`)
    FeatureNotSupported = SGX_ERROR_FEATURE_NOT_SUPPORTED,
    /// A thread in the enclave exited (`0x0009`)
    ThreadExit = SGX_PTHREAD_EXIT,

    // 0x1001 - 0x1fff: Fatal runtime errors
    /// The ECALL or OCALL function index is incorrect (`0x1001`)
    InvalidFunction = SGX_ERROR_INVALID_FUNCTION,
    /// The enclave is out of Thread Control Structures (`0x1003`)
    OutOfTcs = SGX_ERROR_OUT_OF_TCS,
    /// The enclave crashed (`0x1006`)
    EnclaveCrashed = SGX_ERROR_ENCLAVE_CRASHED,
    /// ECALL is not allowed at this time (`0x1007`)
    ///
    /// Possible reasons include:
    ///
    ///  * ECALL is not public.
    ///  * ECALL is blocked by the dynamic entry table.
    ///  * A nested ECALL is not allowed during global initialization.
    EcallNotAllowed = SGX_ERROR_ECALL_NOT_ALLOWED,
    /// OCALL is not allowed during exception handling (`0x1008`)
    OcallNotAllowed = SGX_ERROR_OCALL_NOT_ALLOWED,
    /// Stack overrun occurs within the enclave (`0x1009`)
    StackOverrun = SGX_ERROR_STACK_OVERRUN,

    // 0x2000 - 0x2fff: Enclave construction errors
    /// The enclave contains an undefined symbol (`0x2000`)
    UndefinedSymbol = SGX_ERROR_UNDEFINED_SYMBOL,
    /// The enclave image has been corrupted (`0x2001`)
    InvalidEnclave = SGX_ERROR_INVALID_ENCLAVE,
    /// The enclave ID is invalid (`0x2002`)
    InvalidEnclaveId = SGX_ERROR_INVALID_ENCLAVE_ID,
    /// The signature for the enclave is invalid (`0x2003`)
    InvalidSignature = SGX_ERROR_INVALID_SIGNATURE,
    /// The enclave was signed as a production enclave, and cannot be instantiated as debuggable (`0x2004`)
    NdebugEnclave = SGX_ERROR_NDEBUG_ENCLAVE,
    /// There is not enough EPC (encrypted page cache) available to load the enclave or one of the Architecture Enclaves needed to complete the operation requested (`0x2005`)
    OutOfEpc = SGX_ERROR_OUT_OF_EPC,
    /// Cannot open the device (`0x2006`)
    NoDevice = SGX_ERROR_NO_DEVICE,
    /// Page mapping failed in the driver (`0x2007`)
    MemoryMapConflict = SGX_ERROR_MEMORY_MAP_CONFLICT,
    /// The metadata is incorrect (`0x2009`)
    InvalidMetadata = SGX_ERROR_INVALID_METADATA,
    /// The device is busy (`0x200C`)
    DeviceBusy = SGX_ERROR_DEVICE_BUSY,
    /// Metadata version is inconsistent between uRTS and `sgx_sign` or the uRTS is incompatible with the current platform (`0x200D`)
    InvalidVersion = SGX_ERROR_INVALID_VERSION,
    /// The target enclave mode (either 32 vs. 64-bit, or hardware vs. simulation) is incompatible with the untrusted mode (`0x200E`)
    ModeIncompatible = SGX_ERROR_MODE_INCOMPATIBLE,
    /// Cannot open the enclave file (`0x200F`)
    EnclaveFileAccess = SGX_ERROR_ENCLAVE_FILE_ACCESS,
    /// The MiscSelect or MiscMask settings are incorrect (`0x2010`)
    InvalidMisc = SGX_ERROR_INVALID_MISC,
    /// The launch token is incorrect (`0x2011`)
    InvalidLaunchToken = SGX_ERROR_INVALID_LAUNCH_TOKEN,

    // 0x3001-0x3fff: Report verification
    /// Report verification error (`0x3001`)
    MacMismatch = SGX_ERROR_MAC_MISMATCH,
    /// The enclave is not authorized (`0x3002`)
    InvalidAttribute = SGX_ERROR_INVALID_ATTRIBUTE,
    /// The CPU security version of this platform is too old (`0x3003`)
    InvalidCpuSvn = SGX_ERROR_INVALID_CPUSVN,
    /// The enclave security version is too old (`0x3004`)
    InvalidIsvSvn = SGX_ERROR_INVALID_ISVSVN,
    /// Unsupported key name value (`0x3005`)
    InvalidKeyname = SGX_ERROR_INVALID_KEYNAME,

    // 0x4000 - 0x4fff: AESM
    /// Architectural Enclave service does not respond or the requested service is not supported (`0x4001`)
    ServiceUnavailable = SGX_ERROR_SERVICE_UNAVAILABLE,
    /// The request to the Architectural Enclave service timed out (`0x4002`)
    ServiceTimeout = SGX_ERROR_SERVICE_TIMEOUT,
    /// Intel EPID blob verification error (`0x4003`)
    AeInvalidEpidblob = SGX_ERROR_AE_INVALID_EPIDBLOB,
    /// Enclave has no privilege to get a launch token (`0x4004`)
    ServiceInvalidPrivilege = SGX_ERROR_SERVICE_INVALID_PRIVILEGE,
    /// The EPID group membership has been revoked  (`0x4005`)
    ///
    /// The platform is not trusted,and will not be trusted even if updated
    EpidMemberRevoked = SGX_ERROR_EPID_MEMBER_REVOKED,
    /// Intel SGX requires update (`0x4006`)
    UpdateNeeded = SGX_ERROR_UPDATE_NEEDED,
    /// Network or proxy issue (`0x4007`)
    NetworkFailure = SGX_ERROR_NETWORK_FAILURE,
    /// The Architectural Enclave session is invalid or ended by the server (`0x4008`)
    AeSessionInvalid = SGX_ERROR_AE_SESSION_INVALID,
    /// The requested service is temporarily not available (`0x400A`)
    Busy = SGX_ERROR_BUSY,
    /// The Monotonic Counter does not exist or has been invalidated (`0x400C`)
    McNotFound = SGX_ERROR_MC_NOT_FOUND,
    /// The caller does not have the access right to the specified Virtual Monotonic Counter (`0x400D`)
    McNoAccessRight = SGX_ERROR_MC_NO_ACCESS_RIGHT,
    /// No monotonic counter is available (`0x400E`)
    McUsedUp = SGX_ERROR_MC_USED_UP,
    /// Monotonic counters reached quote limit (`0x400F`)
    McOverQuota = SGX_ERROR_MC_OVER_QUOTA,
    /// Key derivation function did not match during key exchange (`0x4011`)
    KdfMismatch = SGX_ERROR_KDF_MISMATCH,
    /// Intel EPID provisioning failed because the platform is not recognized by the back-end server (`0x4012`)
    UnrecognizedPlatform = SGX_ERROR_UNRECOGNIZED_PLATFORM,
    /// There are unsupported bits in the config (`0x4013`)
    UnsupportedConfig = SGX_ERROR_UNSUPPORTED_CONFIG,

    // 0x5000 - 0x5fff: AESM-internal errors
    /// The application does not have the privilege needed to read UEFI variables (`0x5002`)
    NoPrivilege = SGX_ERROR_NO_PRIVILEGE,

    // 0x6000 - 0x6fff: Encrypted Enclaves
    /// Trying to load an encrypted enclave using API or parameters for plaintext enclaves (`0x6001`)
    PclEncrypted = SGX_ERROR_PCL_ENCRYPTED,
    /// Trying to load an enclave that is not encrypted with using API or parameters for encrypted enclaves (`0x6002`)
    PclNotEncrypted = SGX_ERROR_PCL_NOT_ENCRYPTED,
    /// The runtime AES-GCM-128 MAC result of an encrypted section does not match the one used at build time (`0x6003`)
    PclMacMismatch = SGX_ERROR_PCL_MAC_MISMATCH,
    /// The runtime SHA256 hash of the decryption key does not match the one used at build time (`0x6004`)
    PclShaMismatch = SGX_ERROR_PCL_SHA_MISMATCH,
    /// The GUID in the decryption key sealed blob does not match the one used at build time (`0x6005`)
    PclGuidMismatch = SGX_ERROR_PCL_GUID_MISMATCH,

    // 0x7000 - 0x7fff: SGX Encrypted FS
    /// The file is in a bad status, run sgx_clearerr to try and fix it (`0x7001`)
    FileBadStatus = SGX_ERROR_FILE_BAD_STATUS,
    /// The Key ID field is all zeroes, the encryption key cannot be regenerated (`0x7002`)
    FileNoKeyId = SGX_ERROR_FILE_NO_KEY_ID,
    /// The current file name is different from the original file name (substitution attack) (`0x7003`)
    FileNameMismatch = SGX_ERROR_FILE_NAME_MISMATCH,
    /// The file is not an Intel SGX file (`0x7004`)
    FileNotSgxFile = SGX_ERROR_FILE_NOT_SGX_FILE,
    /// A recovery file cannot be opened, so the flush operation cannot continue (`0x7005`)
    FileCantOpenRecoveryFile = SGX_ERROR_FILE_CANT_OPEN_RECOVERY_FILE,
    /// A recovery file cannot be written, so the flush operation cannot continue (`0x7006`)
    FileCantWriteRecoveryFile = SGX_ERROR_FILE_CANT_WRITE_RECOVERY_FILE,
    /// When opening the file, recovery is needed, but the recovery process failed (`0x7007`)
    FileRecoveryNeeded = SGX_ERROR_FILE_RECOVERY_NEEDED,
    /// The fflush() operation failed (`0x7008`)
    FileFlushFailed = SGX_ERROR_FILE_FLUSH_FAILED,
    /// The fclose() operation failed (`0x7009`)
    FileCloseFailed = SGX_ERROR_FILE_CLOSE_FAILED,

    // 0x8000-0x8fff: Custom Attestation support
    /// Platform quoting infrastructure does not support the key (`0x8001`)
    UnsupportedAttKeyId = SGX_ERROR_UNSUPPORTED_ATT_KEY_ID,
    /// Failed to generate and certify the attestation key (`0x8002`)
    AttKeyCertificationFailure = SGX_ERROR_ATT_KEY_CERTIFICATION_FAILURE,
    /// The platform quoting infrastructure does not have the attestation key available to generate a quote (`0x8003`)
    AttKeyUninitialized = SGX_ERROR_ATT_KEY_UNINITIALIZED,
    /// The data returned by sgx_get_quote_config() is invalid (`0x8004`)
    InvalidAttKeyCertData = SGX_ERROR_INVALID_ATT_KEY_CERT_DATA,
    /// The PCK cert for the platform is not available (`0x8005`)
    PlatformCertUnavailable = SGX_ERROR_PLATFORM_CERT_UNAVAILABLE,

    // 0xf000-0xffff: Internal-to-SGX errors
    /// The ioctl for enclave_create unexpectedly failed with EINTR (`0xf000`)
    EnclaveCreateInterrupted = SGX_INTERNAL_ERROR_ENCLAVE_CREATE_INTERRUPTED,
}

impl Error {
    /// Check if the given i32 value is a valid value.
    ///
    /// This is a little convoluted, because zero in `sgx_status_t` is a the success value (i.e. not
    /// an error), whereas zero in this type is the catch-all unknown error.
    //
    // This method is normally implemented by prost via derive(Enumeration), but clang is
    // determined to represent the [`sgx_status_t`](mc_sgx_core_types_sys::sgx_status_t)
    // enumeration as a `u32`, standards be damned.
    pub fn is_valid(value: i32) -> bool {
        Self::from_i32(value).is_some()
    }

    /// Create a new Error from the given i32 value.
    ///
    /// This is a little convoluted, because zero in `sgx_status_t` is a the success value (i.e. not
    /// an error), whereas zero in this type is the catch-all unknown error.
    //
    // This method is normally implemented by prost via derive(Enumeration), but clang is
    // determined to represent the [`sgx_status_t`](mc_sgx_core_types_sys::sgx_status_t)
    // enumeration as a `u32`, standards be damned.
    pub fn from_i32(value: i32) -> Option<Error> {
        match value {
            0 => Some(Error::Unknown),
            other => Self::try_from(other as sgx_status_t).ok(),
        }
    }
}

impl Default for Error {
    fn default() -> Self {
        Error::Unknown
    }
}

impl TryFrom<sgx_status_t> for Error {
    type Error = ();

    fn try_from(src: sgx_status_t) -> StdResult<Error, ()> {
        match src {
            0 => Err(()),
            0x0001 => Ok(Error::Unexpected),
            0x0002 => Ok(Error::InvalidParameter),
            0x0003 => Ok(Error::OutOfMemory),
            0x0004 => Ok(Error::EnclaveLost),
            0x0005 => Ok(Error::InvalidState),
            0x0008 => Ok(Error::FeatureNotSupported),
            0x0009 => Ok(Error::ThreadExit),

            0x1001 => Ok(Error::InvalidFunction),
            0x1003 => Ok(Error::OutOfTcs),
            0x1006 => Ok(Error::EnclaveCrashed),
            0x1007 => Ok(Error::EcallNotAllowed),
            0x1008 => Ok(Error::OcallNotAllowed),
            0x1009 => Ok(Error::StackOverrun),

            0x2000 => Ok(Error::UndefinedSymbol),
            0x2001 => Ok(Error::InvalidEnclave),
            0x2002 => Ok(Error::InvalidEnclaveId),
            0x2003 => Ok(Error::InvalidSignature),
            0x2004 => Ok(Error::NdebugEnclave),
            0x2005 => Ok(Error::OutOfEpc),
            0x2006 => Ok(Error::NoDevice),
            0x2007 => Ok(Error::MemoryMapConflict),
            0x2009 => Ok(Error::InvalidMetadata),
            0x200c => Ok(Error::DeviceBusy),
            0x200d => Ok(Error::InvalidVersion),
            0x200e => Ok(Error::ModeIncompatible),
            0x200f => Ok(Error::EnclaveFileAccess),
            0x2010 => Ok(Error::InvalidMisc),
            0x2011 => Ok(Error::InvalidLaunchToken),

            0x3001 => Ok(Error::MacMismatch),
            0x3002 => Ok(Error::InvalidAttribute),
            0x3003 => Ok(Error::InvalidCpuSvn),
            0x3004 => Ok(Error::InvalidIsvSvn),
            0x3005 => Ok(Error::InvalidKeyname),

            0x4001 => Ok(Error::ServiceUnavailable),
            0x4002 => Ok(Error::ServiceTimeout),
            0x4003 => Ok(Error::AeInvalidEpidblob),
            0x4004 => Ok(Error::ServiceInvalidPrivilege),
            0x4005 => Ok(Error::EpidMemberRevoked),
            0x4006 => Ok(Error::UpdateNeeded),
            0x4007 => Ok(Error::NetworkFailure),
            0x4008 => Ok(Error::AeSessionInvalid),
            0x400a => Ok(Error::Busy),
            0x400c => Ok(Error::McNotFound),
            0x400d => Ok(Error::McNoAccessRight),
            0x400e => Ok(Error::McUsedUp),
            0x400f => Ok(Error::McOverQuota),
            0x4011 => Ok(Error::KdfMismatch),
            0x4012 => Ok(Error::UnrecognizedPlatform),
            0x4013 => Ok(Error::UnsupportedConfig),

            0x5002 => Ok(Error::NoPrivilege),

            0x6001 => Ok(Error::PclEncrypted),
            0x6002 => Ok(Error::PclNotEncrypted),
            0x6003 => Ok(Error::PclMacMismatch),
            0x6004 => Ok(Error::PclShaMismatch),
            0x6005 => Ok(Error::PclGuidMismatch),

            0x7001 => Ok(Error::FileBadStatus),
            0x7002 => Ok(Error::FileNoKeyId),
            0x7003 => Ok(Error::FileNameMismatch),
            0x7004 => Ok(Error::FileNotSgxFile),
            0x7005 => Ok(Error::FileCantOpenRecoveryFile),
            0x7006 => Ok(Error::FileCantWriteRecoveryFile),
            0x7007 => Ok(Error::FileRecoveryNeeded),
            0x7008 => Ok(Error::FileFlushFailed),
            0x7009 => Ok(Error::FileCloseFailed),

            0x8001 => Ok(Error::UnsupportedAttKeyId),
            0x8002 => Ok(Error::AttKeyCertificationFailure),
            0x8003 => Ok(Error::AttKeyUninitialized),
            0x8004 => Ok(Error::InvalidAttKeyCertData),
            0x8005 => Ok(Error::PlatformCertUnavailable),

            0xF001 => Ok(Error::EnclaveCreateInterrupted),

            _ => Ok(Error::Unknown),
        }
    }
}
