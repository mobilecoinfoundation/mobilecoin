// Copyright (c) 2018-2020 MobileCoin Inc.

//! SGX Error types

use core::{convert::TryFrom, result::Result as StdResult};
use failure::Fail;
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
    SGX_INTERNAL_ERROR_ENCLAVE_CREATE_INTERRUPTED, SGX_PTHREAD_EXIT,
};
use serde::{Deserialize, Serialize};

/// A type alias for an SGX result.
pub type Result<T> = StdResult<T, Error>;

/// A enumeration of SGX errors.
///
/// Those listed here are the ones which are identified in the `sgx_status_t` enum, in order of
/// the actual value. Note that values are grouped (numerically) into the following general
/// sections:
///
///  1. `0x0000-0x0fff`: Generic errors.
///  2. `0x1000-0x1fff`: Fatal runtime errors.
///  3. `0x2000-0x2fff`: Enclave creation errors.
///  4. `0x3000-0x3fff`: Local attestation/report verification errors.
///  5. `0x4000-0x4fff`: Errors when communicating with the Architectural Enclave Service Manager (AESM).
///  6. `0x5000-0x5fff`: Errors internal to AESM.
///  7. `0x6000-0x6fff`: Errors with the encrypted enclave loader.
///  8. `0x7000-0x7fff`: Errors with the "SGX Encrypted FS" utility.
///  9. `0x8000-0x8fff`: Attestation key errors.
/// 10. `0xf000-0xffff`: Internal (to SGX) errors.
#[repr(u32)]
#[derive(Copy, Clone, Debug, Eq, Fail, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub enum Error {
    // 0x0001 - 0x0fff: Generic errors
    /// `0x0001`, An unexpected error.
    #[fail(display = "An unexpected error")]
    Unexpected = SGX_ERROR_UNEXPECTED,
    /// The parameter is incorrect (`0x0002`).
    #[fail(display = "The parameter is incorrect")]
    InvalidParameter = SGX_ERROR_INVALID_PARAMETER,
    /// There is not enough memory available to complete this operation (`0x0003`).
    #[fail(display = "There is not enough memory available to complete this operation")]
    OutOfMemory = SGX_ERROR_OUT_OF_MEMORY,
    /// The enclave was lost after power transition or used in a child process created by fork() (`0x0004`).
    #[fail(
        display = "The enclave was lost after power transition or used in a child process created by fork()"
    )]
    EnclaveLost = SGX_ERROR_ENCLAVE_LOST,
    /// The API is invoked in incorrect order or state (`0x0005`).
    #[fail(display = "The API is invoked in incorrect order or state")]
    InvalidState = SGX_ERROR_INVALID_STATE,
    /// The feature is not supported (`0x0008`).
    #[fail(display = "The feature is not supported")]
    FeatureNotSupported = SGX_ERROR_FEATURE_NOT_SUPPORTED,
    /// A thread in the enclave exited (`0x0009`)
    #[fail(display = "A thread in the enclave exited")]
    ThreadExit = SGX_PTHREAD_EXIT,

    // 0x1001 - 0x1fff: Fatal runtime errors
    /// The ECALL or OCALL function index is incorrect (`0x1001`).
    #[fail(display = "The ECALL or OCALL function index is incorrect")]
    InvalidFunction = SGX_ERROR_INVALID_FUNCTION,
    /// The enclave is out of Thread Control Structures (`0x1003`).
    #[fail(display = "The enclave is out of TCS")]
    OutOfTcs = SGX_ERROR_OUT_OF_TCS,
    /// The enclave crashed (`0x1006`).
    #[fail(display = "The enclave crashed")]
    EnclaveCrashed = SGX_ERROR_ENCLAVE_CRASHED,
    /// ECALL is not allowed at this time (`0x1007`).
    ///
    /// Possible reasons include:
    ///
    ///  * ECALL is not public.
    ///  * ECALL is blocked by the dynamic entry table.
    ///  * A nested ECALL is not allowed during global initialization.
    #[fail(
        display = "ECALL not allowed because it is not public, blocked by a dynamic entry table, or nested during global initialization"
    )]
    EcallNotAllowed = SGX_ERROR_ECALL_NOT_ALLOWED,
    /// OCALL is not allowed during exception handling (`0x1008`).
    #[fail(display = "OCALL is not allowed during exception handling")]
    OcallNotAllowed = SGX_ERROR_OCALL_NOT_ALLOWED,
    /// Stack overrun occurs within the enclave (`0x1009`).
    #[fail(display = "Stack overrun occurs within the enclave")]
    StackOverrun = SGX_ERROR_STACK_OVERRUN,

    // 0x2000 - 0x2fff: Enclave construction errors
    /// The enclave contains an undefined symbol (`0x2000`).
    #[fail(display = "The enclave contains an undefined symbol")]
    UndefinedSymbol = SGX_ERROR_UNDEFINED_SYMBOL,
    /// The enclave image has been corrupted (`0x2001`).
    #[fail(display = "The enclave image has been corrupted")]
    InvalidEnclave = SGX_ERROR_INVALID_ENCLAVE,
    /// The enclave ID is invalid (`0x2002`).
    #[fail(display = "The enclave ID is invalid")]
    InvalidEnclaveId = SGX_ERROR_INVALID_ENCLAVE_ID,
    /// The signature for the enclave is invalid (`0x2003`).
    #[fail(display = "The signature for the enclave is invalid")]
    InvalidSignature = SGX_ERROR_INVALID_SIGNATURE,
    /// The enclave was signed as a production enclave, and cannot be instantiated as debuggable (`0x2004`).
    #[fail(
        display = "The enclave was signed as a production enclave, and cannot be instantiated as debuggable"
    )]
    NdebugEnclave = SGX_ERROR_NDEBUG_ENCLAVE,
    /// There is not enough EPC (encrypted page cache) available to load the enclave or one of the Architecture Enclaves needed to complete the operation requested (`0x2005`).
    #[fail(
        display = "There is not enough EPC (encrypted memory) available to load the enclave or one of the Architecture Enclaves needed to complete the operation requested"
    )]
    OutOfEpc = SGX_ERROR_OUT_OF_EPC,
    /// Cannot open the device (`0x2006`).
    #[fail(display = "Cannot open the device")]
    NoDevice = SGX_ERROR_NO_DEVICE,
    /// Page mapping failed in the driver (`0x2007`).
    #[fail(display = "Page mapping failed in the driver")]
    MemoryMapConflict = SGX_ERROR_MEMORY_MAP_CONFLICT,
    /// The metadata is incorrect (`0x2009`).
    #[fail(display = "The metadata is incorrect")]
    InvalidMetadata = SGX_ERROR_INVALID_METADATA,
    /// The device is busy (`0x200C`)
    #[fail(display = "Device is busy")]
    DeviceBusy = SGX_ERROR_DEVICE_BUSY,
    /// Metadata version is inconsistent between uRTS and `sgx_sign` or the uRTS is incompatible with the current platform (`0x200D`).
    #[fail(
        display = "Metadata version is inconsistent between uRTS and `sgx_sign` or the uRTS is incompatible with the current platform"
    )]
    InvalidVersion = SGX_ERROR_INVALID_VERSION,
    /// The target enclave mode (either 32 vs. 64-bit, or hardware vs. simulation) is incompatible with the untrusted mode (`0x200E`).
    #[fail(
        display = "The target enclave mode (either 32 vs. 64-bit, or hardware vs. simulation) is incompatible with the untrusted mode"
    )]
    ModeIncompatible = SGX_ERROR_MODE_INCOMPATIBLE,
    /// Cannot open the enclave file (`0x200F`).
    #[fail(display = "Cannot open the enclave file")]
    EnclaveFileAccess = SGX_ERROR_ENCLAVE_FILE_ACCESS,
    /// The MiscSelect or MiscMask settings are incorrect (`0x2010`).
    #[fail(display = "The MiscSelect or MiscMask settings are incorrect")]
    InvalidMisc = SGX_ERROR_INVALID_MISC,
    /// The launch token is incorrect (`0x2011`).
    #[fail(display = "The launch token is incorrect")]
    InvalidLaunchToken = SGX_ERROR_INVALID_LAUNCH_TOKEN,

    // 0x3001-0x3fff: Report verification
    /// Report verification error (`0x3001`).
    #[fail(display = "Report verification error")]
    MacMismatch = SGX_ERROR_MAC_MISMATCH,
    /// The enclave is not authorized (`0x3002`).
    #[fail(display = "The enclave is not authorized")]
    InvalidAttribute = SGX_ERROR_INVALID_ATTRIBUTE,
    /// The CPU security version of this platform is too old (`0x3003`).
    #[fail(display = "The CPU security version of this platform is too old")]
    InvalidCpuSvn = SGX_ERROR_INVALID_CPUSVN,
    /// The enclave security version is too old (`0x3004`).
    #[fail(display = "The enclave security version is too old")]
    InvalidIsvSvn = SGX_ERROR_INVALID_ISVSVN,
    /// Unsupported key name value (`0x3005`).
    #[fail(display = "Unsupported key name value")]
    InvalidKeyname = SGX_ERROR_INVALID_KEYNAME,

    // 0x4000 - 0x4fff: AESM
    /// Architectural Enclave service does not respond or the requested service is not supported (`0x4001`).
    #[fail(
        display = "Architectural Enclave service does not respond or the requested service is not supported"
    )]
    ServiceUnavailable = SGX_ERROR_SERVICE_UNAVAILABLE,
    /// The request to the Architectural Enclave service timed out (`0x4002`).
    #[fail(display = "The request to the Architectural Enclave service timed out")]
    ServiceTimeout = SGX_ERROR_SERVICE_TIMEOUT,
    /// Intel EPID blob verification error (`0x4003`).
    #[fail(display = "Intel EPID blob verification error")]
    AeInvalidEpidblob = SGX_ERROR_AE_INVALID_EPIDBLOB,
    /// Enclave has no privilege to get a launch token (`0x4004`).
    #[fail(display = "Enclave has no privilege to get a launch token")]
    ServiceInvalidPrivilege = SGX_ERROR_SERVICE_INVALID_PRIVILEGE,
    /// The EPID group membership has been revoked  (`0x4005`).
    ///
    /// The platform is not trusted,and will not be trusted even if updated.
    #[fail(
        display = "The EPID group membership has been revoked, and the platform cannot be trusted, even with updates"
    )]
    EpidMemberRevoked = SGX_ERROR_EPID_MEMBER_REVOKED,
    /// Intel SGX requires update (`0x4006`).
    #[fail(display = "Intel SGX requires update")]
    UpdateNeeded = SGX_ERROR_UPDATE_NEEDED,
    /// Network or proxy issue (`0x4007`).
    #[fail(display = "Network or proxy issue")]
    NetworkFailure = SGX_ERROR_NETWORK_FAILURE,
    /// The Architectural Enclave session is invalid or ended by the server (`0x4008`).
    #[fail(display = "The session is invalid or ended by the server")]
    AeSessionInvalid = SGX_ERROR_AE_SESSION_INVALID,
    /// The requested service is temporarily not available (`0x400A`).
    #[fail(display = "The requested service is temporarily not available")]
    Busy = SGX_ERROR_BUSY,
    /// The Monotonic Counter does not exist or has been invalidated (`0x400C`).
    #[fail(display = "The Monotonic Counter does not exist or has been invalidated")]
    McNotFound = SGX_ERROR_MC_NOT_FOUND,
    /// The caller does not have the access right to the specified Virtual Monotonic Counter (`0x400D`).
    #[fail(
        display = "The caller does not have the access right to the specified Virtual Monotonic Counter"
    )]
    McNoAccessRight = SGX_ERROR_MC_NO_ACCESS_RIGHT,
    /// No monotonic counter is available (`0x400E`).
    #[fail(display = "No monotonic counter is available")]
    McUsedUp = SGX_ERROR_MC_USED_UP,
    /// Monotonic counters reached quote limit (`0x400F`).
    #[fail(display = "Monotonic counters reached quote limit")]
    McOverQuota = SGX_ERROR_MC_OVER_QUOTA,
    /// Key derivation function did not match during key exchange (`0x4011`).
    #[fail(display = "Key derivation function did not match during key exchange")]
    KdfMismatch = SGX_ERROR_KDF_MISMATCH,
    /// Intel EPID provisioning failed because the platform is not recognized by the back-end server (`0x4012`).
    #[fail(
        display = "Intel EPID provisioning failed because the platform is not recognized by the back-end server"
    )]
    UnrecognizedPlatform = SGX_ERROR_UNRECOGNIZED_PLATFORM,
    /// There are unsupported bits in the config (`0x4013`).
    #[fail(display = "There are unsupported bits in the config")]
    UnsupportedConfig = SGX_ERROR_UNSUPPORTED_CONFIG,

    // 0x5000 - 0x5fff: AESM-internal errors
    /// The application does not have the privilege needed to read UEFI variables (`0x5002`).
    #[fail(display = "The application does not have the privilege needed to read UEFI variables")]
    NoPrivilege = SGX_ERROR_NO_PRIVILEGE,

    // 0x6000 - 0x6fff: Encrypted Enclaves
    /// Trying to load an encrypted enclave using API or parameters for plaintext enclaves (`0x6001`).
    #[fail(
        display = "Trying to load an encrypted enclave using API or parameters for plaintext enclaves"
    )]
    PclEncrypted = SGX_ERROR_PCL_ENCRYPTED,
    /// Trying to load an enclave that is not encrypted with using API or parameters for encrypted enclaves (`0x6002`).
    #[fail(
        display = "Trying to load an enclave that is not encrypted with using API or parameters for encrypted enclaves"
    )]
    PclNotEncrypted = SGX_ERROR_PCL_NOT_ENCRYPTED,
    /// The runtime AES-GCM-128 MAC result of an encrypted section does not match the one used at build time (`0x6003`).
    #[fail(
        display = "The runtime AES-GCM-128 MAC result of an encrypted section does not match the one used at build time"
    )]
    PclMacMismatch = SGX_ERROR_PCL_MAC_MISMATCH,
    /// The runtime SHA256 hash of the decryption key does not match the one used at build time (`0x6004`).
    #[fail(
        display = "The runtime SHA256 hash of the decryption key does not match the one used at build time"
    )]
    PclShaMismatch = SGX_ERROR_PCL_SHA_MISMATCH,
    /// The GUID in the decryption key sealed blob does not match the one used at build time (`0x6005`).
    #[fail(
        display = "The GUID in the decryption key sealed blob does not match the one used at build time"
    )]
    PclGuidMismatch = SGX_ERROR_PCL_GUID_MISMATCH,

    // 0x7000 - 0x7fff: SGX Encrypted FS
    /// The file is in a bad status, run sgx_clearerr to try and fix it (`0x7001`).
    #[fail(display = "The file is in a bad status, run sgx_clearerr to try and fix it")]
    FileBadStatus = SGX_ERROR_FILE_BAD_STATUS,
    /// The Key ID field is all zeroes, the encryption key cannot be regenerated (`0x7002`).
    #[fail(display = "The Key ID field is all zeroes, the encryption key cannot be regenerated")]
    FileNoKeyId = SGX_ERROR_FILE_NO_KEY_ID,
    /// The current file name is different from the original file name (substitution attack) (`0x7003`).
    #[fail(
        display = "The current file name is different from the original file name (substitution attack)"
    )]
    FileNameMismatch = SGX_ERROR_FILE_NAME_MISMATCH,
    /// The file is not an Intel SGX file (`0x7004`).
    #[fail(display = "The file is not an Intel SGX file")]
    FileNotSgxFile = SGX_ERROR_FILE_NOT_SGX_FILE,
    /// A recovery file cannot be opened, so the flush operation cannot continue (`0x7005`).
    #[fail(display = "A recovery file cannot be opened, so the flush operation cannot continue")]
    FileCantOpenRecoveryFile = SGX_ERROR_FILE_CANT_OPEN_RECOVERY_FILE,
    /// A recovery file cannot be written, so the flush operation cannot continue (`0x7006`).
    #[fail(display = "A recovery file cannot be written, so the flush operation cannot continue")]
    FileCantWriteRecoveryFile = SGX_ERROR_FILE_CANT_WRITE_RECOVERY_FILE,
    /// When opening the file, recovery is needed, but the recovery process failed (`0x7007`).
    #[fail(display = "When opening the file, recovery is needed, but the recovery process failed")]
    FileRecoveryNeeded = SGX_ERROR_FILE_RECOVERY_NEEDED,
    /// The fflush() operation failed (`0x7008`).
    #[fail(display = "The fflush() operation failed")]
    FileFlushFailed = SGX_ERROR_FILE_FLUSH_FAILED,
    /// The fclose() operation failed (`0x7009`).
    #[fail(display = "The fclose() operation failed")]
    FileCloseFailed = SGX_ERROR_FILE_CLOSE_FAILED,

    // 0x8000-0x8fff: Custom Attestation support
    /// Platform quoting infrastructure does not support the key (`0x8001`)
    #[fail(display = "Platform quoting infrastructure does not support the key")]
    UnsupportedAttKeyId = SGX_ERROR_UNSUPPORTED_ATT_KEY_ID,
    /// Failed to generate and certify the attestation key (`0x8002`).
    #[fail(display = "Failed to generate and certify the attestation key")]
    AttKeyCertificationFailure = SGX_ERROR_ATT_KEY_CERTIFICATION_FAILURE,
    /// The platform quoting infrastructure does not have the attestation key available to generate a quote (`0x8003`).
    #[fail(
        display = "The platform quoting infrastructure does not have the attestation key available to generate a quote"
    )]
    AttKeyUninitialized = SGX_ERROR_ATT_KEY_UNINITIALIZED,
    /// The data returned by sgx_get_quote_config() is invalid (`0x8004`).
    #[fail(display = "The data returned by sgx_get_quote_config() is invalid")]
    InvalidAttKeyCertData = SGX_ERROR_INVALID_ATT_KEY_CERT_DATA,
    /// The PCK cert for the platform is not available (`0x8005`).
    #[fail(display = "The PCK cert for the platform is not available")]
    PlatformCertUnavailable = SGX_ERROR_PLATFORM_CERT_UNAVAILABLE,

    // 0xf000-0xffff: Internal-to-SGX errors
    /// The ioctl for enclave_create unexpectedly failed with EINTR (`0xf000`).
    #[fail(display = "The ioctl for enclave_create unexpectedly failed with EINTR")]
    EnclaveCreateInterrupted = SGX_INTERNAL_ERROR_ENCLAVE_CREATE_INTERRUPTED,
}

impl TryFrom<sgx_status_t> for Error {
    type Error = ();

    fn try_from(src: sgx_status_t) -> StdResult<Error, ()> {
        match src {
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

            _ => Err(()),
        }
    }
}
