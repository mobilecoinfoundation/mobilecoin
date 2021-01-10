// Copyright (C) 2017-2018 Baidu, Inc. All Rights Reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions
// are met:
//
//  * Redistributions of source code must retain the above copyright
//    notice, this list of conditions and the following disclaimer.
//  * Redistributions in binary form must reproduce the above copyright
//    notice, this list of conditions and the following disclaimer in
//    the documentation and/or other materials provided with the
//    distribution.
//  * Neither the name of Baidu, Inc., nor the names of its
//    contributors may be used to endorse or promote products derived
//    from this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
// "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
// A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
// OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
// LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
// DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
// THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

use core::result;
use core::fmt;
//
// sgx_error.h
//
impl_enum! {

    #[repr(u32)]
    #[derive(Copy, Clone, PartialEq, Eq, Ord, PartialOrd, Debug)]
    pub enum sgx_status_t {
        SGX_SUCCESS                         = 0x0000_0000,

        SGX_ERROR_UNEXPECTED                 = 0x0000_0001,      /* Unexpected error */
        SGX_ERROR_INVALID_PARAMETER         = 0x0000_0002,      /* The parameter is incorrect */
        SGX_ERROR_OUT_OF_MEMORY             = 0x0000_0003,      /* Not enough memory is available to complete this operation */
        SGX_ERROR_ENCLAVE_LOST              = 0x0000_0004,      /* Enclave lost after power transition or used in child process created by linux:fork() */
        SGX_ERROR_INVALID_STATE             = 0x0000_0005,      /* SGX API is invoked in incorrect order or state */
        SGX_ERROR_FEATURE_NOT_SUPPORTED     = 0x0000_0008,      /* Feature is not supported on this platform */

        SGX_ERROR_INVALID_FUNCTION   = 0x0000_1001,      /* The ecall/ocall index is invalid */
        SGX_ERROR_OUT_OF_TCS         = 0x0000_1003,      /* The enclave is out of TCS */
        SGX_ERROR_ENCLAVE_CRASHED    = 0x0000_1006,      /* The enclave is crashed */
        SGX_ERROR_ECALL_NOT_ALLOWED  = 0x0000_1007,      /* The ECALL is not allowed at this time, e.g. ecall is blocked by the dynamic entry table, or nested ecall is not allowed during initialization */
        SGX_ERROR_OCALL_NOT_ALLOWED  = 0x0000_1008,      /* The OCALL is not allowed at this time, e.g. ocall is not allowed during exception handling */
        SGX_ERROR_STACK_OVERRUN      = 0x0000_1009,      /* The enclave is running out of stack */

        SGX_ERROR_UNDEFINED_SYMBOL      = 0x0000_2000,      /* The enclave image has undefined symbol. */
        SGX_ERROR_INVALID_ENCLAVE       = 0x0000_2001,      /* The enclave image is not correct. */
        SGX_ERROR_INVALID_ENCLAVE_ID    = 0x0000_2002,      /* The enclave id is invalid */
        SGX_ERROR_INVALID_SIGNATURE     = 0x0000_2003,      /* The signature is invalid */
        SGX_ERROR_NDEBUG_ENCLAVE        = 0x0000_2004,      /* The enclave is signed as product enclave, and can not be created as debuggable enclave. */
        SGX_ERROR_OUT_OF_EPC            = 0x0000_2005,      /* Not enough EPC is available to load the enclave */
        SGX_ERROR_NO_DEVICE             = 0x0000_2006,      /* Can't open SGX device */
        SGX_ERROR_MEMORY_MAP_CONFLICT   = 0x0000_2007,      /* Page mapping failed in driver */
        SGX_ERROR_INVALID_METADATA      = 0x0000_2009,      /* The metadata is incorrect. */
        SGX_ERROR_DEVICE_BUSY           = 0x0000_200c,      /* Device is busy, mostly EINIT failed. */
        SGX_ERROR_INVALID_VERSION       = 0x0000_200d,      /* Metadata version is inconsistent between uRTS and sgx_sign or uRTS is incompatible with current platform. */
        SGX_ERROR_MODE_INCOMPATIBLE     = 0x0000_200e,      /* The target enclave 32/64 bit mode or sim/hw mode is incompatible with the mode of current uRTS. */
        SGX_ERROR_ENCLAVE_FILE_ACCESS   = 0x0000_200f,     /* Can't open enclave file. */
        SGX_ERROR_INVALID_MISC          = 0x0000_2010,     /* The MiscSelct/MiscMask settings are not correct.*/
        SGX_ERROR_INVALID_LAUNCH_TOKEN  = 0x0000_2011,    /* The launch token is not correct.*/

        SGX_ERROR_MAC_MISMATCH       = 0x0000_3001,      /* Indicates verification error for reports, sealed datas, etc */
        SGX_ERROR_INVALID_ATTRIBUTE  = 0x0000_3002,      /* The enclave is not authorized */
        SGX_ERROR_INVALID_CPUSVN     = 0x0000_3003,      /* The cpu svn is beyond platform's cpu svn value */
        SGX_ERROR_INVALID_ISVSVN     = 0x0000_3004,      /* The isv svn is greater than the enclave's isv svn */
        SGX_ERROR_INVALID_KEYNAME    = 0x0000_3005,      /* The key name is an unsupported value */

        SGX_ERROR_SERVICE_UNAVAILABLE       = 0x0000_4001,   /* Indicates aesm didn't respond or the requested service is not supported */
        SGX_ERROR_SERVICE_TIMEOUT           = 0x0000_4002,   /* The request to aesm timed out */
        SGX_ERROR_AE_INVALID_EPIDBLOB       = 0x0000_4003,   /* Indicates epid blob verification error */
        SGX_ERROR_SERVICE_INVALID_PRIVILEGE = 0x0000_4004,   /* Enclave has no privilege to get launch token */
        SGX_ERROR_EPID_MEMBER_REVOKED       = 0x0000_4005,   /* The EPID group membership is revoked. */
        SGX_ERROR_UPDATE_NEEDED             = 0x0000_4006,   /* SGX needs to be updated */
        SGX_ERROR_NETWORK_FAILURE           = 0x0000_4007,   /* Network connecting or proxy setting issue is encountered */
        SGX_ERROR_AE_SESSION_INVALID        = 0x0000_4008,   /* Session is invalid or ended by server */
        SGX_ERROR_BUSY                      = 0x0000_400a,   /* The requested service is temporarily not availabe */
        SGX_ERROR_MC_NOT_FOUND              = 0x0000_400c,   /* The Monotonic Counter doesn't exist or has been invalided */
        SGX_ERROR_MC_NO_ACCESS_RIGHT        = 0x0000_400d,   /* Caller doesn't have the access right to specified VMC */
        SGX_ERROR_MC_USED_UP                = 0x0000_400e,   /* Monotonic counters are used out */
        SGX_ERROR_MC_OVER_QUOTA             = 0x0000_400f,   /* Monotonic counters exceeds quota limitation */
        SGX_ERROR_KDF_MISMATCH              = 0x0000_4011,   /* Key derivation function doesn't match during key exchange */
        SGX_ERROR_UNRECOGNIZED_PLATFORM     = 0x0000_4012,   /* EPID Provisioning failed due to platform not recognized by backend server*/

        SGX_ERROR_NO_PRIVILEGE              = 0x0000_5002,   /* Not enough privilege to perform the operation */

        /* SGX Protected Code Loader Error codes*/
        SGX_ERROR_PCL_ENCRYPTED             = 0x0000_6001,   /* trying to encrypt an already encrypted enclave */
        SGX_ERROR_PCL_NOT_ENCRYPTED         = 0x0000_6002,   /* trying to load a plain enclave using sgx_create_encrypted_enclave */
        SGX_ERROR_PCL_MAC_MISMATCH          = 0x0000_6003,   /* section mac result does not match build time mac */
        SGX_ERROR_PCL_SHA_MISMATCH          = 0x0000_6004,   /* Unsealed key MAC does not match MAC of key hardcoded in enclave binary */
        SGX_ERROR_PCL_GUID_MISMATCH         = 0x0000_6005,   /* GUID in sealed blob does not match GUID hardcoded in enclave binary */

        /* SGX errors are only used in the file API when there is no appropriate EXXX (EINVAL, EIO etc.) error code */
        SGX_ERROR_FILE_BAD_STATUS               = 0x0000_7001,	/* The file is in bad status, run sgx_clearerr to try and fix it */
        SGX_ERROR_FILE_NO_KEY_ID                = 0x0000_7002,	/* The Key ID field is all zeros, can't re-generate the encryption key */
        SGX_ERROR_FILE_NAME_MISMATCH            = 0x0000_7003,	/* The current file name is different then the original file name (not allowed, substitution attack) */
        SGX_ERROR_FILE_NOT_SGX_FILE             = 0x0000_7004,   /* The file is not an SGX file */
        SGX_ERROR_FILE_CANT_OPEN_RECOVERY_FILE  = 0x0000_7005,	/* A recovery file can't be opened, so flush operation can't continue (only used when no EXXX is returned)  */
        SGX_ERROR_FILE_CANT_WRITE_RECOVERY_FILE = 0x0000_7006,   /* A recovery file can't be written, so flush operation can't continue (only used when no EXXX is returned)  */
        SGX_ERROR_FILE_RECOVERY_NEEDED          = 0x0000_7007,	/* When openeing the file, recovery is needed, but the recovery process failed */
        SGX_ERROR_FILE_FLUSH_FAILED             = 0x0000_7008,	/* fflush operation (to disk) failed (only used when no EXXX is returned) */
        SGX_ERROR_FILE_CLOSE_FAILED             = 0x0000_7009,	/* fclose operation (to disk) failed (only used when no EXXX is returned) */

        SGX_INTERNAL_ERROR_ENCLAVE_CREATE_INTERRUPTED = 0x0000_F001, /* The ioctl for enclave_create unexpectedly failed with EINTR. */

        SGX_ERROR_WASM_BUFFER_TOO_SHORT         = 0x0F00_F001,   /* sgxwasm output buffer not long enough */
        SGX_ERROR_WASM_INTERPRETER_ERROR        = 0x0F00_F002,   /* sgxwasm interpreter error */
        SGX_ERROR_WASM_LOAD_MODULE_ERROR        = 0x0F00_F003,   /* sgxwasm loadmodule error */
        SGX_ERROR_WASM_TRY_LOAD_ERROR           = 0x0F00_F004,   /* sgxwasm tryload error */
        SGX_ERROR_WASM_REGISTER_ERROR           = 0x0F00_F005,   /* sgxwasm register error */
        SGX_ERROR_FAAS_BUFFER_TOO_SHORT         = 0x0F00_E001,   /* faas output buffer not long enough */
        SGX_ERROR_FAAS_INTERNAL_ERROR           = 0x0F00_E002,   /* faas exec internal error */
    }
}

impl sgx_status_t {
    pub fn __description(&self) -> &str {
        match *self {
            sgx_status_t::SGX_SUCCESS => "Success.",
            sgx_status_t::SGX_ERROR_UNEXPECTED => "Unexpected error occurred.",
            sgx_status_t::SGX_ERROR_INVALID_PARAMETER => "The parameter is incorrect.",
            sgx_status_t::SGX_ERROR_OUT_OF_MEMORY => "Not enough memory is available to complete this operation.",
            sgx_status_t::SGX_ERROR_ENCLAVE_LOST => "Enclave lost after power transition or used in child process created.",
            sgx_status_t::SGX_ERROR_INVALID_STATE => "SGX API is invoked in incorrect order or state.",
            sgx_status_t::SGX_ERROR_FEATURE_NOT_SUPPORTED => "Feature is not supported on this platform.",

            sgx_status_t::SGX_ERROR_INVALID_FUNCTION => "The ecall/ocall index is invalid.",
            sgx_status_t::SGX_ERROR_OUT_OF_TCS => "The enclave is out of TCS.",
            sgx_status_t::SGX_ERROR_ENCLAVE_CRASHED => "The enclave is crashed.",
            sgx_status_t::SGX_ERROR_ECALL_NOT_ALLOWED => "The ECALL is not allowed at this time.",
            sgx_status_t::SGX_ERROR_OCALL_NOT_ALLOWED => "The OCALL is not allowed at this time.",
            sgx_status_t::SGX_ERROR_STACK_OVERRUN => "The enclave is running out of stack.",

            sgx_status_t::SGX_ERROR_UNDEFINED_SYMBOL => "The enclave image has undefined symbol.",
            sgx_status_t::SGX_ERROR_INVALID_ENCLAVE => "The enclave image is not correct.",
            sgx_status_t::SGX_ERROR_INVALID_ENCLAVE_ID => "The enclave id is invalid.",
            sgx_status_t::SGX_ERROR_INVALID_SIGNATURE => "The signature is invalid.",
            sgx_status_t::SGX_ERROR_NDEBUG_ENCLAVE => "The enclave can not be created as debuggable enclave.",
            sgx_status_t::SGX_ERROR_OUT_OF_EPC => "Not enough EPC is available to load the enclave.",
            sgx_status_t::SGX_ERROR_NO_DEVICE => "Can't open SGX device.",
            sgx_status_t::SGX_ERROR_MEMORY_MAP_CONFLICT => "Page mapping failed in driver.",
            sgx_status_t::SGX_ERROR_INVALID_METADATA => "The metadata is incorrect.",
            sgx_status_t::SGX_ERROR_DEVICE_BUSY => "Device is busy, mostly EINIT failed.",
            sgx_status_t::SGX_ERROR_INVALID_VERSION => "Enclave version was invalid.",
            sgx_status_t::SGX_ERROR_MODE_INCOMPATIBLE => "The target enclave mode is incompatible with the mode of current uRTS.",
            sgx_status_t::SGX_ERROR_ENCLAVE_FILE_ACCESS => "Can't open enclave file.",
            sgx_status_t::SGX_ERROR_INVALID_MISC => "The MiscSelct/MiscMask settings are not correct.",
            sgx_status_t::SGX_ERROR_INVALID_LAUNCH_TOKEN => "The launch token is not correct.",

            sgx_status_t::SGX_ERROR_MAC_MISMATCH => "Indicates verification error for reports, sealed datas, etc.",
            sgx_status_t::SGX_ERROR_INVALID_ATTRIBUTE => "The enclave is not authorized.",
            sgx_status_t::SGX_ERROR_INVALID_CPUSVN => "The cpu svn is beyond platform's cpu svn value.",
            sgx_status_t::SGX_ERROR_INVALID_ISVSVN => "The isv svn is greater than the enclave's isv svn.",
            sgx_status_t::SGX_ERROR_INVALID_KEYNAME => "The key name is an unsupported value.",

            sgx_status_t::SGX_ERROR_SERVICE_UNAVAILABLE => "Indicates aesm didn't response or the requested service is not supported.",
            sgx_status_t::SGX_ERROR_SERVICE_TIMEOUT => "The request to aesm time out.",
            sgx_status_t::SGX_ERROR_AE_INVALID_EPIDBLOB => "Indicates epid blob verification error.",
            sgx_status_t::SGX_ERROR_SERVICE_INVALID_PRIVILEGE => "Enclave has no privilege to get launch token.",
            sgx_status_t::SGX_ERROR_EPID_MEMBER_REVOKED => "The EPID group membership is revoked.",
            sgx_status_t::SGX_ERROR_UPDATE_NEEDED => "SGX needs to be updated.",
            sgx_status_t::SGX_ERROR_NETWORK_FAILURE => "Network connecting or proxy setting issue is encountered.",
            sgx_status_t::SGX_ERROR_AE_SESSION_INVALID => "Session is invalid or ended by server.",
            sgx_status_t::SGX_ERROR_BUSY => "The requested service is temporarily not availabe.",
            sgx_status_t::SGX_ERROR_MC_NOT_FOUND => "The Monotonic Counter doesn't exist or has been invalided.",
            sgx_status_t::SGX_ERROR_MC_NO_ACCESS_RIGHT => "Caller doesn't have the access right to specified VMC.",
            sgx_status_t::SGX_ERROR_MC_USED_UP => "Monotonic counters are used out.",
            sgx_status_t::SGX_ERROR_MC_OVER_QUOTA => "Monotonic counters exceeds quota limitation.",
            sgx_status_t::SGX_ERROR_KDF_MISMATCH => "Key derivation function doesn't match during key exchange.",
            sgx_status_t::SGX_ERROR_UNRECOGNIZED_PLATFORM => "EPID Provisioning failed due to platform not recognized by backend server.",
            sgx_status_t::SGX_ERROR_NO_PRIVILEGE => "Not enough privilege to perform the operation.",

            sgx_status_t::SGX_ERROR_PCL_ENCRYPTED => "Trying to encrypt an already encrypted enclave.",
            sgx_status_t::SGX_ERROR_PCL_NOT_ENCRYPTED => "Trying to load a plain enclave using sgx_create_encrypted_enclave.",
            sgx_status_t::SGX_ERROR_PCL_MAC_MISMATCH => "Section mac result does not match build time mac.",
            sgx_status_t::SGX_ERROR_PCL_SHA_MISMATCH => "Unsealed key MAC does not match MAC of key hardcoded in enclave binary.",
            sgx_status_t::SGX_ERROR_PCL_GUID_MISMATCH => "GUID in sealed blob does not match GUID hardcoded in enclave binary.",

            sgx_status_t::SGX_ERROR_FILE_BAD_STATUS => "The file is in bad status.",
            sgx_status_t::SGX_ERROR_FILE_NO_KEY_ID => "The Key ID field is all zeros, can't regenerate the encryption key.",
            sgx_status_t::SGX_ERROR_FILE_NAME_MISMATCH => "The current file name is different then the original file name.",
            sgx_status_t::SGX_ERROR_FILE_NOT_SGX_FILE => "The file is not an SGX file.",
            sgx_status_t::SGX_ERROR_FILE_CANT_OPEN_RECOVERY_FILE => "A recovery file can't be opened, so flush operation can't continue.",
            sgx_status_t::SGX_ERROR_FILE_CANT_WRITE_RECOVERY_FILE => "A recovery file can't be written, so flush operation can't continue.",
            sgx_status_t::SGX_ERROR_FILE_RECOVERY_NEEDED => "When openeing the file, recovery is needed, but the recovery process failed.",
            sgx_status_t::SGX_ERROR_FILE_FLUSH_FAILED => "fflush operation failed.",
            sgx_status_t::SGX_ERROR_FILE_CLOSE_FAILED => "fclose operation failed.",

            sgx_status_t::SGX_INTERNAL_ERROR_ENCLAVE_CREATE_INTERRUPTED => "The ioctl for enclave_create unexpectedly failed with EINTR.",

            sgx_status_t::SGX_ERROR_WASM_BUFFER_TOO_SHORT => "sgx wasm output buffer too small.",
            sgx_status_t::SGX_ERROR_WASM_INTERPRETER_ERROR => "sgx wasm interpreter error.",
            sgx_status_t::SGX_ERROR_WASM_LOAD_MODULE_ERROR => "sgxwasm loadmodule error.",
            sgx_status_t::SGX_ERROR_WASM_TRY_LOAD_ERROR => "sgxwasm tryload error.",
            sgx_status_t::SGX_ERROR_WASM_REGISTER_ERROR => "sgxwasm register error.",
            sgx_status_t::SGX_ERROR_FAAS_BUFFER_TOO_SHORT => "faas output buffer too short.",
            sgx_status_t::SGX_ERROR_FAAS_INTERNAL_ERROR => "faas exec internal error.",
        }
    }

    pub fn as_str(&self) -> &str {
        match *self {
            sgx_status_t::SGX_SUCCESS => "SGX_SUCCESS.",
            sgx_status_t::SGX_ERROR_UNEXPECTED => "SGX_ERROR_UNEXPECTED",
            sgx_status_t::SGX_ERROR_INVALID_PARAMETER => "SGX_ERROR_INVALID_PARAMETER",
            sgx_status_t::SGX_ERROR_OUT_OF_MEMORY => "SGX_ERROR_OUT_OF_MEMORY",
            sgx_status_t::SGX_ERROR_ENCLAVE_LOST => "SGX_ERROR_ENCLAVE_LOST",
            sgx_status_t::SGX_ERROR_INVALID_STATE => "SGX_ERROR_INVALID_STATE",
            sgx_status_t::SGX_ERROR_FEATURE_NOT_SUPPORTED => "SGX_ERROR_FEATURE_NOT_SUPPORTED",

            sgx_status_t::SGX_ERROR_INVALID_FUNCTION => "SGX_ERROR_INVALID_FUNCTION",
            sgx_status_t::SGX_ERROR_OUT_OF_TCS => "SGX_ERROR_OUT_OF_TCS",
            sgx_status_t::SGX_ERROR_ENCLAVE_CRASHED => "SGX_ERROR_ENCLAVE_CRASHED",
            sgx_status_t::SGX_ERROR_ECALL_NOT_ALLOWED => "SGX_ERROR_ECALL_NOT_ALLOWED",
            sgx_status_t::SGX_ERROR_OCALL_NOT_ALLOWED => "SGX_ERROR_OCALL_NOT_ALLOWED",
            sgx_status_t::SGX_ERROR_STACK_OVERRUN => "SGX_ERROR_STACK_OVERRUN",

            sgx_status_t::SGX_ERROR_UNDEFINED_SYMBOL => "SGX_ERROR_UNDEFINED_SYMBOL",
            sgx_status_t::SGX_ERROR_INVALID_ENCLAVE => "SGX_ERROR_INVALID_ENCLAVE",
            sgx_status_t::SGX_ERROR_INVALID_ENCLAVE_ID => "SGX_ERROR_INVALID_ENCLAVE_ID",
            sgx_status_t::SGX_ERROR_INVALID_SIGNATURE => "SGX_ERROR_INVALID_SIGNATURE",
            sgx_status_t::SGX_ERROR_NDEBUG_ENCLAVE => "SGX_ERROR_NDEBUG_ENCLAVE",
            sgx_status_t::SGX_ERROR_OUT_OF_EPC => "SGX_ERROR_OUT_OF_EPC",
            sgx_status_t::SGX_ERROR_NO_DEVICE => "SGX_ERROR_NO_DEVICE",
            sgx_status_t::SGX_ERROR_MEMORY_MAP_CONFLICT => "SGX_ERROR_MEMORY_MAP_CONFLICT",
            sgx_status_t::SGX_ERROR_INVALID_METADATA => "SGX_ERROR_INVALID_METADATA",
            sgx_status_t::SGX_ERROR_DEVICE_BUSY => "SGX_ERROR_DEVICE_BUSY",
            sgx_status_t::SGX_ERROR_INVALID_VERSION => "SGX_ERROR_INVALID_VERSION",
            sgx_status_t::SGX_ERROR_MODE_INCOMPATIBLE => "SGX_ERROR_MODE_INCOMPATIBLE",
            sgx_status_t::SGX_ERROR_ENCLAVE_FILE_ACCESS => "SGX_ERROR_ENCLAVE_FILE_ACCESS",
            sgx_status_t::SGX_ERROR_INVALID_MISC => "SGX_ERROR_INVALID_MISC",
            sgx_status_t::SGX_ERROR_INVALID_LAUNCH_TOKEN => "SGX_ERROR_INVALID_LAUNCH_TOKEN",

            sgx_status_t::SGX_ERROR_MAC_MISMATCH => "SGX_ERROR_MAC_MISMATCH",
            sgx_status_t::SGX_ERROR_INVALID_ATTRIBUTE => "SGX_ERROR_INVALID_ATTRIBUTE",
            sgx_status_t::SGX_ERROR_INVALID_CPUSVN => "SGX_ERROR_INVALID_CPUSVN",
            sgx_status_t::SGX_ERROR_INVALID_ISVSVN => "SGX_ERROR_INVALID_ISVSVN",
            sgx_status_t::SGX_ERROR_INVALID_KEYNAME => "SGX_ERROR_INVALID_KEYNAME",

            sgx_status_t::SGX_ERROR_SERVICE_UNAVAILABLE => "SGX_ERROR_SERVICE_UNAVAILABLE",
            sgx_status_t::SGX_ERROR_SERVICE_TIMEOUT => "SGX_ERROR_SERVICE_TIMEOUT",
            sgx_status_t::SGX_ERROR_AE_INVALID_EPIDBLOB => "SGX_ERROR_AE_INVALID_EPIDBLOB",
            sgx_status_t::SGX_ERROR_SERVICE_INVALID_PRIVILEGE => "SGX_ERROR_SERVICE_INVALID_PRIVILEGE",
            sgx_status_t::SGX_ERROR_EPID_MEMBER_REVOKED => "SGX_ERROR_EPID_MEMBER_REVOKED",
            sgx_status_t::SGX_ERROR_UPDATE_NEEDED => "SGX_ERROR_UPDATE_NEEDED",
            sgx_status_t::SGX_ERROR_NETWORK_FAILURE => "SGX_ERROR_NETWORK_FAILURE",
            sgx_status_t::SGX_ERROR_AE_SESSION_INVALID => "SGX_ERROR_AE_SESSION_INVALID",
            sgx_status_t::SGX_ERROR_BUSY => "SGX_ERROR_BUSY",
            sgx_status_t::SGX_ERROR_MC_NOT_FOUND => "SGX_ERROR_MC_NOT_FOUND",
            sgx_status_t::SGX_ERROR_MC_NO_ACCESS_RIGHT => "SGX_ERROR_MC_NO_ACCESS_RIGHT",
            sgx_status_t::SGX_ERROR_MC_USED_UP => "SGX_ERROR_MC_USED_UP",
            sgx_status_t::SGX_ERROR_MC_OVER_QUOTA => "SGX_ERROR_MC_OVER_QUOTA",
            sgx_status_t::SGX_ERROR_KDF_MISMATCH => "SGX_ERROR_KDF_MISMATCH",
            sgx_status_t::SGX_ERROR_UNRECOGNIZED_PLATFORM => "SGX_ERROR_UNRECOGNIZED_PLATFORM",
            sgx_status_t::SGX_ERROR_NO_PRIVILEGE => "SGX_ERROR_NO_PRIVILEGE",

            sgx_status_t::SGX_ERROR_PCL_ENCRYPTED => "SGX_ERROR_PCL_ENCRYPTED",
            sgx_status_t::SGX_ERROR_PCL_NOT_ENCRYPTED => "SGX_ERROR_PCL_NOT_ENCRYPTED",
            sgx_status_t::SGX_ERROR_PCL_MAC_MISMATCH => "SGX_ERROR_PCL_MAC_MISMATCH",
            sgx_status_t::SGX_ERROR_PCL_SHA_MISMATCH => "SGX_ERROR_PCL_SHA_MISMATCH",
            sgx_status_t::SGX_ERROR_PCL_GUID_MISMATCH => "SGX_ERROR_PCL_GUID_MISMATCH",

            sgx_status_t::SGX_ERROR_FILE_BAD_STATUS => "SGX_ERROR_FILE_BAD_STATUS",
            sgx_status_t::SGX_ERROR_FILE_NO_KEY_ID => "SGX_ERROR_FILE_NO_KEY_ID",
            sgx_status_t::SGX_ERROR_FILE_NAME_MISMATCH => "SGX_ERROR_FILE_NAME_MISMATCH",
            sgx_status_t::SGX_ERROR_FILE_NOT_SGX_FILE => "SGX_ERROR_FILE_NOT_SGX_FILE",
            sgx_status_t::SGX_ERROR_FILE_CANT_OPEN_RECOVERY_FILE => "SGX_ERROR_FILE_CANT_OPEN_RECOVERY_FILE",
            sgx_status_t::SGX_ERROR_FILE_CANT_WRITE_RECOVERY_FILE => "SGX_ERROR_FILE_CANT_WRITE_RECOVERY_FILE",
            sgx_status_t::SGX_ERROR_FILE_RECOVERY_NEEDED => "SGX_ERROR_FILE_RECOVERY_NEEDED",
            sgx_status_t::SGX_ERROR_FILE_FLUSH_FAILED => "SGX_ERROR_FILE_FLUSH_FAILED",
            sgx_status_t::SGX_ERROR_FILE_CLOSE_FAILED => "SGX_ERROR_FILE_CLOSE_FAILED",

            sgx_status_t::SGX_INTERNAL_ERROR_ENCLAVE_CREATE_INTERRUPTED => "SGX_INTERNAL_ERROR_ENCLAVE_CREATE_INTERRUPTED",

            sgx_status_t::SGX_ERROR_WASM_BUFFER_TOO_SHORT => "SGX_ERROR_WASM_BUFFER_TOO_SHORT",
            sgx_status_t::SGX_ERROR_WASM_INTERPRETER_ERROR => "SGX_ERROR_WASM_INTERPRETER_ERROR",
            sgx_status_t::SGX_ERROR_WASM_LOAD_MODULE_ERROR => "SGX_ERROR_WASM_LOAD_MODULE_ERROR",
            sgx_status_t::SGX_ERROR_WASM_TRY_LOAD_ERROR    => "SGX_ERROR_WASM_TRY_LOAD_ERROR",
            sgx_status_t::SGX_ERROR_WASM_REGISTER_ERROR    => "SGX_ERROR_WASM_REGISTER_ERROR",
            sgx_status_t::SGX_ERROR_FAAS_BUFFER_TOO_SHORT   => "SGX_ERROR_FAAS_BUFFER_TOO_SHORT",
            sgx_status_t::SGX_ERROR_FAAS_INTERNAL_ERROR => "SGX_ERROR_FAAS_INTERNAL_ERROR",
        }
    }
}

impl fmt::Display for sgx_status_t {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

pub type sys_error_t = ::int32_t;
pub type SgxResult<T> = result::Result<T, sgx_status_t>;
pub type SgxError = result::Result<(), sgx_status_t>;
pub type SysResult<T> = result::Result<T, sys_error_t>;
pub type SysError = result::Result<(), sys_error_t>;

//
// errno.h
//
// https://github.com/intel/linux-sgx/blob/33f4499173497bdfdf72c5f61374c0fadc5c5365/common/inc/tlibc/errno.h#L55
pub mod libc {
use ::int32_t;
pub const EPERM: int32_t = 1;
pub const ENOENT: int32_t = 2;
pub const ESRCH: int32_t = 3;
pub const EINTR: int32_t = 4;
pub const EIO: int32_t = 5;
pub const ENXIO: int32_t = 6;
pub const E2BIG: int32_t = 7;
pub const ENOEXEC: int32_t = 8;
pub const EBADF: int32_t = 9;
pub const ECHILD: int32_t = 10;
pub const EAGAIN: int32_t = 11;
pub const ENOMEM: int32_t = 12;
pub const EACCES: int32_t = 13;
pub const EFAULT: int32_t = 14;
pub const ENOTBLK: int32_t = 15;
pub const EBUSY: int32_t = 16;
pub const EEXIST: int32_t = 17;
pub const EXDEV: int32_t = 18;
pub const ENODEV: int32_t = 19;
pub const ENOTDIR: int32_t = 20;
pub const EISDIR: int32_t = 21;
pub const EINVAL: int32_t = 22;
pub const ENFILE: int32_t = 23;
pub const EMFILE: int32_t = 24;
pub const ENOTTY: int32_t = 25;
pub const ETXTBSY: int32_t = 26;
pub const EFBIG: int32_t = 27;
pub const ENOSPC: int32_t = 28;
pub const ESPIPE: int32_t = 29;
pub const EROFS: int32_t = 30;
pub const EMLINK: int32_t = 31;
pub const EPIPE: int32_t = 32;
pub const EDOM: int32_t = 33;
pub const ERANGE: int32_t = 34;
pub const EDEADLK: int32_t = 35;
pub const ENAMETOOLONG: int32_t = 36;
pub const ENOLCK: int32_t = 37;
pub const ENOSYS: int32_t = 38;
pub const ENOTEMPTY: int32_t = 39;
pub const ELOOP: int32_t = 40;
pub const EWOULDBLOCK: int32_t = EAGAIN;
pub const ENOMSG: int32_t = 42;
pub const EIDRM: int32_t = 43;
pub const ECHRNG: int32_t = 44;
pub const EL2NSYNC: int32_t = 45;
pub const EL3HLT: int32_t = 46;
pub const EL3RST: int32_t = 47;
pub const ELNRNG: int32_t = 48;
pub const EUNATCH: int32_t = 49;
pub const ENOCSI: int32_t = 50;
pub const EL2HLT: int32_t = 51;
pub const EBADE: int32_t = 52;
pub const EBADR: int32_t = 53;
pub const EXFULL: int32_t = 54;
pub const ENOANO: int32_t = 55;
pub const EBADRQC: int32_t = 56;
pub const EBADSLT: int32_t = 57;
pub const EDEADLOCK: int32_t = EDEADLK;
pub const EBFONT: int32_t = 59;
pub const ENOSTR: int32_t = 60;
pub const ENODATA: int32_t = 61;
pub const ETIME: int32_t = 62;
pub const ENOSR: int32_t = 63;
pub const ENONET: int32_t = 64;
pub const ENOPKG: int32_t = 65;
pub const EREMOTE: int32_t = 66;
pub const ENOLINK: int32_t = 67;
pub const EADV: int32_t = 68;
pub const ESRMNT: int32_t = 69;
pub const ECOMM: int32_t = 70;
pub const EPROTO: int32_t = 71;
pub const EMULTIHOP: int32_t = 72;
pub const EDOTDOT: int32_t = 73;
pub const EBADMSG: int32_t = 74;
pub const EOVERFLOW: int32_t = 75;
pub const ENOTUNIQ: int32_t = 76;
pub const EBADFD: int32_t = 77;
pub const EREMCHG: int32_t = 78;
pub const ELIBACC: int32_t = 79;
pub const ELIBBAD: int32_t = 80;
pub const ELIBSCN: int32_t = 81;
pub const ELIBMAX: int32_t = 82;
pub const ELIBEXEC: int32_t = 83;
pub const EILSEQ: int32_t = 84;
pub const ERESTART: int32_t = 85;
pub const ESTRPIPE: int32_t = 86;
pub const EUSERS: int32_t = 87;
pub const ENOTSOCK: int32_t = 88;
pub const EDESTADDRREQ: int32_t = 89;
pub const EMSGSIZE: int32_t = 90;
pub const EPROTOTYPE: int32_t = 91;
pub const ENOPROTOOPT: int32_t = 92;
pub const EPROTONOSUPPORT: int32_t = 93;
pub const ESOCKTNOSUPPORT: int32_t = 94;
pub const EOPNOTSUPP: int32_t = 95;
pub const EPFNOSUPPORT: int32_t = 96;
pub const EAFNOSUPPORT: int32_t = 97;
pub const EADDRINUSE: int32_t = 98;
pub const EADDRNOTAVAIL: int32_t = 99;
pub const ENETDOWN: int32_t = 100;
pub const ENETUNREACH: int32_t = 101;
pub const ENETRESET: int32_t = 102;
pub const ECONNABORTED: int32_t = 103;
pub const ECONNRESET: int32_t = 104;
pub const ENOBUFS: int32_t = 105;
pub const EISCONN: int32_t = 106;
pub const ENOTCONN: int32_t = 107;
pub const ESHUTDOWN: int32_t = 108;
pub const ETOOMANYREFS: int32_t = 109;
pub const ETIMEDOUT: int32_t = 110;
pub const ECONNREFUSED: int32_t = 111;
pub const EHOSTDOWN: int32_t = 112;
pub const EHOSTUNREACH: int32_t = 113;
pub const EALREADY: int32_t = 114;
pub const EINPROGRESS: int32_t = 115;
pub const ESTALE: int32_t = 116;
pub const EUCLEAN: int32_t = 117;
pub const ENOTNAM: int32_t = 118;
pub const ENAVAIL: int32_t = 119;
pub const EISNAM: int32_t = 120;
pub const EREMOTEIO: int32_t = 121;
pub const EDQUOT: int32_t = 122;
pub const ENOMEDIUM: int32_t = 123;
pub const EMEDIUMTYPE: int32_t = 124;
pub const ECANCELED: int32_t = 125;
pub const ENOKEY: int32_t = 126;
pub const EKEYEXPIRED: int32_t = 127;
pub const EKEYREVOKED: int32_t = 128;
pub const EKEYREJECTED: int32_t = 129;
pub const EOWNERDEAD: int32_t = 130;
pub const ENOTRECOVERABLE: int32_t = 131;
pub const ERFKILL: int32_t = 132;
pub const EHWPOISON: int32_t = 133;
pub const ENOTSUP: int32_t = EOPNOTSUPP;
pub const ESGX: int32_t = 0x0000_FFFF;
}
