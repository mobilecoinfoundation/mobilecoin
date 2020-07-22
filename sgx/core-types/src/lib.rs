// Copyright (c) 2018-2020 MobileCoin Inc.

//! Core SGX Types

#![cfg_attr(all(not(test), not(doctest)), no_std)]
#![deny(missing_docs)]

extern crate alloc;

#[doc(hidden)]
pub mod _macros;

mod attributes;
mod config_id;
mod cpu_svn;
mod error;
mod ext_prod_id;
mod family_id;
mod key_128bit;
mod key_id;
mod key_request;
mod mac;
mod measurement;
mod misc_attribute;
mod report;
mod report_body;
mod report_data;
mod target_info;

pub use crate::{
    _macros::FfiWrapper,
    attributes::{AttributeFlags, AttributeXfeatures, Attributes, ATTRIBUTES_SIZE},
    config_id::{ConfigId, CONFIG_ID_SIZE},
    cpu_svn::{CpuSecurityVersion, CPU_SECURITY_VERSION_SIZE},
    error::{Error, Result, SgxStatusToResult},
    ext_prod_id::{ExtendedProductId, EXTENDED_PRODUCT_ID_SIZE},
    family_id::{FamilyId, FAMILY_ID_SIZE},
    key_128bit::{Key128, KEY128_SIZE},
    key_id::{KeyId, KEY_ID_SIZE},
    key_request::{KeyName, KeyPolicy, KeyRequest, KEY_REQUEST_SIZE},
    mac::{Mac, MAC_SIZE},
    measurement::{MrEnclave, MrSigner, MRENCLAVE_SIZE, MRSIGNER_SIZE},
    misc_attribute::{MiscAttribute, MISC_ATTRIBUTE_SIZE},
    report::{Report, REPORT_SIZE},
    report_body::{ReportBody, REPORT_BODY_SIZE},
    report_data::{ReportData, REPORT_DATA_SIZE},
    target_info::{TargetInfo, TARGET_INFO_SIZE},
};

/// The size of a [ConfigSecurityVersion]'s x64 representation, in bytes.
pub use mc_util_encodings::INTEL_U16_SIZE as CONFIG_SECURITY_VERSION_SIZE;

/// A CONFIGSVN value, which is used in the derivation of some keys.
pub use mc_sgx_core_types_sys::sgx_config_svn_t as ConfigSecurityVersion;

/// The size of a [MiscSelect]'s x64 representation, in bytes.
pub use mc_util_encodings::INTEL_U32_SIZE as MISC_SELECT_SIZE;

/// A "miscellaneous selection" flags type, presently only zero is a valid value
pub use mc_sgx_core_types_sys::sgx_misc_select_t as MiscSelect;

/// The size of a [ProductId]'s x64 representation, in bytes.
pub use mc_util_encodings::INTEL_U16_SIZE as PRODUCT_ID_SIZE;

/// A vendor product ID used to distinguish between enclaves signed by the same author.
pub use mc_sgx_core_types_sys::sgx_prod_id_t as ProductId;

/// The size of a [SecurityVersion]'s x64 representation, in bytes.
pub use mc_util_encodings::INTEL_U16_SIZE as SECURITY_VERSION_SIZE;

/// A security version of a given enclave.
///
/// The intent is that this value can be used to restrict trust to known-good versions of an
/// enclave. That is, when an enclave wants to prove it's a secure place to give secret information
/// to, the thing that is providing the secrets can check that the enclave is a particular
/// [ProductId], was signed by a particular [MrSigner], and is no earlier than a particular
/// [SecurityVersion].
pub use mc_sgx_core_types_sys::sgx_isv_svn_t as SecurityVersion;

/// The size of an [EnclaveId]'s x64 representation, in bytes.
pub use mc_util_encodings::INTEL_U64_SIZE as ENCLAVE_ID_SIZE;

/// A handle for a running enclave.
pub use mc_sgx_core_types_sys::sgx_enclave_id_t as EnclaveId;
