// Copyright (c) 2018-2020 MobileCoin Inc.

//! This module contains the wrapper type for an sgx_key_request_t

use crate::{
    _macros::FfiWrapper,
    attributes::{Attributes, ATTRIBUTES_SIZE},
    cpu_svn::{CpuSecurityVersion, CPU_SECURITY_VERSION_SIZE},
    impl_ffi_wrapper_base, impl_hex_base64_with_repr_bytes,
    key_id::{KeyId, KEY_ID_SIZE},
    misc_attribute::{MiscSelect, MISC_SELECT_SIZE},
    ConfigSecurityVersion, SecurityVersion, CONFIG_SECURITY_VERSION_SIZE, SECURITY_VERSION_SIZE,
};
use bitflags::bitflags;
use core::{
    cmp::Ordering,
    convert::{TryFrom, TryInto},
    fmt::{Debug, Display, Formatter, Result as FmtResult},
    hash::{Hash, Hasher},
};
use mc_sgx_core_types_sys::{
    sgx_key_request_t, SGX_KEYPOLICY_CONFIGID, SGX_KEYPOLICY_ISVEXTPRODID,
    SGX_KEYPOLICY_ISVFAMILYID, SGX_KEYPOLICY_MRENCLAVE, SGX_KEYPOLICY_MRSIGNER,
    SGX_KEYPOLICY_NOISVPRODID, SGX_KEYSELECT_EINITTOKEN, SGX_KEYSELECT_PROVISION,
    SGX_KEYSELECT_PROVISION_SEAL, SGX_KEYSELECT_REPORT, SGX_KEYSELECT_SEAL,
    SGX_KEY_REQUEST_RESERVED2_BYTES,
};
use mc_util_encodings::{Error as EncodingError, INTEL_U16_SIZE};
#[cfg(feature = "use_prost")]
use mc_util_repr_bytes::derive_prost_message_from_repr_bytes;
#[cfg(feature = "use_serde")]
use mc_util_repr_bytes::derive_serde_from_repr_bytes;
use mc_util_repr_bytes::{
    derive_into_vec_from_repr_bytes, derive_try_from_slice_from_repr_bytes,
    typenum::{U2, U512},
    GenericArray, ReprBytes,
};
#[cfg(feature = "use_serde")]
use serde::{Deserialize, Serialize};

const KEY_NAME_START: usize = 0;
const KEY_NAME_END: usize = KEY_NAME_START + KEY_NAME_SIZE;
const KEY_POLICY_START: usize = KEY_NAME_END;
const KEY_POLICY_END: usize = KEY_POLICY_START + KEY_POLICY_SIZE;
const ISV_SVN_START: usize = KEY_POLICY_END;
const ISV_SVN_END: usize = ISV_SVN_START + SECURITY_VERSION_SIZE;
const RESERVED1_START: usize = ISV_SVN_END;
const RESERVED1_END: usize = RESERVED1_START + INTEL_U16_SIZE;
const CPU_SVN_START: usize = RESERVED1_END;
const CPU_SVN_END: usize = CPU_SVN_START + CPU_SECURITY_VERSION_SIZE;
const ATTRIBUTES_START: usize = CPU_SVN_END;
const ATTRIBUTES_END: usize = ATTRIBUTES_START + ATTRIBUTES_SIZE;
const KEY_ID_START: usize = ATTRIBUTES_END;
const KEY_ID_END: usize = KEY_ID_START + KEY_ID_SIZE;
const MISC_MASK_START: usize = KEY_ID_END;
const MISC_MASK_END: usize = MISC_MASK_START + MISC_SELECT_SIZE;
const CONFIG_SVN_START: usize = MISC_MASK_END;
const CONFIG_SVN_END: usize = CONFIG_SVN_START + CONFIG_SECURITY_VERSION_SIZE;
const RESERVED2_START: usize = CONFIG_SVN_END;
const RESERVED2_END: usize = RESERVED2_START + SGX_KEY_REQUEST_RESERVED2_BYTES;

/// The size of the x64 representation of a [KeyRequest], in bytes.
pub const KEY_REQUEST_SIZE: usize = RESERVED2_END;

/// The size of the x64 representation of a [KeyName], in bytes.
pub const KEY_NAME_SIZE: usize = INTEL_U16_SIZE;

/// The size of the x64 representation of a [KeyPolicy], in bytes.
pub const KEY_POLICY_SIZE: usize = INTEL_U16_SIZE;

/// An enumeration of key names which can be used in a request.
#[cfg_attr(feature = "use_serde", derive(Deserialize, Serialize))]
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(u16)]
pub enum KeyName {
    /// Launch key
    EnclaveInitToken = SGX_KEYSELECT_EINITTOKEN,
    /// Provisioning key
    Provision = SGX_KEYSELECT_PROVISION,
    /// Provisioning seal key
    ProvisionSeal = SGX_KEYSELECT_PROVISION_SEAL,
    /// Report key
    Report = SGX_KEYSELECT_REPORT,
    /// Seal key
    Seal = SGX_KEYSELECT_SEAL,
}

impl_hex_base64_with_repr_bytes!(KeyName);
derive_try_from_slice_from_repr_bytes!(KeyName);
derive_into_vec_from_repr_bytes!(KeyName);

impl KeyName {
    /// Check if the given i32 value is a valid value.
    //
    // This method is normally implemented by prost via derive(Enumeration), but the SGX SDK chooses
    // to use a u16 for the in-situ data type.
    pub fn is_valid(value: i32) -> bool {
        Self::from_i32(value).is_some()
    }

    /// Create a new Error from the given i32 value.
    //
    // This method is normally implemented by prost via derive(Enumeration), but the SGX SDK chooses
    // to use a u16 for the in-situ data type.
    pub fn from_i32(value: i32) -> Option<Self> {
        Self::try_from(u16::try_from(value).ok()?).ok()
    }
}

impl Display for KeyName {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        match self {
            KeyName::EnclaveInitToken => write!(f, "Enclave initialization token"),
            KeyName::Provision => write!(f, "Provisioning key"),
            KeyName::ProvisionSeal => write!(f, "Provisioning seal key"),
            KeyName::Report => write!(f, "Report signing key"),
            KeyName::Seal => write!(f, "Sealing key"),
        }
    }
}

impl From<KeyName> for u16 {
    fn from(src: KeyName) -> u16 {
        match src {
            KeyName::EnclaveInitToken => 0x0000,
            KeyName::Provision => 0x0001,
            KeyName::ProvisionSeal => 0x0002,
            KeyName::Report => 0x0003,
            KeyName::Seal => 0x0004,
        }
    }
}

impl ReprBytes for KeyName {
    type Size = U2;
    type Error = EncodingError;

    fn from_bytes(src: &GenericArray<u8, Self::Size>) -> Result<Self, Self::Error> {
        Self::try_from(u16::from_le_bytes(src.clone().into()))
    }

    fn to_bytes(&self) -> GenericArray<u8, Self::Size> {
        GenericArray::from(u16::from(*self).to_le_bytes())
    }
}

impl TryFrom<u16> for KeyName {
    type Error = EncodingError;

    fn try_from(src: u16) -> Result<Self, Self::Error> {
        match src {
            0x0000 => Ok(KeyName::EnclaveInitToken),
            0x0001 => Ok(KeyName::Provision),
            0x0002 => Ok(KeyName::ProvisionSeal),
            0x0003 => Ok(KeyName::Report),
            0x0004 => Ok(KeyName::Seal),
            _ => Err(EncodingError::InvalidInput),
        }
    }
}

bitflags! {
    /// An enumeration of flags controlling what values should be included when deriving a new key.
    pub struct KeyPolicy: u16 {
        /// Derived keys are tied to the specific enclave measurement
        const MR_ENCLAVE = SGX_KEYPOLICY_MRENCLAVE;
        /// Derived keys are tied to the signing public key
        const MR_SIGNER = SGX_KEYPOLICY_MRSIGNER;
        /// Derived keys are not tied to the product ID
        const SKIP_PRODUCT_ID = SGX_KEYPOLICY_NOISVPRODID;
        /// Derived keys are tied to the enclave configuration
        const CONFIG_ID = SGX_KEYPOLICY_CONFIGID;
        /// Derived keys are tied to the signer's family ID
        const FAMILY_ID = SGX_KEYPOLICY_ISVFAMILYID;
        /// Derived keys are tied to the signer's extended product ID
        const EXTENDED_PRODUCT_ID = SGX_KEYPOLICY_ISVEXTPRODID;
    }
}

impl_hex_base64_with_repr_bytes!(KeyPolicy);
derive_try_from_slice_from_repr_bytes!(KeyPolicy);
derive_into_vec_from_repr_bytes!(KeyPolicy);

impl Display for KeyPolicy {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        let mut previous = if self.contains(KeyPolicy::MR_ENCLAVE) {
            write!(f, "MRENCLAVE")?;
            true
        } else {
            false
        };

        if self.contains(KeyPolicy::MR_SIGNER) {
            if previous {
                write!(f, ", ")?;
            }
            write!(f, "MRSIGNER")?;
            previous = true;
        }

        if !self.contains(KeyPolicy::SKIP_PRODUCT_ID) {
            if previous {
                write!(f, ", ")?;
            }
            write!(f, "Product ID")?;
            previous = true;
        }

        if self.contains(KeyPolicy::CONFIG_ID) {
            if previous {
                write!(f, ", ")?;
            }
            write!(f, "Config ID")?;
            previous = true;
        }

        if self.contains(KeyPolicy::FAMILY_ID) {
            if previous {
                write!(f, ", ")?;
            }
            write!(f, "Family ID")?;
            previous = true;
        }

        if self.contains(KeyPolicy::EXTENDED_PRODUCT_ID) {
            if previous {
                write!(f, ", ")?;
            }
            write!(f, "Extended Product ID")?;
        }

        Ok(())
    }
}

impl ReprBytes for KeyPolicy {
    type Size = U2;
    type Error = EncodingError;

    fn from_bytes(src: &GenericArray<u8, Self::Size>) -> Result<Self, Self::Error> {
        Self::from_bits(u16::from_le_bytes(src.clone().into())).ok_or(EncodingError::InvalidInput)
    }

    fn to_bytes(&self) -> GenericArray<u8, Self::Size> {
        GenericArray::from(self.bits.to_le_bytes())
    }
}

/// A key request data structure.
///
/// This is used with the `sgx_get_key()` inside-the-enclave method.
#[derive(Default)]
pub struct KeyRequest(sgx_key_request_t);

impl_ffi_wrapper_base! {
    KeyRequest, sgx_key_request_t;
}

impl_hex_base64_with_repr_bytes!(KeyRequest);
derive_into_vec_from_repr_bytes!(KeyRequest);

#[cfg(feature = "use_prost")]
derive_prost_message_from_repr_bytes!(KeyRequest);

#[cfg(feature = "use_serde")]
derive_serde_from_repr_bytes!(KeyRequest);

impl KeyRequest {
    /// Retrieve the name of the key contained in this request, if it's valid.
    pub fn key_name(&self) -> KeyName {
        KeyName::try_from(self.0.key_name).expect("Could not read the key name")
    }

    /// Retrieve the key policy.
    pub fn key_policy(&self) -> KeyPolicy {
        KeyPolicy::from_bits(self.0.key_policy).expect("Bad key policy in KeyRequest")
    }

    /// Retrieve the ISV enclave security version.
    pub fn security_version(&self) -> SecurityVersion {
        self.0.isv_svn
    }

    /// Retrieve the platform security version.
    pub fn cpu_security_version(&self) -> CpuSecurityVersion {
        CpuSecurityVersion::from(&self.0.cpu_svn)
    }

    /// Retrieve the attribute mask to be used.
    pub fn attribute_mask(&self) -> Attributes {
        Attributes::try_from(&self.0.attribute_mask).expect("Invalid attributes found")
    }

    /// Retrieve the Key ID used in this request.
    pub fn key_id(&self) -> KeyId {
        KeyId::from(&self.0.key_id)
    }

    /// Retrieve the mask of the attribute flags which are included in the key.
    pub fn misc_mask(&self) -> MiscSelect {
        self.0.misc_mask
    }

    /// Retrieve the configuration version used to lock a key to a particular enclave.
    pub fn config_security_version(&self) -> ConfigSecurityVersion {
        self.0.config_svn
    }
}

impl Debug for KeyRequest {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        write!(
            f,
            "KeyRequest {{ key_name: {:?}, key_policy: {:?}, security_version: {:?}, cpu_security_version: {:?}, attribute_mask: {:?}, key_id: {:?}, misc_mask: {:?}, config_security_version: {:?} }}",
            self.key_name(),
            self.key_policy(),
            self.security_version(),
            self.cpu_security_version(),
            self.attribute_mask(),
            self.key_id(),
            self.misc_mask(),
            self.config_security_version()
        )
    }
}

impl Display for KeyRequest {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        write!(
            f,
            "Key Request for {}, with policy {}",
            self.key_name(),
            self.key_policy()
        )
    }
}

impl FfiWrapper<sgx_key_request_t> for KeyRequest {}

impl Hash for KeyRequest {
    fn hash<H: Hasher>(&self, state: &mut H) {
        "KeyRequest".hash(state);
        self.key_name().hash(state);
        self.key_policy().hash(state);
        self.security_version().hash(state);
        self.cpu_security_version().hash(state);
        self.attribute_mask().hash(state);
        self.key_id().hash(state);
        self.misc_mask().hash(state);
        self.config_security_version().hash(state);
    }
}

// TODO: Implement prost::Message

impl Ord for KeyRequest {
    fn cmp(&self, other: &Self) -> Ordering {
        fn to_tuple(
            key_request: &KeyRequest,
        ) -> (
            KeyName,
            KeyPolicy,
            SecurityVersion,
            CpuSecurityVersion,
            KeyId,
            MiscSelect,
            ConfigSecurityVersion,
        ) {
            (
                key_request.key_name(),
                key_request.key_policy(),
                key_request.security_version(),
                key_request.cpu_security_version(),
                key_request.key_id(),
                key_request.misc_mask(),
                key_request.config_security_version(),
            )
        }

        to_tuple(self).cmp(&to_tuple(other))
    }
}

impl PartialEq for KeyRequest {
    fn eq(&self, other: &Self) -> bool {
        self.key_name() == other.key_name()
            && self.key_policy() == other.key_policy()
            && self.security_version() == other.security_version()
            && self.cpu_security_version() == other.cpu_security_version()
            && self.attribute_mask() == other.attribute_mask()
            && self.key_id() == other.key_id()
            && self.misc_mask() == other.misc_mask()
            && self.config_security_version() == other.config_security_version()
    }
}

impl PartialOrd for KeyRequest {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl ReprBytes for KeyRequest {
    type Size = U512;
    type Error = EncodingError;

    fn from_bytes(src: &GenericArray<u8, Self::Size>) -> Result<Self, Self::Error> {
        Self::try_from(src.as_slice())
    }

    fn to_bytes(&self) -> GenericArray<u8, Self::Size> {
        let mut retval = GenericArray::default();

        retval[KEY_NAME_START..KEY_NAME_END].copy_from_slice(self.key_name().to_bytes().as_slice());

        retval[KEY_POLICY_START..KEY_POLICY_END]
            .copy_from_slice(self.key_name().to_bytes().as_slice());

        retval[ISV_SVN_START..ISV_SVN_END].copy_from_slice(&self.security_version().to_le_bytes());

        retval[CPU_SVN_START..CPU_SVN_END]
            .copy_from_slice(self.cpu_security_version().to_bytes().as_slice());

        retval[ATTRIBUTES_START..ATTRIBUTES_END]
            .copy_from_slice(self.attribute_mask().to_bytes().as_slice());

        retval[KEY_ID_START..KEY_ID_END].copy_from_slice(self.key_id().to_bytes().as_slice());

        retval[MISC_MASK_START..MISC_MASK_END].copy_from_slice(&self.misc_mask().to_le_bytes());
        retval[CONFIG_SVN_START..CONFIG_SVN_END]
            .copy_from_slice(&self.config_security_version().to_le_bytes());

        retval
    }
}

impl TryFrom<&sgx_key_request_t> for KeyRequest {
    type Error = EncodingError;

    fn try_from(src: &sgx_key_request_t) -> Result<Self, Self::Error> {
        let attribute_mask = Attributes::try_from(&src.attribute_mask)?.into();

        Ok(Self(sgx_key_request_t {
            key_name: src.key_name,
            key_policy: src.key_policy,
            isv_svn: src.isv_svn,
            reserved1: 0,
            cpu_svn: CpuSecurityVersion::from(&src.cpu_svn).into(),
            attribute_mask,
            key_id: KeyId::from(&src.key_id).into(),
            misc_mask: src.misc_mask,
            config_svn: src.config_svn,
            reserved2: [0u8; SGX_KEY_REQUEST_RESERVED2_BYTES],
        }))
    }
}

impl<'src> TryFrom<&'src [u8]> for KeyRequest {
    type Error = EncodingError;

    fn try_from(src: &[u8]) -> Result<Self, Self::Error> {
        if src.len() < KEY_REQUEST_SIZE {
            return Err(EncodingError::InvalidInputLength);
        }

        let key_name = KeyName::try_from(&src[KEY_NAME_START..KEY_NAME_END])?;
        let key_policy = KeyPolicy::try_from(&src[KEY_POLICY_START..KEY_POLICY_END])?;

        let isv_svn_bytes = (&src[ISV_SVN_START..ISV_SVN_END])
            .try_into()
            .map_err(|_e| EncodingError::InvalidInput)?;
        let isv_svn = SecurityVersion::from_le_bytes(isv_svn_bytes);

        let cpu_svn = CpuSecurityVersion::try_from(&src[CPU_SVN_START..CPU_SVN_END])?;
        let attribute_mask = Attributes::try_from(&src[ATTRIBUTES_START..ATTRIBUTES_END])?;
        let key_id = KeyId::try_from(&src[KEY_ID_START..KEY_ID_END])?;

        let misc_mask_bytes = (&src[MISC_MASK_START..MISC_MASK_END])
            .try_into()
            .map_err(|_e| EncodingError::InvalidInput)?;
        let misc_mask = MiscSelect::from_le_bytes(misc_mask_bytes);

        let config_svn_bytes = (&src[CONFIG_SVN_START..CONFIG_SVN_END])
            .try_into()
            .map_err(|_e| EncodingError::InvalidInput)?;
        let config_svn = ConfigSecurityVersion::from_le_bytes(config_svn_bytes);

        Ok(Self(sgx_key_request_t {
            key_name: key_name as u16,
            key_policy: key_policy.bits,
            isv_svn,
            reserved1: 0,
            cpu_svn: cpu_svn.into(),
            attribute_mask: attribute_mask.into(),
            key_id: key_id.into(),
            misc_mask,
            config_svn,
            reserved2: [0u8; SGX_KEY_REQUEST_RESERVED2_BYTES],
        }))
    }
}
