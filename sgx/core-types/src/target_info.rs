// Copyright (c) 2018-2020 MobileCoin Inc.

//! This module contains the wrapper type for an sgx_target_info_t

use crate::{
    _macros::FfiWrapper,
    attributes::{Attributes, ATTRIBUTES_SIZE},
    config_id::{ConfigId, CONFIG_ID_SIZE},
    impl_ffi_wrapper_base, impl_serialize_to_x64,
    measurement::{MrEnclave, MRENCLAVE_SIZE},
    ConfigSecurityVersion, MiscSelect, CONFIG_SECURITY_VERSION_SIZE, MISC_SELECT_SIZE,
};
use core::{
    cmp::Ordering,
    convert::TryInto,
    fmt::{Debug, Display, Formatter, Result as FmtResult},
    hash::{Hash, Hasher},
};
use mc_encodings::{Error as EncodingError, FromX64, ToX64};
use mc_sgx_core_types_sys::{
    sgx_target_info_t, SGX_TARGET_INFO_RESERVED1_BYTES, SGX_TARGET_INFO_RESERVED2_BYTES,
    SGX_TARGET_INFO_RESERVED3_BYTES,
};

// byte positions for each field in an x86_64 representation
const MR_ENCLAVE_START: usize = 0;
const MR_ENCLAVE_END: usize = MR_ENCLAVE_START + MRENCLAVE_SIZE;
const ATTRIBUTES_START: usize = MR_ENCLAVE_END;
const ATTRIBUTES_END: usize = ATTRIBUTES_START + ATTRIBUTES_SIZE;
const RESERVED1_START: usize = ATTRIBUTES_END;
const RESERVED1_END: usize = RESERVED1_START + SGX_TARGET_INFO_RESERVED1_BYTES;
const CONFIG_SVN_START: usize = RESERVED1_END;
const CONFIG_SVN_END: usize = CONFIG_SVN_START + CONFIG_SECURITY_VERSION_SIZE;
const SELECT_START: usize = CONFIG_SVN_END;
const SELECT_END: usize = SELECT_START + MISC_SELECT_SIZE;
const RESERVED2_START: usize = SELECT_END;
const RESERVED2_END: usize = RESERVED2_START + SGX_TARGET_INFO_RESERVED2_BYTES;
const CONFIG_ID_START: usize = RESERVED2_END;
const CONFIG_ID_END: usize = CONFIG_ID_START + CONFIG_ID_SIZE;
const RESERVED3_START: usize = CONFIG_ID_END;
const RESERVED3_END: usize = RESERVED3_START + SGX_TARGET_INFO_RESERVED3_BYTES;

/// The size of a [TargetInfo] structure's x64 representation, in bytes.
pub const TARGET_INFO_SIZE: usize = RESERVED3_END;

/// An opaque structure used to address an enclave for local attestation.
///
/// In remote attestation, the untrusted code retrieves this from the Intel
/// Quoting Enclave, and the enclave under test uses it to create a Report.
#[derive(Default)]
#[repr(transparent)]
pub struct TargetInfo(sgx_target_info_t);

impl TargetInfo {
    /// Retrieve the target enclave's attributes
    pub fn attributes(&self) -> Attributes {
        Attributes::from(&self.0.attributes)
    }

    /// Retrieve the target enclave's XML config ID
    pub fn config_id(&self) -> ConfigId {
        ConfigId::from(&self.0.config_id)
    }

    /// Retrieve the target enclave's security version
    pub fn config_security_version(&self) -> ConfigSecurityVersion {
        self.0.config_svn
    }

    /// Retrieve whether the target enclave requested extended SSA frames
    pub fn misc_select(&self) -> MiscSelect {
        self.0.misc_select
    }

    /// Retrieve the target enclave's measurement
    pub fn mr_enclave(&self) -> MrEnclave {
        MrEnclave::from(&self.0.mr_enclave)
    }
}

impl_ffi_wrapper_base! {
    TargetInfo, sgx_target_info_t, TARGET_INFO_SIZE;
}

impl_serialize_to_x64! {
    TargetInfo, TARGET_INFO_SIZE;
}

impl Debug for TargetInfo {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        write!(f, "TargetInfo {{ mr_enclave: {:?}, attributes: {:?}, config_security_version: {:?}, misc_select: {:?}, config_id: {:?} }}", self.mr_enclave(), self.attributes(), self.config_security_version(), self.misc_select(), self.config_id())
    }
}

impl Display for TargetInfo {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        write!(f, "Target information for {}", self.mr_enclave())
    }
}

impl FfiWrapper<sgx_target_info_t> for TargetInfo {}

impl From<&sgx_target_info_t> for TargetInfo {
    fn from(src: &sgx_target_info_t) -> Self {
        let mut reserved1 = [0u8; SGX_TARGET_INFO_RESERVED1_BYTES];
        reserved1.copy_from_slice(&src.reserved1[..]);

        let mut reserved2 = [0u8; SGX_TARGET_INFO_RESERVED2_BYTES];
        reserved2.copy_from_slice(&src.reserved2[..]);

        let mut reserved3 = [0u8; SGX_TARGET_INFO_RESERVED3_BYTES];
        reserved3.copy_from_slice(&src.reserved3[..]);

        Self(sgx_target_info_t {
            mr_enclave: MrEnclave::from(&src.mr_enclave).into(),
            attributes: Attributes::from(&src.attributes).into(),
            reserved1,
            config_svn: src.config_svn,
            misc_select: src.misc_select,
            reserved2,
            config_id: ConfigId::from(&src.config_id).into(),
            reserved3,
        })
    }
}

impl FromX64 for TargetInfo {
    type Error = EncodingError;

    fn from_x64(src: &[u8]) -> Result<Self, EncodingError> {
        if src.len() < TARGET_INFO_SIZE {
            return Err(EncodingError::InvalidInputLength);
        }

        let reserved1 = [0u8; SGX_TARGET_INFO_RESERVED1_BYTES];
        if &src[RESERVED1_START..RESERVED1_END] != &reserved1[..] {
            return Err(EncodingError::InvalidInput);
        }

        let reserved2 = [0u8; SGX_TARGET_INFO_RESERVED2_BYTES];
        if &src[RESERVED2_START..RESERVED2_END] != &reserved2[..] {
            return Err(EncodingError::InvalidInput);
        }

        let reserved3 = [0u8; SGX_TARGET_INFO_RESERVED3_BYTES];
        if &src[RESERVED3_START..RESERVED3_END] != &reserved3[..] {
            return Err(EncodingError::InvalidInput);
        }

        Ok(Self(sgx_target_info_t {
            mr_enclave: MrEnclave::from_x64(&src[MR_ENCLAVE_START..MR_ENCLAVE_END])?.into(),
            attributes: Attributes::from_x64(&src[ATTRIBUTES_START..ATTRIBUTES_END])?.into(),
            reserved1,
            config_svn: u16::from_le_bytes(
                (&src[CONFIG_SVN_START..CONFIG_SVN_END])
                    .try_into()
                    .expect("Could not read config_svn bytes."),
            ),
            misc_select: u32::from_le_bytes((&src[SELECT_START..SELECT_END]).try_into().unwrap()),
            reserved2,
            config_id: ConfigId::from_x64(&src[CONFIG_ID_START..CONFIG_ID_END])?.into(),
            reserved3,
        }))
    }
}

impl Hash for TargetInfo {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.mr_enclave().hash(state);
        self.attributes().hash(state);
        self.config_security_version().hash(state);
        self.misc_select().hash(state);
        self.config_id().hash(state);
    }
}

impl Ord for TargetInfo {
    fn cmp(&self, other: &Self) -> Ordering {
        match self.mr_enclave().cmp(&other.mr_enclave()) {
            Ordering::Equal => match self.attributes().cmp(&other.attributes()) {
                Ordering::Equal => match self.config_id().cmp(&other.config_id()) {
                    Ordering::Equal => match self
                        .config_security_version()
                        .cmp(&other.config_security_version())
                    {
                        Ordering::Equal => self.misc_select().cmp(&other.misc_select()),
                        ordering => ordering,
                    },
                    ordering => ordering,
                },
                ordering => ordering,
            },
            ordering => ordering,
        }
    }
}

impl PartialEq for TargetInfo {
    /// TargetInfo structures are equal if all their fields are equal.
    fn eq(&self, other: &Self) -> bool {
        self.mr_enclave() == other.mr_enclave()
            && self.attributes() == other.attributes()
            && self.config_security_version() == other.config_security_version()
            && self.misc_select() == other.misc_select()
            && self.config_id() == other.config_id()
    }
}

/// Serialization into the x86_64 struct representation
impl ToX64 for TargetInfo {
    fn to_x64(&self, dest: &mut [u8]) -> Result<usize, usize> {
        if dest.len() < TARGET_INFO_SIZE {
            return Err(TARGET_INFO_SIZE);
        }

        self.mr_enclave()
            .to_x64(&mut dest[MR_ENCLAVE_START..MR_ENCLAVE_END])
            .or(Err(TARGET_INFO_SIZE))?;
        self.attributes()
            .to_x64(&mut dest[ATTRIBUTES_START..ATTRIBUTES_END])
            .or(Err(TARGET_INFO_SIZE))?;

        dest[RESERVED1_START..RESERVED1_END]
            .copy_from_slice(&[0u8; SGX_TARGET_INFO_RESERVED1_BYTES]);

        dest[CONFIG_SVN_START..CONFIG_SVN_END]
            .copy_from_slice(&self.config_security_version().to_le_bytes());
        dest[SELECT_START..SELECT_END].copy_from_slice(&self.misc_select().to_le_bytes());

        dest[RESERVED2_START..RESERVED2_END]
            .copy_from_slice(&[0u8; SGX_TARGET_INFO_RESERVED2_BYTES]);

        dest[CONFIG_ID_START..CONFIG_ID_END].copy_from_slice(&self.0.config_id[..]);

        dest[RESERVED3_START..RESERVED3_END]
            .copy_from_slice(&[0u8; SGX_TARGET_INFO_RESERVED3_BYTES]);

        Ok(TARGET_INFO_SIZE)
    }
}

#[cfg(test)]
mod test {
    extern crate std;
    use std::vec;

    use super::*;
    use bincode::{deserialize, serialize};
    use mc_sgx_core_types_sys::{
        sgx_attributes_t, sgx_measurement_t, sgx_target_info_t, SGX_TARGET_INFO_RESERVED1_BYTES,
        SGX_TARGET_INFO_RESERVED2_BYTES, SGX_TARGET_INFO_RESERVED3_BYTES,
    };

    const TARGET_INFO_SAMPLE: sgx_target_info_t = sgx_target_info_t {
        mr_enclave: sgx_measurement_t {
            m: [
                1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
                24, 25, 26, 27, 28, 29, 30, 31, 32,
            ],
        },
        attributes: sgx_attributes_t {
            flags: 0x0000_0000_0000_0001 | 0x0000_0000_0000_0004 | 0x0000_0000_0000_0080,
            xfrm: 0x0000_0000_0000_0006,
        },
        reserved1: [0u8; SGX_TARGET_INFO_RESERVED1_BYTES],
        config_svn: 0xDEAD,
        misc_select: 0xCAFE_BEEF,
        reserved2: [0u8; SGX_TARGET_INFO_RESERVED2_BYTES],
        config_id: [
            1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
            25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46,
            47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64,
        ],
        reserved3: [0u8; SGX_TARGET_INFO_RESERVED3_BYTES],
    };

    #[test]
    fn test_bad_ffi_write_len() {
        let ti = TargetInfo::from(&TARGET_INFO_SAMPLE);
        let mut outbuf = vec![0u8; TARGET_INFO_SIZE - 1];

        assert_eq!(ti.to_x64(&mut outbuf[..]), Err(TARGET_INFO_SIZE));
    }

    #[test]
    fn test_bad_ffi_read_len() {
        let ti = TargetInfo::from(&TARGET_INFO_SAMPLE);
        let outbuf = ti.to_x64_vec();

        assert_eq!(
            TargetInfo::from_x64(&outbuf[..TARGET_INFO_SIZE - 1]),
            Err(EncodingError::InvalidInputLength)
        );
    }

    #[test]
    fn test_target_info_serde() {
        let ti1 = TargetInfo::from(&TARGET_INFO_SAMPLE);
        let ti1ser = serialize(&ti1).expect("TargetInfo serialization failure");
        let ti2 = deserialize(&ti1ser).expect("TargetInfo deserialization failure");
        assert_eq!(ti1, ti2);
    }
}
