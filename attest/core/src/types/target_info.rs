// Copyright (c) 2018-2021 The MobileCoin Foundation

//! This module contains the wrapper type for an sgx_target_info_t

use crate::{
    error::TargetInfoError,
    impl_sgx_wrapper_reqs,
    traits::SgxWrapperType,
    types::{
        attributes::Attributes, config_id::ConfigId, measurement::MrEnclave, ConfigSecurityVersion,
        MiscSelect,
    },
};
use alloc::vec::Vec;
use core::{
    cmp::Ordering,
    convert::{TryFrom, TryInto},
    fmt::{Debug, Formatter, Result as FmtResult},
    hash::{Hash, Hasher},
    mem::size_of,
};
use mc_sgx_types::{
    sgx_target_info_t, SGX_TARGET_INFO_RESERVED1_BYTES, SGX_TARGET_INFO_RESERVED2_BYTES,
    SGX_TARGET_INFO_RESERVED3_BYTES,
};
use mc_util_encodings::{Error as EncodingError, IntelLayout};

// byte positions for each field in an x86_64 representation
const TI_MRENCLAVE_START: usize = 0;
const TI_MRENCLAVE_END: usize = TI_MRENCLAVE_START + <MrEnclave as IntelLayout>::X86_64_CSIZE;
const TI_ATTRIBUTES_START: usize = TI_MRENCLAVE_END;
const TI_ATTRIBUTES_END: usize = TI_ATTRIBUTES_START + <Attributes as IntelLayout>::X86_64_CSIZE;
const TI_RESERVED1_START: usize = TI_ATTRIBUTES_END;
const TI_RESERVED1_END: usize = TI_RESERVED1_START + SGX_TARGET_INFO_RESERVED1_BYTES;
const TI_CONFIGSVN_START: usize = TI_RESERVED1_END;
const TI_CONFIGSVN_END: usize = TI_CONFIGSVN_START + size_of::<u16>();
const TI_SELECT_START: usize = TI_CONFIGSVN_END;
const TI_SELECT_END: usize = TI_SELECT_START + size_of::<u32>();
const TI_RESERVED2_START: usize = TI_SELECT_END;
const TI_RESERVED2_END: usize = TI_RESERVED2_START + SGX_TARGET_INFO_RESERVED2_BYTES;
const TI_CONFIGID_START: usize = TI_RESERVED2_END;
const TI_CONFIGID_END: usize = TI_CONFIGID_START + <ConfigId as IntelLayout>::X86_64_CSIZE;
const TI_RESERVED3_START: usize = TI_CONFIGID_END;
const TI_RESERVED3_END: usize = TI_RESERVED3_START + SGX_TARGET_INFO_RESERVED3_BYTES;
const TI_SIZE: usize = TI_RESERVED3_END;

/// An opaque structure used to address an enclave for local attestation.
///
/// In remote attestation, the untrusted code retrieves this from the Intel
/// Quoting Enclave, and the enclave under test uses it to create a Report.
#[derive(Clone, Copy, Default)]
#[repr(transparent)]
pub struct TargetInfo(sgx_target_info_t);

impl TargetInfo {
    /// Retrieve the target enclave's attributes
    pub fn attributes(&self) -> Attributes {
        self.0.attributes.into()
    }

    /// Retrieve the target enclave's XML config ID
    pub fn config_id(&self) -> ConfigId {
        (&self.0.config_id).into()
    }

    /// Retrieve the target enclave's security version
    pub fn config_svn(&self) -> ConfigSecurityVersion {
        self.0.config_svn
    }

    /// Retrieve whether the target enclave requested extended SSA frames
    pub fn misc_select(&self) -> MiscSelect {
        self.0.misc_select
    }

    /// Retrieve the target enclave's measurement
    pub fn mr_enclave(&self) -> MrEnclave {
        self.0.mr_enclave.into()
    }
}

impl_sgx_wrapper_reqs! {
    TargetInfo, sgx_target_info_t, TI_SIZE;
}

impl Debug for TargetInfo {
    fn fmt(&self, formatter: &mut Formatter) -> FmtResult {
        write!(formatter, "TargetInfo {{ mr_enclave: {:?}, attributes: {:?}, config_svn: {:?}, misc_select: {:?}, config_id: {:?} }}", self.mr_enclave(), self.attributes(), self.config_svn(), self.misc_select(), self.config_id())
    }
}

impl Hash for TargetInfo {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.mr_enclave().hash(state);
        self.attributes().hash(state);
        self.config_svn().hash(state);
        self.misc_select().hash(state);
        self.config_id().hash(state);
    }
}

impl Ord for TargetInfo {
    fn cmp(&self, other: &Self) -> Ordering {
        match self.mr_enclave().cmp(&other.mr_enclave()) {
            Ordering::Equal => match self.attributes().cmp(&other.attributes()) {
                Ordering::Equal => match self.config_id().cmp(&other.config_id()) {
                    Ordering::Equal => match self.config_svn().cmp(&other.config_svn()) {
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
            && self.config_svn() == other.config_svn()
            && self.misc_select() == other.misc_select()
            && self.config_id() == other.config_id()
    }
}

/// Serialization into the x86_64 struct representation
impl SgxWrapperType<sgx_target_info_t> for TargetInfo {
    fn write_ffi_bytes(src: &sgx_target_info_t, dest: &mut [u8]) -> Result<usize, EncodingError> {
        if dest.len() < TI_SIZE {
            return Err(EncodingError::InvalidOutputLength);
        }

        MrEnclave::write_ffi_bytes(
            &src.mr_enclave,
            &mut dest[TI_MRENCLAVE_START..TI_MRENCLAVE_END],
        )?;
        Attributes::write_ffi_bytes(
            &src.attributes,
            &mut dest[TI_ATTRIBUTES_START..TI_ATTRIBUTES_END],
        )?;

        dest[TI_RESERVED1_START..TI_RESERVED1_END]
            .copy_from_slice(&[0u8; SGX_TARGET_INFO_RESERVED1_BYTES]);

        dest[TI_CONFIGSVN_START..TI_CONFIGSVN_END].copy_from_slice(&src.config_svn.to_le_bytes());
        dest[TI_SELECT_START..TI_SELECT_END].copy_from_slice(&src.misc_select.to_le_bytes());

        dest[TI_RESERVED2_START..TI_RESERVED2_END]
            .copy_from_slice(&[0u8; SGX_TARGET_INFO_RESERVED2_BYTES]);

        dest[TI_CONFIGID_START..TI_CONFIGID_END].copy_from_slice(&src.config_id[..]);

        dest[TI_RESERVED3_START..TI_RESERVED3_END]
            .copy_from_slice(&[0u8; SGX_TARGET_INFO_RESERVED3_BYTES]);

        Ok(Self::X86_64_CSIZE)
    }
}

/// Deserialize from x86_64 byte structures
impl<'src> TryFrom<&'src [u8]> for TargetInfo {
    type Error = TargetInfoError;

    fn try_from(src: &[u8]) -> Result<Self, TargetInfoError> {
        if src.len() < TI_SIZE {
            return Err(EncodingError::InvalidInputLength.into());
        }

        let mr_enclave = MrEnclave::try_from(&src[TI_MRENCLAVE_START..TI_MRENCLAVE_END])?.into();
        let attributes = Attributes::try_from(&src[TI_ATTRIBUTES_START..TI_ATTRIBUTES_END])?.into();
        let config_id = ConfigId::try_from(&src[TI_CONFIGID_START..TI_CONFIGID_END])?.into();

        Ok(Self(sgx_target_info_t {
            mr_enclave,
            attributes,
            reserved1: Default::default(),
            config_svn: u16::from_le_bytes(
                (&src[TI_CONFIGSVN_START..TI_CONFIGSVN_END])
                    .try_into()
                    .unwrap(),
            ),
            misc_select: u32::from_le_bytes(
                (&src[TI_SELECT_START..TI_SELECT_END]).try_into().unwrap(),
            ),
            reserved2: [0u8; SGX_TARGET_INFO_RESERVED2_BYTES],
            config_id,
            reserved3: [0u8; SGX_TARGET_INFO_RESERVED3_BYTES],
        }))
    }
}

impl TryFrom<Vec<u8>> for TargetInfo {
    type Error = TargetInfoError;

    fn try_from(src: Vec<u8>) -> Result<Self, Self::Error> {
        Self::try_from(&src[..])
    }
}

#[cfg(test)]
mod test {
    extern crate std;
    use std::vec;

    use super::*;
    use crate::traits::SgxWrapperType;
    use mc_sgx_types::{
        sgx_attributes_t, sgx_measurement_t, sgx_target_info_t, SGX_TARGET_INFO_RESERVED1_BYTES,
        SGX_TARGET_INFO_RESERVED2_BYTES, SGX_TARGET_INFO_RESERVED3_BYTES,
    };
    use mc_util_serial::{deserialize, serialize};

    const TARGET_INFO_SAMPLE: sgx_target_info_t = sgx_target_info_t {
        mr_enclave: sgx_measurement_t {
            m: [
                1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
                24, 25, 26, 27, 28, 29, 30, 31, 32,
            ],
        },
        attributes: sgx_attributes_t {
            flags: 0xffff_ffff_ffff_ffff,
            xfrm: 0x0000_0000_0000_0000,
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
        let ti: TargetInfo = TARGET_INFO_SAMPLE.clone().into();
        let mut outbuf = vec![0u8; size_of::<TargetInfo>() - 1];

        assert_eq!(
            TargetInfo::write_ffi_bytes(ti.as_ref(), &mut outbuf),
            Err(EncodingError::InvalidOutputLength)
        );
    }

    #[test]
    fn test_bad_ffi_read_len() {
        let ti: TargetInfo = TARGET_INFO_SAMPLE.clone().into();
        let mut outbuf = vec![0u8; size_of::<TargetInfo>() - 1];

        assert_eq!(
            TargetInfo::write_ffi_bytes(ti.as_ref(), &mut outbuf),
            Err(EncodingError::InvalidOutputLength)
        );
    }

    #[test]
    fn test_target_info_serde() {
        let ti1: TargetInfo = TARGET_INFO_SAMPLE.clone().into();
        let ti1ser = serialize(&ti1).expect("TargetInfo serialization failure");
        let ti2 = deserialize(&ti1ser).expect("TargetInfo deserialization failure");
        assert_eq!(ti1, ti2);
    }
}
