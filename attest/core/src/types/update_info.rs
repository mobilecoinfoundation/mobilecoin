// Copyright (c) 2018-2021 The MobileCoin Foundation

//! FFI type for the sgx_update_bit_t

use crate::{impl_sgx_wrapper_reqs, traits::SgxWrapperType};
use alloc::vec::Vec;
use core::{
    cmp::{Ord, Ordering},
    convert::TryInto,
    fmt::{Debug, Display, Formatter, Result as FmtResult},
    hash::{Hash, Hasher},
};
use mc_sgx_types::sgx_update_info_bit_t;
use mc_util_encodings::Error as EncodingError;

const UPDATE_INFO_SIZE: usize = 12;

/// An opaque update info structure.
#[derive(Clone, Copy, Default)]
#[repr(transparent)]
pub struct UpdateInfo(sgx_update_info_bit_t);

impl_sgx_wrapper_reqs! {
    UpdateInfo, sgx_update_info_bit_t, UPDATE_INFO_SIZE;
}

impl Debug for UpdateInfo {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        let ucode_update = self.0.ucodeUpdate;
        let csme_fw_update = self.0.csmeFwUpdate;
        let psw_update = self.0.pswUpdate;
        write!(
            f,
            "UpdateInfo {{ ucodeUpdate: i32({}), csmeFwUpdate: i32({}), pswUpdate: i32({}) }}",
            ucode_update, csme_fw_update, psw_update,
        )
    }
}

impl Display for UpdateInfo {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        let ucode_update = self.0.ucodeUpdate;
        let csme_fw_update = self.0.csmeFwUpdate;
        let psw_update = self.0.pswUpdate;
        write!(
            f,
            "Microcode {}, Management Engine Firmware {}, Platform Services {}",
            ucode_update, csme_fw_update, psw_update
        )
    }
}

impl From<Vec<u8>> for UpdateInfo {
    fn from(src: Vec<u8>) -> UpdateInfo {
        let src_slice: &[u8] = src.as_ref();
        Self::from(src_slice)
    }
}

impl<'src> From<&'src [u8]> for UpdateInfo {
    fn from(src: &'src [u8]) -> UpdateInfo {
        Self(sgx_update_info_bit_t {
            ucodeUpdate: i32::from_le_bytes(
                src[0..4]
                    .try_into()
                    .expect("Could not convert 4-byte slice to 4-byte array"),
            ),
            csmeFwUpdate: i32::from_le_bytes(
                src[4..8]
                    .try_into()
                    .expect("Could not convert 4-byte slice to 4-byte array"),
            ),
            pswUpdate: i32::from_le_bytes(
                src[8..12]
                    .try_into()
                    .expect("Could not convert 4-byte slice to 4-byte array"),
            ),
        })
    }
}

impl Hash for UpdateInfo {
    fn hash<H: Hasher>(&self, state: &mut H) {
        let mut tmp: i32 = self.0.ucodeUpdate;
        tmp.hash(state);
        tmp = self.0.csmeFwUpdate;
        tmp.hash(state);
        tmp = self.0.pswUpdate;
        tmp.hash(state);
    }
}

impl Ord for UpdateInfo {
    fn cmp(&self, other: &Self) -> Ordering {
        let self_val = self.0.ucodeUpdate;
        let other_val = other.0.ucodeUpdate;
        match self_val.cmp(&other_val) {
            Ordering::Equal => {
                let self_val = self.0.csmeFwUpdate;
                let other_val = other.0.csmeFwUpdate;
                match self_val.cmp(&other_val) {
                    Ordering::Equal => {
                        let self_val = self.0.pswUpdate;
                        let other_val = other.0.pswUpdate;
                        self_val.cmp(&other_val)
                    }
                    order => order,
                }
            }
            order => order,
        }
    }
}

impl PartialEq for UpdateInfo {
    fn eq(&self, other: &Self) -> bool {
        self.0.ucodeUpdate == other.0.ucodeUpdate
            && self.0.csmeFwUpdate == other.0.csmeFwUpdate
            && self.0.pswUpdate == other.0.pswUpdate
    }
}

impl SgxWrapperType<sgx_update_info_bit_t> for UpdateInfo {
    fn write_ffi_bytes(
        src: &sgx_update_info_bit_t,
        dest: &mut [u8],
    ) -> Result<usize, EncodingError> {
        if dest.len() < UPDATE_INFO_SIZE {
            return Err(EncodingError::InvalidOutputLength);
        }

        dest[..4].copy_from_slice(&src.ucodeUpdate.to_le_bytes());
        dest[4..8].copy_from_slice(&src.csmeFwUpdate.to_le_bytes());
        dest[8..12].copy_from_slice(&src.pswUpdate.to_le_bytes());
        Ok(UPDATE_INFO_SIZE)
    }
}

#[cfg(test)]
mod test {
    extern crate std;
    use std::format;

    use super::*;

    use mc_util_serial::{deserialize, serialize};
    use std::collections::HashSet;

    #[test]
    fn test_serde() {
        let mut src = UpdateInfo::default();
        src.0.ucodeUpdate = 1;
        src.0.csmeFwUpdate = 2;
        src.0.pswUpdate = 3;

        let bytes = serialize(&src).expect("Could not serialize UpdateInfo");
        let dest: UpdateInfo = deserialize(&bytes).expect("Could not deserialize UpdateInfo");
        assert_eq!(src, dest);
    }

    #[test]
    fn test_display() {
        let mut src = UpdateInfo::default();
        src.0.ucodeUpdate = 1;
        src.0.csmeFwUpdate = 2;
        src.0.pswUpdate = 3;

        assert_eq!(
            format!("{}", &src),
            "Microcode 1, Management Engine Firmware 2, Platform Services 3"
        );
    }

    #[test]
    fn test_debug() {
        let mut src = UpdateInfo::default();
        src.0.ucodeUpdate = 1;
        src.0.csmeFwUpdate = 2;
        src.0.pswUpdate = 3;

        assert_eq!(
            format!("{:?}", &src),
            "UpdateInfo { ucodeUpdate: i32(1), csmeFwUpdate: i32(2), pswUpdate: i32(3) }",
        );
    }

    #[test]
    fn test_hash() {
        let mut set = HashSet::new();

        let mut src1 = UpdateInfo::default();
        src1.0.ucodeUpdate = 1;
        src1.0.csmeFwUpdate = 2;
        src1.0.pswUpdate = 3;

        set.insert(src1);

        let mut src2 = UpdateInfo::default();
        src2.0.ucodeUpdate = 3;
        src2.0.csmeFwUpdate = 2;
        src2.0.pswUpdate = 1;

        set.insert(src2);

        let mut src3 = UpdateInfo::default();
        src3.0.ucodeUpdate = 1;
        src3.0.csmeFwUpdate = 2;
        src3.0.pswUpdate = 3;

        assert!(set.contains(&src3));
    }
}
