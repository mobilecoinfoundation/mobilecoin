// Copyright (c) 2018-2020 MobileCoin Inc.

//! Update Info Bit (PIB update details) wrapper

use core::{
    cmp::Ordering,
    convert::TryInto,
    fmt::{Debug, Display, Formatter, Result as FmtResult},
    hash::{Hash, Hasher},
};
use mc_sgx_core_types::{impl_ffi_wrapper_base, impl_serialize_to_x64, FfiWrapper};
use mc_sgx_epid_types_sys::sgx_update_info_bit_t;
use mc_util_encodings::{Error as EncodingError, FromX64, ToX64, INTEL_U32_SIZE};

const UCODE_START: usize = 0;
const UCODE_END: usize = UCODE_START + INTEL_U32_SIZE;
const CSME_START: usize = UCODE_END;
const CSME_END: usize = CSME_START + INTEL_U32_SIZE;
const PSW_START: usize = CSME_END;
const PSW_END: usize = PSW_START + INTEL_U32_SIZE;

/// The size of the [UpdateInfo]'s x64 representation, in bytes.
pub const UPDATE_INFO_SIZE: usize = PSW_END;

/// An update info structure, describing which parts (if any) of the platform's
/// [Trusted Computing Base](https://en.wikipedia.org/wiki/Trusted_computing_base)
/// require updates to remain secure.
#[derive(Default)]
#[repr(transparent)]
pub struct UpdateInfo(sgx_update_info_bit_t);

impl_ffi_wrapper_base! {
    UpdateInfo, sgx_update_info_bit_t, UPDATE_INFO_SIZE;
}

impl_serialize_to_x64! {
    UpdateInfo, UPDATE_INFO_SIZE;
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

impl FfiWrapper<sgx_update_info_bit_t> for UpdateInfo {}

impl From<&sgx_update_info_bit_t> for UpdateInfo {
    fn from(src: &sgx_update_info_bit_t) -> UpdateInfo {
        Self(sgx_update_info_bit_t {
            ucodeUpdate: src.ucodeUpdate,
            csmeFwUpdate: src.csmeFwUpdate,
            pswUpdate: src.pswUpdate,
        })
    }
}

impl FromX64 for UpdateInfo {
    type Error = EncodingError;

    fn from_x64(src: &[u8]) -> Result<UpdateInfo, EncodingError> {
        Ok(Self(sgx_update_info_bit_t {
            ucodeUpdate: i32::from_le_bytes(src[0..4].try_into()?),
            csmeFwUpdate: i32::from_le_bytes(src[4..8].try_into()?),
            pswUpdate: i32::from_le_bytes(src[8..12].try_into()?),
        }))
    }
}

impl Hash for UpdateInfo {
    fn hash<H: Hasher>(&self, state: &mut H) {
        "UpdateInfo".hash(state);
        let mut value = self.0.ucodeUpdate;
        value.hash(state);
        value = self.0.csmeFwUpdate;
        value.hash(state);
        value = self.0.pswUpdate;
        value.hash(state);
    }
}

impl Ord for UpdateInfo {
    fn cmp(&self, other: &Self) -> Ordering {
        (self.0.ucodeUpdate, self.0.csmeFwUpdate, self.0.pswUpdate).cmp(&(
            other.0.ucodeUpdate,
            other.0.csmeFwUpdate,
            other.0.pswUpdate,
        ))
    }
}

impl PartialEq for UpdateInfo {
    fn eq(&self, other: &Self) -> bool {
        (self.0.ucodeUpdate, self.0.csmeFwUpdate, self.0.pswUpdate)
            == (other.0.ucodeUpdate, other.0.csmeFwUpdate, other.0.pswUpdate)
    }
}

impl ToX64 for UpdateInfo {
    fn to_x64(&self, dest: &mut [u8]) -> Result<usize, usize> {
        if dest.len() < UPDATE_INFO_SIZE {
            Err(UPDATE_INFO_SIZE)
        } else {
            dest[UCODE_START..UCODE_END].copy_from_slice(&self.0.ucodeUpdate.to_le_bytes());
            dest[CSME_START..CSME_END].copy_from_slice(&self.0.csmeFwUpdate.to_le_bytes());
            dest[PSW_START..PSW_END].copy_from_slice(&self.0.pswUpdate.to_le_bytes());
            Ok(UPDATE_INFO_SIZE)
        }
    }
}

#[cfg(test)]
mod test {
    extern crate std;

    use super::*;
    use bincode::{deserialize, serialize};
    use std::{collections::HashSet, format, mem};

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn size() {
        assert_eq!(UPDATE_INFO_SIZE, mem::size_of::<sgx_update_info_bit_t>())
    }

    #[test]
    fn serde() {
        let mut src = UpdateInfo::default();
        src.0.ucodeUpdate = 1;
        src.0.csmeFwUpdate = 2;
        src.0.pswUpdate = 3;

        let bytes = serialize(&src).expect("Could not serialize UpdateInfo");
        let dest: UpdateInfo = deserialize(&bytes).expect("Could not deserialize UpdateInfo");
        assert_eq!(src, dest);
    }

    #[test]
    fn display() {
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
    fn debug() {
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
    fn hash() {
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

    #[test]
    fn ordering() {
        let mut ui1 = UpdateInfo::default();
        ui1.0.ucodeUpdate = 1;
        ui1.0.csmeFwUpdate = 2;
        ui1.0.pswUpdate = 3;

        let mut ui2 = UpdateInfo::default();
        ui2.0.ucodeUpdate = 2;
        ui2.0.csmeFwUpdate = 2;
        ui2.0.pswUpdate = 2;

        // (1, 2, 3) vs. (2, 2, 2)
        assert!(ui1 < ui2);

        // (1, 2, 3) vs. (1, 2, 2)
        ui2.0.ucodeUpdate = 1;
        assert!(ui1 > ui2);

        // (1, 2, 3) vs. (1, 4, 2)
        ui2.0.csmeFwUpdate = 4;
        assert!(ui1 < ui2);

        // (1, 2, 3) vs. (1, 2, 2) -- reset
        ui2.0.csmeFwUpdate = 2;
        assert!(ui1 > ui2);

        // (1, 2, 1) vs. (1, 2, 2)
        ui1.0.pswUpdate = 1;
        assert!(ui1 < ui2);
    }
}
