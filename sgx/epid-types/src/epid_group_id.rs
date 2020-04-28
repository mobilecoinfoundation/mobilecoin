// Copyright (c) 2018-2020 MobileCoin Inc.

//! SGX Quote wrapper

use mc_sgx_core_types::impl_ffi_wrapper;
use mc_sgx_epid_types_sys::sgx_epid_group_id_t;

/// The size of an [EpidGroupId] x64 representation, in bytes.
pub const EPID_GROUP_ID_SIZE: usize = 4;

/// The EPID group ID structure, used to retrieve
#[derive(Default)]
#[repr(transparent)]
pub struct EpidGroupId(sgx_epid_group_id_t);

impl_ffi_wrapper! {
    EpidGroupId, sgx_epid_group_id_t, EPID_GROUP_ID_SIZE;
}

#[cfg(test)]
mod test {
    extern crate std;

    use super::*;
    use bincode::{deserialize, serialize};
    use std::format;

    #[test]
    fn serde() {
        let gid = [0u8, 1, 2, 3];
        let epid_gid = EpidGroupId::from(gid).expect("Could not create group ID from bytes.");

        let ser = serialize(&epid_gid).expect("Error serializing epidgid.");
        let epid_gid2 = deserialize::<EpidGroupId>(&ser).expect("Error deserializing epidgid");
        assert_eq!(epid_gid, epid_gid2);
    }

    #[test]
    fn display() {
        let gid: sgx_epid_group_id_t = [0x2eu8, 0x0b, 0, 0];
        let epid_gid = EpidGroupId::from(gid);
        assert_eq!("00000b2e", format!("{}", epid_gid));
    }
}
