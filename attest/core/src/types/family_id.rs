// Copyright (c) 2018-2021 The MobileCoin Foundation

//! This is the FFI Wrapper type for sgx_isvfamily_id_t

use crate::impl_sgx_newtype_for_bytearray;
use mc_sgx_types::{sgx_isvfamily_id_t, SGX_ISV_FAMILY_ID_SIZE};

#[derive(Clone, Copy)]
pub struct FamilyId(sgx_isvfamily_id_t);

impl_sgx_newtype_for_bytearray! {
    FamilyId, sgx_isvfamily_id_t, SGX_ISV_FAMILY_ID_SIZE;
}

#[cfg(test)]
mod test {
    use super::*;
    use mc_util_serial::*;

    #[test]
    fn test_serde() {
        let src = [1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
        let famid: FamilyId = src.into();
        let serialized = serialize(&famid).expect("Error serializing extended product id.");
        let famid2: FamilyId =
            deserialize(&serialized).expect("Error deserializing extended product id");
        assert_eq!(famid, famid2);
    }
}
