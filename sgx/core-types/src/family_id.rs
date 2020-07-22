// Copyright (c) 2018-2020 MobileCoin Inc.

//! ISV Family ID.

/// The size of the X64 representation of a [FamilyId], in bytes.
pub use mc_sgx_core_types_sys::SGX_ISV_FAMILY_ID_SIZE as FAMILY_ID_SIZE;

use crate::impl_ffi_wrapper;
use mc_sgx_core_types_sys::sgx_isvfamily_id_t;
#[cfg(feature = "use_prost")]
use mc_util_repr_bytes::derive_prost_message_from_repr_bytes;
#[cfg(feature = "use_serde")]
use mc_util_repr_bytes::derive_serde_from_repr_bytes;
use mc_util_repr_bytes::typenum::U16;

/// The ISV Family ID for a given enclave.
///
/// This is used when deriving keys when the Key Separation & Sharing feature is enabled.
#[derive(Default)]
#[repr(transparent)]
pub struct FamilyId(sgx_isvfamily_id_t);

impl_ffi_wrapper! {
    FamilyId, sgx_isvfamily_id_t, U16;
}

#[cfg(feature = "use_prost")]
derive_prost_message_from_repr_bytes!(FamilyId);

#[cfg(feature = "use_serde")]
derive_serde_from_repr_bytes!(FamilyId);

#[cfg(test)]
mod test {
    use super::*;
    #[cfg(feature = "use_serde")]
    use bincode::{deserialize, serialize};

    #[cfg(feature = "use_serde")]
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
