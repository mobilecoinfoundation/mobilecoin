// Copyright (c) 2018-2020 MobileCoin Inc.

//! This is the FFI wrapper for sgx_isvext_prod_id_t

/// The size of the x64 representation of an [ExtendedProductId], in bytes.
pub use mc_sgx_core_types_sys::SGX_ISVEXT_PROD_ID_SIZE as EXTENDED_PRODUCT_ID_SIZE;

use crate::impl_ffi_wrapper;
use mc_sgx_core_types_sys::sgx_isvext_prod_id_t;
#[cfg(feature = "use_prost")]
use mc_util_repr_bytes::derive_prost_message_from_repr_bytes;
#[cfg(feature = "use_serde")]
use mc_util_repr_bytes::derive_serde_from_repr_bytes;
use mc_util_repr_bytes::typenum::U16;

/// The Extended Product ID data type.
#[derive(Default)]
#[repr(transparent)]
pub struct ExtendedProductId(sgx_isvext_prod_id_t);

impl_ffi_wrapper! {
    ExtendedProductId, sgx_isvext_prod_id_t, U16;
}

#[cfg(feature = "use_prost")]
derive_prost_message_from_repr_bytes!(ExtendedProductId);

#[cfg(feature = "use_serde")]
derive_serde_from_repr_bytes!(ExtendedProductId);

#[cfg(test)]
mod test {
    use super::*;
    #[cfg(feature = "use_serde")]
    use bincode::{deserialize, serialize};

    #[cfg(feature = "use_serde")]
    #[test]
    fn test_serde() {
        let src = [1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
        let prodid: ExtendedProductId = src.into();
        let serialized = serialize(&prodid).expect("Error serializing extended product id.");
        let prodid2: ExtendedProductId =
            deserialize(&serialized).expect("Error deserializing extended product id");
        assert_eq!(prodid, prodid2);
    }
}
