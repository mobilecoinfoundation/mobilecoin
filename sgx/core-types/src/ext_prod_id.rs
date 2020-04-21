// Copyright (c) 2018-2020 MobileCoin Inc.

//! This is the FFI wrapper for sgx_isvext_prod_id_t

use crate::impl_ffi_wrapper;
use mc_sgx_core_types_sys::sgx_isvext_prod_id_t;

/// The size of the x64 representation of an [ExtendedProductId], in bytes.
pub use mc_sgx_core_types_sys::SGX_ISVEXT_PROD_ID_SIZE as EXTENDED_PRODUCT_ID_SIZE;

/// The Extended Product ID data type
///
/// This type exists because of the lack of non-type polymorphism, and
/// should be removed once https://github.com/rust-lang/rust/issues/44580
/// has been completed.
#[derive(Default)]
#[repr(transparent)]
pub struct ExtendedProductId(sgx_isvext_prod_id_t);

impl_ffi_wrapper! {
    ExtendedProductId, sgx_isvext_prod_id_t, EXTENDED_PRODUCT_ID_SIZE;
}

#[cfg(test)]
mod test {
    use super::*;
    use bincode::{deserialize, serialize};

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
