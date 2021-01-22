// Copyright (c) 2018-2021 The MobileCoin Foundation

//! This module contains the wrapper type for an sgx_isvext_prod_id_t

use crate::impl_sgx_newtype_for_bytearray;
use mc_sgx_types::{sgx_isvext_prod_id_t, SGX_ISVEXT_PROD_ID_SIZE};

/// The Extended Product ID data type
///
/// This type exists because of the lack of non-type polymorphism, and
/// should be removed once https://github.com/rust-lang/rust/issues/44580
/// has been completed.
#[derive(Clone, Copy)]
pub struct ExtendedProductId(sgx_isvext_prod_id_t);

impl_sgx_newtype_for_bytearray! {
    ExtendedProductId, sgx_isvext_prod_id_t, SGX_ISVEXT_PROD_ID_SIZE;
}

#[cfg(test)]
mod test {
    use super::*;
    use mc_util_serial::*;

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
