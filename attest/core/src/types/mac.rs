// Copyright (c) 2018-2021 The MobileCoin Foundation

//! This module contains the wrapper type for an sgx_mac_t

use crate::impl_sgx_newtype_for_bytearray;
use mc_sgx_types::{sgx_mac_t, SGX_MAC_SIZE};

/// A configuration ID data type
///
/// This type exists because of the lack of non-type polymorphism, and
/// should be removed once https://github.com/rust-lang/rust/issues/44580
/// has been completed.
#[derive(Clone, Copy)]
pub struct Mac(sgx_mac_t);

impl_sgx_newtype_for_bytearray! {
    Mac, sgx_mac_t, SGX_MAC_SIZE;
}

#[cfg(test)]
mod test {
    use super::*;
    use mc_util_serial::*;

    #[test]
    fn test_serde() {
        let src = [1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
        let mac: Mac = src.into();
        let serialized = serialize(&mac).expect("Error serializing extended product id.");
        let mac2: Mac = deserialize(&serialized).expect("Error deserializing extended product id");
        assert_eq!(mac, mac2);
    }
}
