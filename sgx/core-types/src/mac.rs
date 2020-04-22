// Copyright (c) 2018-2020 MobileCoin Inc.

//! This module contains the wrapper type for an sgx_mac_t

use crate::impl_ffi_wrapper;
use mc_sgx_core_types_sys::{sgx_mac_t, SGX_MAC_SIZE};

/// The size of [Mac]'s x64 representation, in bytes.
pub use mc_sgx_core_types_sys::SGX_MAC_SIZE as MAC_SIZE;

/// 128-bit CMAC of Report data.
#[derive(Default)]
#[repr(transparent)]
pub struct Mac(sgx_mac_t);

impl_ffi_wrapper! {
    Mac, sgx_mac_t, SGX_MAC_SIZE;
}

#[cfg(test)]
mod test {
    use super::*;
    use bincode::{deserialize, serialize};

    #[test]
    fn test_serde() {
        let src = [1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
        let mac: Mac = src.into();
        let serialized = serialize(&mac).expect("Error serializing a mac.");
        let mac2: Mac = deserialize(&serialized).expect("Error deserializing a mac");
        assert_eq!(mac, mac2);
    }
}
