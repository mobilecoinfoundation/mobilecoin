// Copyright (c) 2018-2020 MobileCoin Inc.

//! This module contains the wrapper type for an sgx_mac_t

/// The size of [Mac]'s x64 representation, in bytes.
pub use mc_sgx_core_types_sys::SGX_MAC_SIZE as MAC_SIZE;

use crate::impl_ffi_wrapper;
use mc_sgx_core_types_sys::sgx_mac_t;
#[cfg(feature = "use_prost")]
use mc_util_repr_bytes::derive_prost_message_from_repr_bytes;
#[cfg(feature = "use_serde")]
use mc_util_repr_bytes::derive_serde_from_repr_bytes;
use mc_util_repr_bytes::typenum::U16;

/// 128-bit CMAC of Report data.
#[derive(Default)]
#[repr(transparent)]
pub struct Mac(sgx_mac_t);

impl_ffi_wrapper! {
    Mac, sgx_mac_t, U16;
}

#[cfg(feature = "use_prost")]
derive_prost_message_from_repr_bytes!(Mac);

#[cfg(feature = "use_serde")]
derive_serde_from_repr_bytes!(Mac);

#[cfg(test)]
mod test {
    use super::*;
    #[cfg(feature = "use_serde")]
    use bincode::{deserialize, serialize};

    #[cfg(feature = "use_serde")]
    #[test]
    fn test_serde() {
        let src = [1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
        let mac: Mac = src.into();
        let serialized = serialize(&mac).expect("Error serializing a mac.");
        let mac2: Mac = deserialize(&serialized).expect("Error deserializing a mac");
        assert_eq!(mac, mac2);
    }
}
