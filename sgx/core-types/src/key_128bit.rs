// Copyright (c) 2018-2020 MobileCoin Inc.

//! 128-bit SGX Key used to store a derived key.

use crate::impl_ffi_wrapper;
use mc_sgx_core_types_sys::sgx_key_128bit_t;
#[cfg(feature = "use_prost")]
use mc_util_repr_bytes::derive_prost_message_from_repr_bytes;
#[cfg(feature = "use_serde")]
use mc_util_repr_bytes::derive_serde_from_repr_bytes;
use mc_util_repr_bytes::typenum::U16;

/// The size of the [Key128] structure's x64 representation, in bytes.
pub const KEY128_SIZE: usize = 16;

/// The ISV Family ID for a given enclave.
///
/// This is used when deriving keys when the Key Separation & Sharing feature is enabled.
#[derive(Default)]
#[repr(transparent)]
pub struct Key128(sgx_key_128bit_t);

impl_ffi_wrapper! {
    Key128, sgx_key_128bit_t, U16;
}

#[cfg(feature = "use_prost")]
derive_prost_message_from_repr_bytes!(Key128);

#[cfg(feature = "use_serde")]
derive_serde_from_repr_bytes!(Key128);

#[cfg(test)]
mod test {
    use super::*;
    #[cfg(feature = "use_serde")]
    use bincode::{deserialize, serialize};

    #[cfg(feature = "use_serde")]
    #[test]
    fn test_serde() {
        let src = [1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
        let key1: Key128 = src.into();
        let serialized = serialize(&key1).expect("Error serializing 128-bit key.");
        let key2: Key128 = deserialize(&serialized).expect("Error deserializing 128-bit key");
        assert_eq!(key1, key2);
    }
}
