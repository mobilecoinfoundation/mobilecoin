// Copyright (c) 2018-2020 MobileCoin Inc.

//! 128-bit SGX Key used to store a derived key.

use crate::impl_ffi_wrapper;
use mc_sgx_core_types_sys::sgx_key_128bit_t;

/// The size of the [Key128] structure's x64 representation, in bytes.
pub const KEY128_SIZE: usize = 16;

/// The ISV Family ID for a given enclave.
///
/// This is used when deriving keys when the Key Separation & Sharing feature is enabled.
#[derive(Default)]
#[repr(transparent)]
pub struct Key128(sgx_key_128bit_t);

impl_ffi_wrapper! {
    Key128, sgx_key_128bit_t, KEY128_SIZE;
}

#[cfg(test)]
mod test {
    use super::*;
    use bincode::{deserialize, serialize};

    #[test]
    fn test_serde() {
        let src = [1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
        let key1: Key128 = src.into();
        let serialized = serialize(&key1).expect("Error serializing 128-bit key.");
        let key2: Key128 = deserialize(&serialized).expect("Error deserializing 128-bit key");
        assert_eq!(key1, key2);
    }
}
