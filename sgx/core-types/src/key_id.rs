// Copyright (c) 2018-2020 MobileCoin Inc.

//! The key ID used in requests.

use crate::impl_ffi_wrapper;
use mc_sgx_core_types_sys::sgx_key_id_t;

/// The size of the [KeyId] structure's x64 representation, in bytes.
pub use mc_sgx_core_types_sys::SGX_KEYID_SIZE as KEY_ID_SIZE;

/// An SGX Key ID
#[derive(Default)]
#[repr(transparent)]
pub struct KeyId(sgx_key_id_t);

impl_ffi_wrapper! {
    KeyId, sgx_key_id_t, KEY_ID_SIZE, id;
}

#[cfg(test)]
mod test {
    use super::*;
    use bincode::{deserialize, serialize};

    #[test]
    fn test_serde() {
        let src = sgx_key_id_t {
            id: [
                1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
                24, 25, 26, 27, 28, 29, 30, 31, 32,
            ],
        };

        let keyid: KeyId = src.into();
        let serialized = serialize(&keyid).expect("Could not serialize cpu_keyid");
        let keyid2: KeyId = deserialize(&serialized).expect("Could not deserialize cpu_keyid");
        assert_eq!(keyid, keyid2);
    }
}
