// Copyright (c) 2018-2021 The MobileCoin Foundation

//! This is the FFI wrapper type for sgx_keyid_t

use crate::impl_sgx_newtype_for_bytestruct;
use mc_sgx_types::{sgx_key_id_t, SGX_KEYID_SIZE};

/// An SGX Key ID
#[derive(Clone, Copy, Default)]
#[repr(transparent)]
pub struct KeyId(sgx_key_id_t);

impl_sgx_newtype_for_bytestruct! {
    KeyId, sgx_key_id_t, SGX_KEYID_SIZE, id;
}

#[cfg(test)]
mod test {
    use super::*;
    use mc_util_serial::{deserialize, serialize};

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
