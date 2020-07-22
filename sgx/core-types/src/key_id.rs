// Copyright (c) 2018-2020 MobileCoin Inc.

//! The key ID used in requests.

/// The size of the [KeyId] structure's x64 representation, in bytes.
pub use mc_sgx_core_types_sys::SGX_KEYID_SIZE as KEY_ID_SIZE;

use crate::impl_ffi_wrapper;
use mc_sgx_core_types_sys::sgx_key_id_t;
#[cfg(feature = "use_prost")]
use mc_util_repr_bytes::derive_prost_message_from_repr_bytes;
#[cfg(feature = "use_serde")]
use mc_util_repr_bytes::derive_serde_from_repr_bytes;
use mc_util_repr_bytes::typenum::U32;

/// An SGX Key ID
#[derive(Default)]
#[repr(transparent)]
pub struct KeyId(sgx_key_id_t);

impl_ffi_wrapper! {
    KeyId, sgx_key_id_t, U32, id;
}

#[cfg(feature = "use_prost")]
derive_prost_message_from_repr_bytes!(KeyId);

#[cfg(feature = "use_serde")]
derive_serde_from_repr_bytes!(KeyId);

#[cfg(test)]
mod test {
    use super::*;
    #[cfg(feature = "use_serde")]
    use bincode::{deserialize, serialize};

    #[cfg(feature = "use_serde")]
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
