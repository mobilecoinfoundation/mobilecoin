// Copyright (c) 2018-2020 MobileCoin Inc.

//! Enclave CONFIGID.

/// The size of the x64 representation of[ConfigId], in bytes.
pub use mc_sgx_core_types_sys::SGX_CONFIGID_SIZE as CONFIG_ID_SIZE;

use crate::impl_ffi_wrapper;
use mc_sgx_core_types_sys::sgx_config_id_t;
#[cfg(feature = "use_prost")]
use mc_util_repr_bytes::derive_prost_message_from_repr_bytes;
#[cfg(feature = "use_serde")]
use mc_util_repr_bytes::derive_serde_from_repr_bytes;
use mc_util_repr_bytes::typenum::U64;

/// The SGX configuration ID data type.
///
/// A rust-friendly alternative to sgx_config_id_t, which contains the enclave CONFIGID, which is
/// used "to derive some keys" according to the SGX Developer Reference.
#[repr(transparent)]
pub struct ConfigId(sgx_config_id_t);

impl_ffi_wrapper! {
    ConfigId, sgx_config_id_t, U64;
}

#[cfg(feature = "use_prost")]
derive_prost_message_from_repr_bytes!(ConfigId);

#[cfg(feature = "use_serde")]
derive_serde_from_repr_bytes!(ConfigId);

impl Default for ConfigId {
    fn default() -> Self {
        Self([0u8; CONFIG_ID_SIZE])
    }
}

#[cfg(test)]
mod test {
    use super::*;
    #[cfg(feature = "use_serde")]
    use bincode::{deserialize, serialize};

    #[cfg(feature = "use_serde")]
    #[test]
    fn test_serde() {
        let src = [
            0u8, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
            24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45,
            46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63,
        ];

        let cid: ConfigId = (&src).into();
        let cidser = serialize(&cid).expect("Could not serialize ConfigId");
        let cid2: ConfigId = deserialize(&cidser).expect("Could not deserialize ConfigId");
        assert_eq!(cid, cid2);
        let dest: sgx_config_id_t = cid2.into();
        assert_eq!(&src[..], &dest[..]);
    }
}
