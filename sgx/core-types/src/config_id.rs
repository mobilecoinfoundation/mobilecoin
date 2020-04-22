// Copyright (c) 2018-2020 MobileCoin Inc.

//! Enclave CONFIGID.

use crate::impl_ffi_wrapper;
use mc_sgx_core_types_sys::sgx_config_id_t;

/// The size of the x64 representation of[ConfigId], in bytes.
pub use mc_sgx_core_types_sys::SGX_CONFIGID_SIZE as CONFIG_ID_SIZE;

/// The SGX configuration ID data type.
///
/// A rust-friendly alternative to sgx_config_id_t, which contains the enclave CONFIGID, which is
/// used "to derive some keys" according to the SGX Developer Reference.
#[repr(transparent)]
pub struct ConfigId(sgx_config_id_t);

impl_ffi_wrapper! {
    ConfigId, sgx_config_id_t, CONFIG_ID_SIZE;
}

impl Default for ConfigId {
    fn default() -> Self {
        Self([0u8; CONFIG_ID_SIZE])
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use bincode::{deserialize, serialize};

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
