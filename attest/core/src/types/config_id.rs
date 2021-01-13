// Copyright (c) 2018-2021 The MobileCoin Foundation

//! This module contains the wrapper type for an sgx_config_id_t

use crate::impl_sgx_newtype_for_bytearray;
use mc_sgx_types::{sgx_config_id_t, SGX_CONFIGID_SIZE};

/// A configuration ID data type
///
/// This type exists because of the lack of non-type polymorphism, and
/// should be removed once https://github.com/rust-lang/rust/issues/44580
/// has been completed.
#[derive(Clone, Copy)]
pub struct ConfigId(sgx_config_id_t);

impl_sgx_newtype_for_bytearray! {
    ConfigId, sgx_config_id_t, SGX_CONFIGID_SIZE;
}

#[cfg(test)]
mod test {
    use super::*;
    use mc_util_serial::{deserialize, serialize};

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
