// Copyright (c) 2018-2021 The MobileCoin Foundation

//! This is the FFI wrapper type for sgx_basename_t

use crate::impl_sgx_newtype_for_bytestruct;
use mc_sgx_types::sgx_basename_t;

const BASENAME_SIZE: usize = 32;

#[derive(Clone, Copy, Default)]
#[repr(transparent)]
pub struct Basename(sgx_basename_t);

impl_sgx_newtype_for_bytestruct! {
    Basename, sgx_basename_t, BASENAME_SIZE, name;
}

#[cfg(test)]
mod test {
    use super::*;
    use mc_util_serial::{deserialize, serialize};

    #[test]
    fn test_serde() {
        let src = sgx_basename_t {
            name: [
                1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
                24, 25, 26, 27, 28, 29, 30, 31, 32,
            ],
        };

        let name: Basename = src.into();
        let serialized = serialize(&name).expect("Could not serialize cpu_name");
        let name2: Basename = deserialize(&serialized).expect("Could not deserialize cpu_name");
        assert_eq!(name, name2);
    }
}
