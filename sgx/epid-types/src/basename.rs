// Copyright (c) 2018-2020 MobileCoin Inc.

//! Basename wrapper

use mc_sgx_core_types::impl_ffi_wrapper;
use mc_sgx_epid_types_sys::sgx_basename_t;
#[cfg(feature = "use_prost")]
use mc_util_repr_bytes::derive_prost_message_from_repr_bytes;
#[cfg(feature = "use_serde")]
use mc_util_repr_bytes::derive_serde_from_repr_bytes;
use mc_util_repr_bytes::typenum::U32;

/// The size of a [Basename] x64 representation, in bytes.
pub const BASENAME_SIZE: usize = 32;

/// An SGX basename used in a quote
#[derive(Default)]
#[repr(transparent)]
pub struct Basename(sgx_basename_t);

impl_ffi_wrapper! {
    Basename, sgx_basename_t, U32, name;
}

#[cfg(feature = "use_prost")]
derive_prost_message_from_repr_bytes!(Basename);

#[cfg(feature = "use_serde")]
derive_serde_from_repr_bytes!(Basename);

#[cfg(test)]
mod test {
    use super::*;
    #[cfg(feature = "use_serde")]
    use bincode::{deserialize, serialize};

    #[cfg(feature = "use_serde")]
    #[test]
    fn serde() {
        let src = sgx_basename_t {
            name: [
                1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
                24, 25, 26, 27, 28, 29, 30, 31, 32,
            ],
        };

        let name = Basename::from(src);
        let serialized = serialize(&name).expect("Could not serialize cpu_name");
        let name2 = deserialize::<Basename>(&serialized).expect("Could not deserialize cpu_name");
        assert_eq!(name, name2);
    }
}
