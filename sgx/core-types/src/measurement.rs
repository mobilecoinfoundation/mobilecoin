// Copyright (c) 2018-2020 MobileCoin Inc.

//! This module contains the wrapper types for an sgx_measurement_t
//!
//! Different types are used for MrSigner and MrEnclave to prevent misuse.

/// The size of a MrEnclave's x64 representation, in bytes.
pub use mc_sgx_core_types_sys::SGX_HASH_SIZE as MRENCLAVE_SIZE;

/// The size of a MrSigner's x64 representation, in bytes.
pub use mc_sgx_core_types_sys::SGX_HASH_SIZE as MRSIGNER_SIZE;

use crate::impl_ffi_wrapper;
use mc_sgx_core_types_sys::sgx_measurement_t;
#[cfg(feature = "use_prost")]
use mc_util_repr_bytes::derive_prost_message_from_repr_bytes;
#[cfg(feature = "use_serde")]
use mc_util_repr_bytes::derive_serde_from_repr_bytes;
use mc_util_repr_bytes::typenum::U32;

/// An opaque type for MRENCLAVE values.
///
/// A MRENCLAVE value is a chained cryptographic hash of the signed enclave binary (.so), and the
/// results of the page initialization steps which created the enclave's encrypted pages.
#[derive(Default)]
#[repr(transparent)]
pub struct MrEnclave(sgx_measurement_t);

/// An opaque type for MRSIGNER values.
///
/// A MRSIGNER value is a SHA256 hash of the public key an enclave was signed with.
#[derive(Default)]
#[repr(transparent)]
pub struct MrSigner(sgx_measurement_t);

impl_ffi_wrapper! {
    MrEnclave, sgx_measurement_t, U32, m;
    MrSigner, sgx_measurement_t, U32, m;
}

#[cfg(feature = "use_prost")]
derive_prost_message_from_repr_bytes!(MrEnclave);

#[cfg(feature = "use_serde")]
derive_serde_from_repr_bytes!(MrEnclave);

#[cfg(feature = "use_prost")]
derive_prost_message_from_repr_bytes!(MrSigner);

#[cfg(feature = "use_serde")]
derive_serde_from_repr_bytes!(MrSigner);

#[cfg(test)]
mod test {
    use super::*;
    #[cfg(feature = "use_serde")]
    use bincode::{deserialize, serialize};

    #[cfg(feature = "use_serde")]
    #[test]
    fn test_mrenclave_serde() {
        let mr_value = sgx_measurement_t {
            m: [
                1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
                24, 25, 26, 27, 28, 29, 30, 31, 32,
            ],
        };
        let mrenclave: MrEnclave = mr_value.into();
        let mrser = serialize(&mrenclave).expect("Could not serialize MrEnclave.");
        let mrdeser: MrEnclave = deserialize(&mrser).expect("Could not deserialize MrEnclave.");
        assert_eq!(mrenclave, mrdeser);
    }

    #[cfg(feature = "use_serde")]
    #[test]
    fn test_mrsigner_serde() {
        let mr_value = sgx_measurement_t {
            m: [
                1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
                24, 25, 26, 27, 28, 29, 30, 31, 32,
            ],
        };
        let mrsigner: MrSigner = mr_value.into();
        let mrser = serialize(&mrsigner).expect("Could not serialize MrSigner.");
        let mrdeser: MrSigner = deserialize(&mrser).expect("Could not deserialize MrSigner.");
        assert_eq!(mrsigner, mrdeser);
    }
}
