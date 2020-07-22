// Copyright (c) 2018-2020 MobileCoin Inc.

//! This is the FFI wrapper type for sgx_cpu_svn_t

use crate::impl_ffi_wrapper;
use mc_sgx_core_types_sys::sgx_cpu_svn_t;
#[cfg(feature = "use_prost")]
use mc_util_repr_bytes::derive_prost_message_from_repr_bytes;
#[cfg(feature = "use_serde")]
use mc_util_repr_bytes::derive_serde_from_repr_bytes;
use mc_util_repr_bytes::typenum::U16;

/// The size of the x64 representation of [CpuSecurityVersion], in bytes.
pub use mc_sgx_core_types_sys::SGX_CPUSVN_SIZE as CPU_SECURITY_VERSION_SIZE;

/// A CPU security version.
///
/// This value is used in key SGX SDK key derivation.
#[derive(Default)]
#[repr(transparent)]
pub struct CpuSecurityVersion(sgx_cpu_svn_t);

impl_ffi_wrapper! {
    CpuSecurityVersion, sgx_cpu_svn_t, U16, svn;
}

#[cfg(feature = "use_prost")]
derive_prost_message_from_repr_bytes!(CpuSecurityVersion);

#[cfg(feature = "use_serde")]
derive_serde_from_repr_bytes!(CpuSecurityVersion);

#[cfg(test)]
mod test {
    use super::*;
    #[cfg(feature = "use_serde")]
    use bincode::{deserialize, serialize};

    #[cfg(feature = "use_serde")]
    #[test]
    fn test_serde() {
        let src = sgx_cpu_svn_t {
            svn: [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16],
        };

        let svn: CpuSecurityVersion = src.into();
        let serialized = serialize(&svn).expect("Could not serialize cpu_svn");
        let svn2: CpuSecurityVersion =
            deserialize(&serialized).expect("Could not deserialize cpu_svn");
        assert_eq!(svn, svn2);
    }
}
