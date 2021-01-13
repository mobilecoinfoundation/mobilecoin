// Copyright (c) 2018-2021 The MobileCoin Foundation

//! This is the FFI wrapper type for sgx_cpu_svn_t

use crate::impl_sgx_newtype_for_bytestruct;
use mc_sgx_types::{sgx_cpu_svn_t, SGX_CPUSVN_SIZE};

#[derive(Clone, Copy, Default)]
#[repr(transparent)]
pub struct CpuSecurityVersion(sgx_cpu_svn_t);

impl_sgx_newtype_for_bytestruct! {
    CpuSecurityVersion, sgx_cpu_svn_t, SGX_CPUSVN_SIZE, svn;
}

#[cfg(test)]
mod test {
    use super::*;
    use mc_util_serial::{deserialize, serialize};

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
