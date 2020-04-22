//! Platform Info Blob wrapper

use mc_sgx_core_types::impl_ffi_wrapper;
use mc_sgx_epid_types_sys::sgx_platform_info_t;

/// The size of a [PlatformInfo]'s x64 representation, in bytes.
pub use mc_sgx_epid_types_sys::SGX_PLATFORM_INFO_SIZE as PLATFORM_INFO_SIZE;

/// A structure containing a "platform info blob", used by IAS
#[derive(Default)]
#[repr(transparent)]
pub struct PlatformInfo(sgx_platform_info_t);

impl_ffi_wrapper! {
    PlatformInfo, sgx_platform_info_t, PLATFORM_INFO_SIZE, platform_info;
}

#[cfg(test)]
mod test {
    use super::*;
    use bincode::{deserialize, serialize};

    #[test]
    fn serde() {
        let src = sgx_platform_info_t {
            platform_info: [
                1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
                24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44,
                45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64, 65,
                66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 84, 85, 86,
                87, 88, 89, 90, 91, 92, 93, 94, 95, 96, 97, 98, 99, 100, 101,
            ],
        };

        let pib = PlatformInfo::from(src);
        let serialized = serialize(&pib).expect("Could not serialize pib");
        let pib2 = deserialize::<PlatformInfo>(&serialized).expect("Could not deserialize pib");
        assert_eq!(pib, pib2);
    }
}
