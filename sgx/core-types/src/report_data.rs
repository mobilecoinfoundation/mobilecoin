// Copyright (c) 2018-2020 MobileCoin Inc.

//! The report data structure

/// The size of the [ReportData] x64 representation, in bytes.
pub use mc_sgx_core_types_sys::SGX_REPORT_DATA_SIZE as REPORT_DATA_SIZE;

use crate::impl_ffi_wrapper;
use core::ops::BitAnd;
use mc_sgx_core_types_sys::sgx_report_data_t;
#[cfg(feature = "use_prost")]
use mc_util_repr_bytes::derive_prost_message_from_repr_bytes;
#[cfg(feature = "use_serde")]
use mc_util_repr_bytes::derive_serde_from_repr_bytes;
use mc_util_repr_bytes::typenum::U64;

/// A data structure used for the user data in a report.
#[derive(Default)]
#[repr(transparent)]
pub struct ReportData(sgx_report_data_t);

impl_ffi_wrapper! {
    ReportData, sgx_report_data_t, U64, d;
}

#[cfg(feature = "use_prost")]
derive_prost_message_from_repr_bytes!(ReportData);

#[cfg(feature = "use_serde")]
derive_serde_from_repr_bytes!(ReportData);

impl BitAnd for ReportData {
    type Output = Self;

    fn bitand(self, rhs: Self) -> Self::Output {
        let mut output = self;
        for i in 0..REPORT_DATA_SIZE {
            output.0.d[i] &= rhs.0.d[i];
        }

        output
    }
}

#[cfg(test)]
mod test {
    use super::*;
    #[cfg(feature = "use_serde")]
    use bincode::{deserialize, serialize};
    use core::convert::TryFrom;

    const REPORT_DATA_TEST: sgx_report_data_t = sgx_report_data_t {
        d: [
            1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
            25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46,
            47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64,
        ],
    };

    #[cfg(feature = "use_serde")]
    #[test]
    fn test_serde() {
        let data = ReportData::from(&REPORT_DATA_TEST);
        let serialized = serialize(&data).expect("Could not serialize report_data");
        let data2: ReportData =
            deserialize(&serialized).expect("Could not deserialize report_data");
        assert_eq!(data, data2);
    }

    #[test]
    fn test_mask() {
        let bitmask: [u8; REPORT_DATA_SIZE] = [
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];

        let mask = ReportData::try_from(&bitmask[..]).expect("Could not create mask structure");
        let data = ReportData::from(&REPORT_DATA_TEST);

        assert!(mask & data.clone() != data);
    }
}
