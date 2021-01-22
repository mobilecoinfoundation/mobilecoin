// Copyright (c) 2018-2021 The MobileCoin Foundation

//! The report data structure

use crate::impl_sgx_newtype_for_bytestruct;
use core::convert::TryFrom;
use mc_sgx_types::{sgx_report_data_t, SGX_REPORT_DATA_SIZE};
use mc_util_encodings::{Error as EncodingError, IntelLayout};
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;

/// A data structure used for the user data in a report.
#[derive(Clone, Copy, Default)]
#[repr(transparent)]
pub struct ReportData(sgx_report_data_t);

impl_sgx_newtype_for_bytestruct! {
    ReportData, sgx_report_data_t, SGX_REPORT_DATA_SIZE, d;
}

#[derive(
    Clone, Copy, Debug, Default, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize,
)]
pub struct ReportDataMask {
    data: ReportData,
    mask: ReportData,
}

impl ReportDataMask {
    pub fn new_with_mask(data: &[u8], mask: &[u8]) -> Result<Self, EncodingError> {
        if data.len() > ReportData::X86_64_CSIZE || mask.len() > ReportData::X86_64_CSIZE {
            Err(EncodingError::InvalidInputLength)
        } else {
            let mut retval = ReportDataMask::default();
            retval.data.0.d[..data.len()].copy_from_slice(data);
            retval.mask.0.d[..mask.len()].copy_from_slice(mask);
            Ok(retval)
        }
    }
}

impl<'src> TryFrom<&'src [u8]> for ReportDataMask {
    type Error = EncodingError;

    fn try_from(src: &[u8]) -> Result<Self, EncodingError> {
        if src.len() > ReportData::X86_64_CSIZE {
            Err(EncodingError::InvalidInputLength)
        } else {
            let mut retval = ReportDataMask::default();
            retval.data.0.d[..src.len()].copy_from_slice(src);
            for i in 0..src.len() {
                retval.mask.0.d[i] = 0xff;
            }
            Ok(retval)
        }
    }
}

impl PartialEq<ReportData> for ReportDataMask {
    fn eq(&self, rhs: &ReportData) -> bool {
        let mut self_data = [0u8; ReportData::X86_64_CSIZE];
        let mut rhs_data = [0u8; ReportData::X86_64_CSIZE];

        for i in 0..self.mask.0.d.len() {
            self_data[i] = self.data.0.d[i] & self.mask.0.d[i];
            rhs_data[i] = rhs.0.d[i] & self.mask.0.d[i];
        }

        self_data[..].ct_eq(&rhs_data[..]).unwrap_u8() == 1
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use mc_util_serial::{deserialize, serialize};

    const REPORT_DATA_TEST: sgx_report_data_t = sgx_report_data_t {
        d: [
            1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
            25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46,
            47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64,
        ],
    };

    #[test]
    fn test_serde() {
        let data: ReportData = REPORT_DATA_TEST.clone().into();
        let serialized = serialize(&data).expect("Could not serialize report_data");
        let data2: ReportData =
            deserialize(&serialized).expect("Could not deserialize report_data");
        assert_eq!(data, data2);
    }

    #[test]
    fn test_mask() {
        let bitmask: [u8; 32] = [
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff,
        ];

        let mask = ReportDataMask::new_with_mask(&REPORT_DATA_TEST.d[..], &bitmask[..])
            .expect("Could not create mask structure");
        let data: ReportData = REPORT_DATA_TEST.clone().into();

        assert!(mask.eq(&data));
    }
}
