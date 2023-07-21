// Copyright (c) 2018-2022 The MobileCoin Foundation

//! The report data structure

use crate::ReportData;
use mc_util_encodings::Error as EncodingError;
use subtle::ConstantTimeEq;

#[derive(Clone, Debug, Default, Eq, Hash, PartialEq)]
pub struct ReportDataMask {
    data: ReportData,
    mask: ReportData,
}

impl ReportDataMask {
    pub fn new_with_mask(data: &[u8], mask: &[u8]) -> Result<Self, EncodingError> {
        if data.len() > ReportData::SIZE || mask.len() > ReportData::SIZE {
            Err(EncodingError::InvalidInputLength)
        } else {
            let mut retval = ReportDataMask::default();
            let r_data: &mut [u8] = retval.data.as_mut();
            r_data[..data.len()].copy_from_slice(data);
            let r_mask: &mut [u8] = retval.mask.as_mut();
            r_mask[..mask.len()].copy_from_slice(mask);
            Ok(retval)
        }
    }
}

impl<'src> TryFrom<&'src [u8]> for ReportDataMask {
    type Error = EncodingError;

    fn try_from(src: &[u8]) -> Result<Self, EncodingError> {
        if src.len() > ReportData::SIZE {
            Err(EncodingError::InvalidInputLength)
        } else {
            let mut retval = ReportDataMask::default();
            let data: &mut [u8] = retval.data.as_mut();
            data[..src.len()].copy_from_slice(src);
            let mask: &mut [u8] = retval.mask.as_mut();
            for byte in mask.iter_mut().take(src.len()) {
                *byte = 0xff;
            }
            Ok(retval)
        }
    }
}

impl PartialEq<ReportData> for ReportDataMask {
    fn eq(&self, rhs: &ReportData) -> bool {
        let data = &self.data & &self.mask;
        let masked_rhs = rhs & &self.mask;

        let data_ref: &[u8] = data.as_ref();
        data_ref.ct_eq(masked_rhs.as_ref()).unwrap_u8() == 1
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use mc_sgx_types::sgx_report_data_t;

    const REPORT_DATA_TEST: sgx_report_data_t = sgx_report_data_t {
        d: [
            1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
            25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46,
            47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64,
        ],
    };

    #[test]
    fn test_mask() {
        let bitmask: [u8; 32] = [
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff,
        ];

        let mask = ReportDataMask::new_with_mask(&REPORT_DATA_TEST.d[..], &bitmask[..])
            .expect("Could not create mask structure");
        let data: ReportData = REPORT_DATA_TEST.into();

        assert!(mask.eq(&data));
    }
}
