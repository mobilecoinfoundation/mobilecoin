// Copyright (c) 2018-2020 MobileCoin Inc.

//! SGX Report Structures

use crate::{
    _macros::FfiWrapper,
    impl_ffi_wrapper_base, impl_serialize_to_x64,
    key_id::{KeyId, KEY_ID_SIZE},
    mac::{Mac, MAC_SIZE},
    report_body::{ReportBody, REPORT_BODY_SIZE},
};
use core::{
    cmp::Ordering,
    fmt::{Debug, Display, Formatter, Result as FmtResult},
    hash::{Hash, Hasher},
};
use mc_encodings::{Error as EncodingError, FromX64, ToX64};
use mc_sgx_core_types_sys::sgx_report_t;

const BODY_START: usize = 0;
const BODY_END: usize = REPORT_BODY_SIZE;
const KEY_ID_START: usize = BODY_END;
const KEY_ID_END: usize = KEY_ID_START + KEY_ID_SIZE;
const MAC_START: usize = KEY_ID_END;
const MAC_END: usize = MAC_START + MAC_SIZE;

/// The size of the SGX report structure's x64 representation, in bytes.
pub const REPORT_SIZE: usize = MAC_END;

/// The results of an EREPORT called from within SGX
///
/// In attestation, the enclave under test will generate a report for use
/// by another enclave addressible by it's TargetInfo.
#[derive(Default)]
#[repr(transparent)]
pub struct Report(sgx_report_t);

impl_ffi_wrapper_base! {
    Report, sgx_report_t, REPORT_SIZE;
}

impl_serialize_to_x64! {
    Report, REPORT_SIZE;
}

impl Report {
    /// Retrieve the report body structure
    pub fn body(&self) -> ReportBody {
        ReportBody::from(&self.0.body)
    }

    /// Retrieve the Key ID used to construct the report
    pub fn key_id(&self) -> KeyId {
        KeyId::from(&self.0.key_id)
    }

    /// Retrieve the MAC of the report
    pub fn mac(&self) -> Mac {
        Mac::from(&self.0.mac)
    }
}

impl Debug for Report {
    fn fmt(&self, formatter: &mut Formatter) -> FmtResult {
        write!(
            formatter,
            "Report: {{ body: {:?}, key: {:?}, mac: {:?} }}",
            self.body(),
            self.key_id(),
            self.mac()
        )
    }
}

impl Display for Report {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        write!(
            f,
            "SGX report {}, signed by key {}, with mac {}",
            self.body(),
            self.key_id(),
            self.mac()
        )
    }
}

impl FfiWrapper<sgx_report_t> for Report {}

impl From<&sgx_report_t> for Report {
    fn from(src: &sgx_report_t) -> Self {
        Self(sgx_report_t {
            body: ReportBody::from(&src.body).into(),
            mac: Mac::from(&src.mac).into(),
            key_id: KeyId::from(&src.key_id).into(),
        })
    }
}

impl FromX64 for Report {
    type Error = EncodingError;

    fn from_x64(src: &[u8]) -> Result<Self, EncodingError> {
        if src.len() < REPORT_SIZE {
            return Err(EncodingError::InvalidInputLength);
        }
        Ok(Self(sgx_report_t {
            body: ReportBody::from_x64(&src[BODY_START..BODY_END])?.into(),
            mac: Mac::from_x64(&src[MAC_START..MAC_END])?.into(),
            key_id: KeyId::from_x64(&src[KEY_ID_START..KEY_ID_END])?.into(),
        }))
    }
}

impl Hash for Report {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.body().hash(state);
        self.key_id().hash(state);
        self.mac().hash(state);
    }
}

// Note, intentionally skipping comparison of mac here, per NCC audit, to avoid
// side-channel leakage of the mac value
impl Ord for Report {
    fn cmp(&self, other: &Self) -> Ordering {
        match self.body().cmp(&other.body()) {
            Ordering::Equal => self.key_id().cmp(&other.key_id()),
            other => other,
        }
    }
}

impl PartialEq for Report {
    fn eq(&self, other: &Self) -> bool {
        use subtle::ConstantTimeEq;
        self.0.mac[..].ct_eq(&other.0.mac[..]).into()
    }
}

impl ToX64 for Report {
    fn to_x64(&self, dest: &mut [u8]) -> Result<usize, usize> {
        if dest.len() < REPORT_SIZE {
            Err(REPORT_SIZE)
        } else {
            self.body()
                .to_x64(&mut dest[BODY_START..BODY_END])
                .or(Err(REPORT_SIZE))?;
            self.key_id()
                .to_x64(&mut dest[KEY_ID_START..KEY_ID_END])
                .or(Err(REPORT_SIZE))?;
            self.mac()
                .to_x64(&mut dest[MAC_START..MAC_END])
                .or(Err(REPORT_SIZE))?;
            Ok(REPORT_SIZE)
        }
    }
}

#[cfg(test)]
mod test {
    extern crate std;

    use std::{format, vec};

    use super::*;
    use bincode::{deserialize, serialize};
    use mc_sgx_core_types_sys::{
        sgx_attributes_t, sgx_cpu_svn_t, sgx_key_id_t, sgx_measurement_t, sgx_report_body_t,
        sgx_report_data_t,
    };
    const TEST_REPORT1: sgx_report_t = sgx_report_t {
        body: sgx_report_body_t {
            cpu_svn: sgx_cpu_svn_t {
                svn: [1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16],
            },
            misc_select: 17,
            reserved1: [0u8; 12],
            isv_ext_prod_id: [1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16],
            attributes: sgx_attributes_t {
                flags: 0x0102_0304_0506_0708,
                xfrm: 0x0807_0605_0403_0201,
            },
            mr_enclave: sgx_measurement_t {
                m: [
                    17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36,
                    37, 38, 39, 40, 41, 42, 43, 43, 44, 45, 46, 47,
                ],
            },
            reserved2: [0u8; 32],
            mr_signer: sgx_measurement_t {
                m: [
                    48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64, 65, 66, 67,
                    68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79,
                ],
            },
            reserved3: [0u8; 32],
            config_id: [
                80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 91, 92, 93, 94, 95, 96, 97, 98, 99,
                100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 112, 113, 114, 115,
                116, 117, 118, 119, 120, 121, 122, 123, 124, 125, 126, 127, 128, 129, 130, 131,
                132, 133, 134, 135, 136, 137, 138, 139, 140, 141, 142, 143,
            ],
            isv_prod_id: 144,
            isv_svn: 145,
            config_svn: 146,
            reserved4: [0u8; 42],
            isv_family_id: [
                147, 148, 149, 150, 151, 152, 153, 154, 155, 156, 157, 158, 159, 160, 161, 162,
            ],
            report_data: sgx_report_data_t {
                d: [
                    163, 164, 165, 166, 167, 168, 169, 170, 171, 172, 173, 174, 175, 176, 177, 178,
                    179, 180, 181, 182, 183, 184, 185, 186, 187, 188, 189, 190, 191, 192, 193, 194,
                    195, 196, 197, 198, 199, 200, 201, 202, 203, 204, 205, 206, 207, 208, 209, 210,
                    211, 212, 213, 214, 215, 216, 217, 218, 219, 220, 221, 222, 223, 224, 225, 226,
                ],
            },
        },
        mac: [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16],
        key_id: sgx_key_id_t {
            id: [
                1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
                24, 25, 26, 27, 28, 29, 30, 31, 32,
            ],
        },
    };

    const TEST_REPORT_DEBUGSTR: &str = "Report: { body: ReportBody: { cpu_svn: CpuSecurityVersion: [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16], misc_select: 17, isv_ext_prod_id: ExtendedProductId: [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16], attributes: Attributes { flags: 72623859790382856, xfrm: 578437695752307201 }, mr_enclave: MrEnclave: [17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 43, 44, 45, 46, 47], mr_signer: MrSigner: [48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64, 65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79], config_id: ConfigId: [80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 91, 92, 93, 94, 95, 96, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 112, 113, 114, 115, 116, 117, 118, 119, 120, 121, 122, 123, 124, 125, 126, 127, 128, 129, 130, 131, 132, 133, 134, 135, 136, 137, 138, 139, 140, 141, 142, 143], isv_prod_id: 144, isv_svn: 145, config_svn: 146, isv_family_id: FamilyId: [147, 148, 149, 150, 151, 152, 153, 154, 155, 156, 157, 158, 159, 160, 161, 162], report_data: ReportData: [163, 164, 165, 166, 167, 168, 169, 170, 171, 172, 173, 174, 175, 176, 177, 178, 179, 180, 181, 182, 183, 184, 185, 186, 187, 188, 189, 190, 191, 192, 193, 194, 195, 196, 197, 198, 199, 200, 201, 202, 203, 204, 205, 206, 207, 208, 209, 210, 211, 212, 213, 214, 215, 216, 217, 218, 219, 220, 221, 222, 223, 224, 225, 226] }, key: KeyId: [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32], mac: Mac: [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16] }";

    #[test]
    fn test_serde() {
        let report = Report::from(&TEST_REPORT1);
        let serialized = serialize(&report).expect("Could not serialize report");
        let report2: Report = deserialize(&serialized).expect("Could not deserialize report");
        assert_eq!(report, report2);
    }

    #[test]
    fn test_debug() {
        let report = Report::from(&TEST_REPORT1);
        let debug_str = format!("{:?}", &report);
        assert_eq!(&debug_str, TEST_REPORT_DEBUGSTR);
    }

    #[test]
    fn test_ord() {
        let report1 = Report::from(&TEST_REPORT1);
        let mut report2 = report1.clone();
        assert_eq!(report1, report2);
        assert!(!(report1 < report2));

        let orig_value = report2.0.key_id.id[0];
        report2.0.key_id.id[0] = 255;
        assert!(report1 < report2);
        report2.0.key_id.id[0] = orig_value;
        assert_eq!(report1, report2);
        assert!(!(report1 < report2));
    }

    #[test]
    // Report::try_from should return EncodingError::InvalidInputLength if the input contains fewer
    // than REPORT_SIZE bytes.
    fn test_report_try_from_insufficient_length() {
        let sparkle_heart = vec![240, 159, 146, 150];
        match Report::from_x64(&sparkle_heart[..]) {
            Ok(_) => panic!(),
            Err(EncodingError::InvalidInputLength) => {} // Expected.
            Err(e) => panic!("Unexpected error {:?}", e),
        }
    }
}
