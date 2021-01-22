// Copyright (c) 2018-2021 The MobileCoin Foundation

//! A structure for handling report bodies

use crate::{
    error::ReportBodyVerifyError,
    impl_sgx_wrapper_reqs,
    traits::SgxWrapperType,
    types::{
        attributes::Attributes,
        config_id::ConfigId,
        cpu_svn::CpuSecurityVersion,
        ext_prod_id::ExtendedProductId,
        family_id::FamilyId,
        measurement::{Measurement, MrEnclave, MrSigner},
        report_data::{ReportData, ReportDataMask},
        ConfigSecurityVersion, MiscSelect, ProductId, SecurityVersion,
    },
};
use alloc::vec::Vec;
use core::{
    cmp::Ordering,
    convert::{TryFrom, TryInto},
    fmt::{Debug, Formatter, Result as FmtResult},
    hash::{Hash, Hasher},
    mem::size_of,
};
use mc_sgx_types::{sgx_report_body_t, SGX_FLAGS_DEBUG};
use mc_util_encodings::{Error as EncodingError, IntelLayout};

// Offsets of various fields in a sgx_report_body_t with x86_64 layout
const RB_CPUSVN_START: usize = 0;
const RB_CPUSVN_END: usize = RB_CPUSVN_START + <CpuSecurityVersion as IntelLayout>::X86_64_CSIZE;
const RB_SELECT_START: usize = RB_CPUSVN_END;
const RB_SELECT_END: usize = RB_SELECT_START + size_of::<u32>();
const RB_RESERVED1_START: usize = RB_SELECT_END;
const RB_RESERVED1_END: usize = RB_RESERVED1_START + 12;
const RB_EXTPRODID_START: usize = RB_RESERVED1_END;
const RB_EXTPRODID_END: usize =
    RB_EXTPRODID_START + <ExtendedProductId as IntelLayout>::X86_64_CSIZE;
const RB_ATTRIBUTES_START: usize = RB_EXTPRODID_END;
const RB_ATTRIBUTES_END: usize = RB_ATTRIBUTES_START + <Attributes as IntelLayout>::X86_64_CSIZE;
const RB_MRENCLAVE_START: usize = RB_ATTRIBUTES_END;
const RB_MRENCLAVE_END: usize = RB_MRENCLAVE_START + <MrEnclave as IntelLayout>::X86_64_CSIZE;
const RB_RESERVED2_START: usize = RB_MRENCLAVE_END;
const RB_RESERVED2_END: usize = RB_RESERVED2_START + 32;
const RB_MRSIGNER_START: usize = RB_RESERVED2_END;
const RB_MRSIGNER_END: usize = RB_MRSIGNER_START + <MrSigner as IntelLayout>::X86_64_CSIZE;
const RB_RESERVED3_START: usize = RB_MRSIGNER_END;
const RB_RESERVED3_END: usize = RB_RESERVED3_START + 32;
const RB_CONFIGID_START: usize = RB_RESERVED3_END;
const RB_CONFIGID_END: usize = RB_CONFIGID_START + <ConfigId as IntelLayout>::X86_64_CSIZE;
const RB_ISVPRODID_START: usize = RB_CONFIGID_END;
const RB_ISVPRODID_END: usize = RB_ISVPRODID_START + size_of::<u16>();
const RB_ISVSVN_START: usize = RB_ISVPRODID_END;
const RB_ISVSVN_END: usize = RB_ISVSVN_START + size_of::<u16>();
const RB_CONFIGSVN_START: usize = RB_ISVSVN_END;
const RB_CONFIGSVN_END: usize = RB_CONFIGSVN_START + size_of::<u16>();
const RB_RESERVED4_START: usize = RB_CONFIGSVN_END;
const RB_RESERVED4_END: usize = RB_RESERVED4_START + 42;
const RB_ISVFAMILYID_START: usize = RB_RESERVED4_END;
const RB_ISVFAMILYID_END: usize = RB_ISVFAMILYID_START + <FamilyId as IntelLayout>::X86_64_CSIZE;
const RB_REPORTDATA_START: usize = RB_ISVFAMILYID_END;
const RB_REPORTDATA_END: usize = RB_REPORTDATA_START + <ReportData as IntelLayout>::X86_64_CSIZE;

const REPORT_BODY_SIZE: usize = RB_REPORTDATA_END;
// const REPORT_SIZE: usize = 432; // taken from sgx_types

/// The data pertinant to a Report and Quote.
#[derive(Clone, Copy, Default)]
#[repr(transparent)]
pub struct ReportBody(sgx_report_body_t);

impl_sgx_wrapper_reqs! {
    ReportBody, sgx_report_body_t, REPORT_BODY_SIZE;
}

impl ReportBody {
    /// Retrieve the attributes of an enclave's report.
    pub fn attributes(&self) -> Attributes {
        self.0.attributes.into()
    }

    /// Retrieve a 64-byte ID representing the enclave XML configuration
    pub fn config_id(&self) -> ConfigId {
        self.0.config_id.into()
    }

    /// Retrieve the security version of the enclave's XML configuration
    pub fn config_security_version(&self) -> ConfigSecurityVersion {
        self.0.config_svn
    }

    /// Retrieve the security version of the CPU the report was generated
    /// on
    pub fn cpu_security_version(&self) -> CpuSecurityVersion {
        self.0.cpu_svn.into()
    }

    /// Retrieve the extended product ID, identifying the enclave software
    pub fn extended_product_id(&self) -> ExtendedProductId {
        self.0.isv_ext_prod_id.into()
    }

    /// Retrieve the product family ID, used to identify enclave software
    pub fn family_id(&self) -> FamilyId {
        self.0.isv_family_id.into()
    }

    /// Retrieve the enclave measurement
    pub fn mr_enclave(&self) -> MrEnclave {
        self.0.mr_enclave.into()
    }

    /// Retrieve whether the extended SSA frame feature was requested (source
    /// from the enclave XML)
    pub fn misc_select(&self) -> MiscSelect {
        self.0.misc_select
    }

    /// Retrieve the enclave signer measurement
    pub fn mr_signer(&self) -> MrSigner {
        self.0.mr_signer.into()
    }

    /// Retrieve the product ID of the enclave
    pub fn product_id(&self) -> ProductId {
        self.0.isv_prod_id
    }

    /// Retrieve the user data provided when the report was created
    pub fn report_data(&self) -> ReportData {
        self.0.report_data.into()
    }

    /// Retrieve the security version of the enclave
    pub fn security_version(&self) -> SecurityVersion {
        self.0.isv_svn
    }

    /// Verify the contents of a report body are acceptable based on the
    /// arguments
    pub fn verify(
        &self,
        allow_debug: bool,
        expected_measurements: &[Measurement],
        expected_product_id: ProductId,
        minimum_security_version: SecurityVersion,
        expected_data: &ReportDataMask,
    ) -> Result<(), ReportBodyVerifyError> {
        // Check debug
        if !allow_debug && (self.attributes().flags() & SGX_FLAGS_DEBUG != 0) {
            return Err(ReportBodyVerifyError::DebugNotAllowed);
        }

        // Check if we're even using the right product ID
        let product_id = self.product_id();
        if expected_product_id != product_id {
            return Err(ReportBodyVerifyError::ProductId(
                expected_product_id,
                product_id,
            ));
        }

        // Check if the security version is high enough
        let svn = self.security_version();
        if minimum_security_version > svn {
            return Err(ReportBodyVerifyError::SecurityVersion(
                minimum_security_version,
            ));
        }

        // Check mr_signer/mr_enclave against acceptable measurements.
        // Any match of expected mr_signers or mr_enclaves passes verification.
        let mr_signer = self.mr_signer();
        let mr_enclave = self.mr_enclave();
        if !expected_measurements
            .iter()
            .any(|m| m == &mr_signer || m == &mr_enclave)
        {
            return Err(ReportBodyVerifyError::MrMismatch(
                expected_measurements.to_vec(),
                mr_enclave,
                mr_signer,
            ));
        }

        // check report data
        if expected_data != &self.report_data() {
            return Err(ReportBodyVerifyError::DataMismatch);
        }

        Ok(())
    }
}

impl Debug for ReportBody {
    fn fmt(&self, formatter: &mut Formatter) -> FmtResult {
        write!(formatter, "ReportBody: {{ cpu_svn: {:?}, misc_select: {:?}, isv_ext_prod_id: {:?}, attributes: {:?}, mr_enclave: {:?}, mr_signer: {:?}, config_id: {:?}, isv_prod_id: {:?}, isv_svn: {:?}, config_svn: {:?}, isv_family_id: {:?}, report_data: {:?} }}",
        self.cpu_security_version(), self.misc_select(), self.extended_product_id(), self.attributes(), self.mr_enclave(), self.mr_signer(), self.config_id(), self.product_id(), self.security_version(), self.config_security_version(), self.family_id(), self.report_data())
    }
}

impl Hash for ReportBody {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.cpu_security_version().hash(state);
        self.misc_select().hash(state);
        self.extended_product_id().hash(state);
        self.attributes().hash(state);
        self.mr_enclave().hash(state);
        self.mr_signer().hash(state);
        self.config_id().hash(state);
        self.product_id().hash(state);
        self.security_version().hash(state);
        self.config_security_version().hash(state);
        self.family_id().hash(state);
    }
}

impl Ord for ReportBody {
    /// Create an arbitrary sort order for report body types
    ///
    /// We sort by Family ID, ProdID, Extended ProdID, SVN, MrSigner, MrEnclave,
    /// Attributes, Misc Select, ConfigId, ConfigSVN, CPU SVN, and
    /// ReportData, in that order
    fn cmp(&self, other: &Self) -> Ordering {
        match (&self.0.isv_family_id[..]).cmp(&other.0.isv_family_id[..]) {
            Ordering::Equal => match self.0.isv_prod_id.cmp(&other.0.isv_prod_id) {
                Ordering::Equal => match self.0.isv_ext_prod_id.cmp(&other.0.isv_ext_prod_id) {
                    Ordering::Equal => match self.0.isv_svn.cmp(&other.0.isv_svn) {
                        Ordering::Equal => match self.mr_signer().cmp(&other.mr_signer()) {
                            Ordering::Equal => match self.mr_enclave().cmp(&other.mr_enclave()) {
                                Ordering::Equal => match self.attributes().cmp(&other.attributes())
                                {
                                    Ordering::Equal => {
                                        match self.0.misc_select.cmp(&other.0.misc_select) {
                                            Ordering::Equal => {
                                                match self.config_id().cmp(&other.config_id()) {
                                                    Ordering::Equal => match self
                                                        .0
                                                        .config_svn
                                                        .cmp(&other.0.config_svn)
                                                    {
                                                        Ordering::Equal => match self
                                                            .cpu_security_version()
                                                            .cmp(&other.cpu_security_version())
                                                        {
                                                            Ordering::Equal => self
                                                                .report_data()
                                                                .cmp(&other.report_data()),
                                                            ordering => ordering,
                                                        },
                                                        ordering => ordering,
                                                    },
                                                    ordering => ordering,
                                                }
                                            }
                                            ordering => ordering,
                                        }
                                    }
                                    ordering => ordering,
                                },
                                ordering => ordering,
                            },
                            ordering => ordering,
                        },
                        ordering => ordering,
                    },
                    ordering => ordering,
                },
                ordering => ordering,
            },
            ordering => ordering,
        }
    }
}

impl PartialEq for ReportBody {
    fn eq(&self, other: &Self) -> bool {
        self.cpu_security_version() == other.cpu_security_version()
            && self.misc_select() == other.misc_select()
            && self.attributes() == other.attributes()
            && self.config_security_version() == other.config_security_version()
            && self.extended_product_id() == other.extended_product_id()
            && self.family_id() == other.family_id()
            && self.mr_enclave() == other.mr_enclave()
            && self.mr_signer() == other.mr_signer()
            && self.product_id() == other.product_id()
            && self.report_data() == other.report_data()
            && self.security_version() == other.security_version()
    }
}

impl SgxWrapperType<sgx_report_body_t> for ReportBody {
    fn write_ffi_bytes(src: &sgx_report_body_t, dest: &mut [u8]) -> Result<usize, EncodingError> {
        if dest.len() < REPORT_BODY_SIZE {
            return Err(EncodingError::InvalidOutputLength);
        }

        CpuSecurityVersion::write_ffi_bytes(
            &src.cpu_svn,
            &mut dest[RB_CPUSVN_START..RB_CPUSVN_END],
        )?;
        dest[RB_SELECT_START..RB_SELECT_END].copy_from_slice(&src.misc_select.to_le_bytes());
        ExtendedProductId::write_ffi_bytes(
            &src.isv_ext_prod_id,
            &mut dest[RB_EXTPRODID_START..RB_EXTPRODID_END],
        )?;
        Attributes::write_ffi_bytes(
            &src.attributes,
            &mut dest[RB_ATTRIBUTES_START..RB_ATTRIBUTES_END],
        )?;
        MrEnclave::write_ffi_bytes(
            &src.mr_enclave,
            &mut dest[RB_MRENCLAVE_START..RB_MRENCLAVE_END],
        )?;
        MrSigner::write_ffi_bytes(
            &src.mr_signer,
            &mut dest[RB_MRSIGNER_START..RB_MRSIGNER_END],
        )?;
        ConfigId::write_ffi_bytes(
            &src.config_id,
            &mut dest[RB_CONFIGID_START..RB_CONFIGID_END],
        )?;
        dest[RB_ISVPRODID_START..RB_ISVPRODID_END].copy_from_slice(&src.isv_prod_id.to_le_bytes());
        dest[RB_ISVSVN_START..RB_ISVSVN_END].copy_from_slice(&src.isv_svn.to_le_bytes());
        dest[RB_CONFIGSVN_START..RB_CONFIGSVN_END].copy_from_slice(&src.config_svn.to_le_bytes());
        FamilyId::write_ffi_bytes(
            &src.isv_family_id,
            &mut dest[RB_ISVFAMILYID_START..RB_ISVFAMILYID_END],
        )?;
        ReportData::write_ffi_bytes(
            &src.report_data,
            &mut dest[RB_REPORTDATA_START..RB_REPORTDATA_END],
        )?;
        Ok(REPORT_BODY_SIZE)
    }
}

impl<'src> TryFrom<&'src [u8]> for ReportBody {
    type Error = EncodingError;

    fn try_from(src: &[u8]) -> Result<Self, EncodingError> {
        if src.len() < <Self as IntelLayout>::X86_64_CSIZE {
            return Err(EncodingError::InvalidInputLength);
        }

        let mut reserved4 = [0u8; 42];
        reserved4[..].copy_from_slice(&src[RB_RESERVED4_START..RB_RESERVED4_END]);

        Ok(Self(sgx_report_body_t {
            cpu_svn: CpuSecurityVersion::try_from(&src[RB_CPUSVN_START..RB_CPUSVN_END])?.into(),
            misc_select: u32::from_le_bytes(
                (&src[RB_SELECT_START..RB_SELECT_END]).try_into().unwrap(),
            ),
            reserved1: (&src[RB_RESERVED1_START..RB_RESERVED1_END])
                .try_into()
                .map_err(|_e| EncodingError::InvalidInput)?,
            isv_ext_prod_id: ExtendedProductId::try_from(
                &src[RB_EXTPRODID_START..RB_EXTPRODID_END],
            )?
            .into(),
            attributes: Attributes::try_from(&src[RB_ATTRIBUTES_START..RB_ATTRIBUTES_END])?.into(),
            mr_enclave: MrEnclave::try_from(&src[RB_MRENCLAVE_START..RB_MRENCLAVE_END])?.into(),
            reserved2: (&src[RB_RESERVED2_START..RB_RESERVED2_END])
                .try_into()
                .map_err(|_e| EncodingError::InvalidInput)?,
            mr_signer: MrSigner::try_from(&src[RB_MRSIGNER_START..RB_MRSIGNER_END])?.into(),
            reserved3: (&src[RB_RESERVED3_START..RB_RESERVED3_END])
                .try_into()
                .map_err(|_e| EncodingError::InvalidInput)?,
            config_id: ConfigId::try_from(&src[RB_CONFIGID_START..RB_CONFIGID_END])?.into(),
            isv_prod_id: u16::from_le_bytes(
                (&src[RB_ISVPRODID_START..RB_ISVPRODID_END])
                    .try_into()
                    .unwrap(),
            ),
            isv_svn: u16::from_le_bytes((&src[RB_ISVSVN_START..RB_ISVSVN_END]).try_into().unwrap()),
            config_svn: u16::from_le_bytes(
                (&src[RB_CONFIGSVN_START..RB_CONFIGSVN_END])
                    .try_into()
                    .unwrap(),
            ),
            reserved4,
            isv_family_id: FamilyId::try_from(&src[RB_ISVFAMILYID_START..RB_ISVFAMILYID_END])?
                .into(),
            report_data: ReportData::try_from(&src[RB_REPORTDATA_START..RB_REPORTDATA_END])?.into(),
        }))
    }
}

impl TryFrom<Vec<u8>> for ReportBody {
    type Error = EncodingError;

    fn try_from(src: Vec<u8>) -> Result<Self, Self::Error> {
        Self::try_from(&src[..])
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use core::mem::size_of;
    use mc_sgx_types::{sgx_attributes_t, sgx_cpu_svn_t, sgx_measurement_t, sgx_report_data_t};
    use mc_util_serial::*;

    const REPORT_BODY_SRC: sgx_report_body_t = sgx_report_body_t {
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
                17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37,
                38, 39, 40, 41, 42, 43, 43, 44, 45, 46, 47,
            ],
        },
        reserved2: [0u8; 32],
        mr_signer: sgx_measurement_t {
            m: [
                48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64, 65, 66, 67, 68,
                69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79,
            ],
        },
        reserved3: [0u8; 32],
        config_id: [
            80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 91, 92, 93, 94, 95, 96, 97, 98, 99, 100,
            101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 112, 113, 114, 115, 116, 117,
            118, 119, 120, 121, 122, 123, 124, 125, 126, 127, 128, 129, 130, 131, 132, 133, 134,
            135, 136, 137, 138, 139, 140, 141, 142, 143,
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
    };

    #[test]
    #[allow(clippy::cognitive_complexity)]
    fn test_ord() {
        let body1: ReportBody = REPORT_BODY_SRC.clone().into();
        let mut body2 = body1;

        let orig_value = body2.0.cpu_svn.svn[0];
        body2.0.cpu_svn.svn[0] = 255;
        assert!(body1 < body2);
        body2.0.cpu_svn.svn[0] = orig_value;
        assert_eq!(body1, body2);

        let orig_value = body2.0.misc_select;
        body2.0.misc_select = 255;
        assert!(body1 < body2);
        body2.0.misc_select = orig_value;
        assert_eq!(body1, body2);

        let orig_value = body2.0.isv_ext_prod_id[0];
        body2.0.isv_ext_prod_id[0] = 255;
        assert!(body1 < body2);
        body2.0.isv_ext_prod_id[0] = orig_value;
        assert_eq!(body1, body2);

        let orig_value = body2.0.isv_ext_prod_id[0];
        body2.0.isv_ext_prod_id[0] = 255;
        assert!(body1 < body2);
        body2.0.isv_ext_prod_id[0] = orig_value;
        assert_eq!(body1, body2);

        let orig_value = body2.0.attributes.flags;
        body2.0.attributes.flags += 1;
        assert!(body1 < body2);
        body2.0.attributes.flags = orig_value;
        assert_eq!(body1, body2);

        let orig_value = body2.0.attributes.xfrm;
        body2.0.attributes.xfrm += 1;
        assert!(body1 < body2);
        body2.0.attributes.xfrm = orig_value;
        assert_eq!(body1, body2);

        let orig_value = body2.0.mr_enclave.m[0];
        body2.0.mr_enclave.m[0] = 255;
        assert!(body1 < body2);
        body2.0.mr_enclave.m[0] = orig_value;
        assert_eq!(body1, body2);

        let orig_value = body2.0.mr_signer.m[0];
        body2.0.mr_signer.m[0] = 255;
        assert!(body1 < body2);
        body2.0.mr_signer.m[0] = orig_value;
        assert_eq!(body1, body2);

        let orig_value = body2.0.config_id[0];
        body2.0.config_id[0] = 255;
        assert!(body1 < body2);
        body2.0.config_id[0] = orig_value;
        assert_eq!(body1, body2);

        let orig_value = body2.0.isv_prod_id;
        body2.0.isv_prod_id = 255;
        assert!(body1 < body2);
        body2.0.isv_prod_id = orig_value;
        assert_eq!(body1, body2);

        let orig_value = body2.0.isv_svn;
        body2.0.isv_svn = 255;
        assert!(body1 < body2);
        body2.0.isv_svn = orig_value;
        assert_eq!(body1, body2);

        let orig_value = body2.0.isv_family_id[0];
        body2.0.isv_family_id[0] = 255;
        assert!(body1 < body2);
        body2.0.isv_family_id[0] = orig_value;
        assert_eq!(body1, body2);

        let orig_value = body2.0.report_data.d[0];
        body2.0.report_data.d[0] = 255;
        assert!(body1 < body2);
        body2.0.report_data.d[0] = orig_value;
        assert_eq!(body1, body2);
    }

    #[test]
    fn test_serde() {
        assert_eq!(REPORT_BODY_SIZE, size_of::<sgx_report_body_t>());

        let body: ReportBody = REPORT_BODY_SRC.clone().into();
        let serialized = serialize(&body).expect("Error serializing report.");
        let body2: ReportBody = deserialize(&serialized).expect("Error deserializing report");
        assert_eq!(body, body2);
        let dest: sgx_report_body_t = body2.into();
        assert_eq!(&REPORT_BODY_SRC.report_data.d[..], &dest.report_data.d[..]);
    }
}
