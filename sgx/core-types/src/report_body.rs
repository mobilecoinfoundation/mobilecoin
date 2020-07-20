// Copyright (c) 2018-2020 MobileCoin Inc.

//! A wrapper for sgx_report_body_t

use crate::{
    _macros::FfiWrapper,
    attributes::{Attributes, ATTRIBUTES_SIZE},
    config_id::{ConfigId, CONFIG_ID_SIZE},
    cpu_svn::{CpuSecurityVersion, CPU_SECURITY_VERSION_SIZE},
    ext_prod_id::{ExtendedProductId, EXTENDED_PRODUCT_ID_SIZE},
    family_id::{FamilyId, FAMILY_ID_SIZE},
    impl_ffi_wrapper_base, impl_hex_base64_with_repr_bytes,
    measurement::{MrEnclave, MrSigner, MRENCLAVE_SIZE, MRSIGNER_SIZE},
    report_data::{ReportData, REPORT_DATA_SIZE},
    ConfigSecurityVersion, MiscSelect, ProductId, SecurityVersion, CONFIG_SECURITY_VERSION_SIZE,
    MISC_SELECT_SIZE, PRODUCT_ID_SIZE, SECURITY_VERSION_SIZE,
};
use core::{
    cmp::Ordering,
    convert::{TryFrom, TryInto},
    fmt::{Debug, Display, Formatter, Result as FmtResult},
    hash::{Hash, Hasher},
};
use mc_sgx_core_types_sys::{
    sgx_report_body_t, SGX_REPORT_BODY_RESERVED1_BYTES, SGX_REPORT_BODY_RESERVED2_BYTES,
    SGX_REPORT_BODY_RESERVED3_BYTES, SGX_REPORT_BODY_RESERVED4_BYTES,
};
use mc_util_encodings::Error as EncodingError;
#[cfg(feature = "use_prost")]
use mc_util_repr_bytes::derive_prost_message_from_repr_bytes;
#[cfg(feature = "use_serde")]
use mc_util_repr_bytes::derive_serde_from_repr_bytes;
use mc_util_repr_bytes::{derive_into_vec_from_repr_bytes, typenum::U384, GenericArray, ReprBytes};

// Offsets of various fields in a sgx_report_body_t with x86_64 layout
const CPU_SVN_START: usize = 0;
const CPU_SVN_END: usize = CPU_SVN_START + CPU_SECURITY_VERSION_SIZE;
const MISC_SELECT_START: usize = CPU_SVN_END;
const MISC_SELECT_END: usize = MISC_SELECT_START + MISC_SELECT_SIZE;
const RESERVED1_START: usize = MISC_SELECT_END;
const RESERVED1_END: usize = RESERVED1_START + SGX_REPORT_BODY_RESERVED1_BYTES;
const EXT_PROD_ID_START: usize = RESERVED1_END;
const EXT_PROD_ID_END: usize = EXT_PROD_ID_START + EXTENDED_PRODUCT_ID_SIZE;
const ATTRIBUTES_START: usize = EXT_PROD_ID_END;
const ATTRIBUTES_END: usize = ATTRIBUTES_START + ATTRIBUTES_SIZE;
const MRENCLAVE_START: usize = ATTRIBUTES_END;
const MRENCLAVE_END: usize = MRENCLAVE_START + MRENCLAVE_SIZE;
const RESERVED2_START: usize = MRENCLAVE_END;
const RESERVED2_END: usize = RESERVED2_START + SGX_REPORT_BODY_RESERVED2_BYTES;
const MRSIGNER_START: usize = RESERVED2_END;
const MRSIGNER_END: usize = MRSIGNER_START + MRSIGNER_SIZE;
const RESERVED3_START: usize = MRSIGNER_END;
const RESERVED3_END: usize = RESERVED3_START + SGX_REPORT_BODY_RESERVED3_BYTES;
const CONFIG_ID_START: usize = RESERVED3_END;
const CONFIG_ID_END: usize = CONFIG_ID_START + CONFIG_ID_SIZE;
const ISV_PROD_ID_START: usize = CONFIG_ID_END;
const ISV_PROD_ID_END: usize = ISV_PROD_ID_START + PRODUCT_ID_SIZE;
const ISV_SVN_START: usize = ISV_PROD_ID_END;
const ISV_SVN_END: usize = ISV_SVN_START + SECURITY_VERSION_SIZE;
const CONFIG_SVN_START: usize = ISV_SVN_END;
const CONFIG_SVN_END: usize = CONFIG_SVN_START + CONFIG_SECURITY_VERSION_SIZE;
const RESERVED4_START: usize = CONFIG_SVN_END;
const RESERVED4_END: usize = RESERVED4_START + SGX_REPORT_BODY_RESERVED4_BYTES;
const FAMILY_ID_START: usize = RESERVED4_END;
const FAMILY_ID_END: usize = FAMILY_ID_START + FAMILY_ID_SIZE;
const REPORT_DATA_START: usize = FAMILY_ID_END;
const REPORT_DATA_END: usize = REPORT_DATA_START + REPORT_DATA_SIZE;

/// The size of a [ReportBody]'s x64 representation, in bytes.
pub const REPORT_BODY_SIZE: usize = REPORT_DATA_END;

/// The data pertinent to a Report and Quote.
#[derive(Default)]
#[repr(transparent)]
pub struct ReportBody(sgx_report_body_t);

impl_ffi_wrapper_base! {
    ReportBody, sgx_report_body_t;
}

impl_hex_base64_with_repr_bytes!(ReportBody);
derive_into_vec_from_repr_bytes!(ReportBody);

#[cfg(feature = "use_prost")]
derive_prost_message_from_repr_bytes!(ReportBody);

#[cfg(feature = "use_serde")]
derive_serde_from_repr_bytes!(ReportBody);

impl ReportBody {
    /// Retrieve the attributes of an enclave's report.
    pub fn attributes(&self) -> Attributes {
        Attributes::try_from(&self.0.attributes).expect("Invalid attributes found")
    }

    /// Retrieve a 64-byte ID representing the enclave XML configuration
    pub fn config_id(&self) -> ConfigId {
        ConfigId::from(&self.0.config_id)
    }

    /// Retrieve the security version of the enclave's XML configuration
    pub fn config_security_version(&self) -> ConfigSecurityVersion {
        self.0.config_svn
    }

    /// Retrieve the security version of the CPU the report was generated
    /// on
    pub fn cpu_security_version(&self) -> CpuSecurityVersion {
        CpuSecurityVersion::from(&self.0.cpu_svn)
    }

    /// Retrieve the extended product ID, identifying the enclave software
    pub fn extended_product_id(&self) -> ExtendedProductId {
        ExtendedProductId::from(&self.0.isv_ext_prod_id)
    }

    /// Retrieve the product family ID, used to identify enclave software
    pub fn family_id(&self) -> FamilyId {
        FamilyId::from(&self.0.isv_family_id)
    }

    /// Retrieve the enclave measurement
    pub fn mr_enclave(&self) -> MrEnclave {
        MrEnclave::from(&self.0.mr_enclave)
    }

    /// Retrieve whether the extended SSA frame feature was requested (source
    /// from the enclave XML)
    pub fn misc_select(&self) -> MiscSelect {
        self.0.misc_select
    }

    /// Retrieve the enclave signer measurement
    pub fn mr_signer(&self) -> MrSigner {
        MrSigner::from(&self.0.mr_signer)
    }

    /// Retrieve the product ID of the enclave
    pub fn product_id(&self) -> ProductId {
        self.0.isv_prod_id
    }

    /// Retrieve the user data provided when the report was created
    pub fn report_data(&self) -> ReportData {
        ReportData::from(&self.0.report_data)
    }

    /// Retrieve the security version of the enclave
    pub fn security_version(&self) -> SecurityVersion {
        self.0.isv_svn
    }
}

impl Debug for ReportBody {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        write!(f, "ReportBody: {{ cpu_svn: {:?}, misc_select: {:?}, isv_ext_prod_id: {:?}, attributes: {:?}, mr_enclave: {:?}, mr_signer: {:?}, config_id: {:?}, isv_prod_id: {:?}, isv_svn: {:?}, config_svn: {:?}, isv_family_id: {:?}, report_data: {:?} }}",
        self.cpu_security_version(), self.misc_select(), self.extended_product_id(), self.attributes(), self.mr_enclave(), self.mr_signer(), self.config_id(), self.product_id(), self.security_version(), self.config_security_version(), self.family_id(), self.report_data())
    }
}

impl Display for ReportBody {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        write!(
            f,
            "Report for enclave {}, signed by {}, with product ID {} and version {}",
            self.mr_enclave(),
            self.mr_signer(),
            self.product_id(),
            self.security_version()
        )
    }
}

impl FfiWrapper<sgx_report_body_t> for ReportBody {}

impl TryFrom<&sgx_report_body_t> for ReportBody {
    type Error = EncodingError;

    fn try_from(src: &sgx_report_body_t) -> Result<Self, Self::Error> {
        let attributes = Attributes::try_from(&src.attributes)?.into();

        let mut reserved1 = [0u8; SGX_REPORT_BODY_RESERVED1_BYTES];
        reserved1[..].copy_from_slice(&src.reserved1[..]);

        let mut reserved2 = [0u8; SGX_REPORT_BODY_RESERVED2_BYTES];
        reserved2[..].copy_from_slice(&src.reserved2[..]);

        let mut reserved3 = [0u8; SGX_REPORT_BODY_RESERVED3_BYTES];
        reserved3[..].copy_from_slice(&src.reserved3[..]);

        let mut reserved4 = [0u8; SGX_REPORT_BODY_RESERVED4_BYTES];
        reserved4[..].copy_from_slice(&src.reserved4[..]);

        Ok(Self(sgx_report_body_t {
            cpu_svn: CpuSecurityVersion::from(&src.cpu_svn).into(),
            misc_select: src.misc_select,
            reserved1,
            isv_ext_prod_id: ExtendedProductId::from(&src.isv_ext_prod_id).into(),
            attributes,
            mr_enclave: MrEnclave::from(&src.mr_enclave).into(),
            reserved2,
            mr_signer: MrSigner::from(&src.mr_signer).into(),
            reserved3,
            config_id: ConfigId::from(&src.config_id).into(),
            isv_prod_id: src.isv_prod_id,
            isv_svn: src.isv_svn,
            config_svn: src.config_svn,
            reserved4,
            isv_family_id: FamilyId::from(&src.isv_family_id).into(),
            report_data: ReportData::from(&src.report_data).into(),
        }))
    }
}

impl Hash for ReportBody {
    fn hash<H: Hasher>(&self, state: &mut H) {
        "ReportBody".hash(state);
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
    /// We sort by Family ID, ProdID, Extended ProdID, SVN, MrSigner, MrEnclave, Attributes,
    /// Misc Select, ConfigId, ConfigSVN, CPU SVN, and ReportData, in that order
    fn cmp(&self, other: &Self) -> Ordering {
        fn to_tuple(
            report_body: &ReportBody,
        ) -> (
            FamilyId,
            ProductId,
            SecurityVersion,
            ExtendedProductId,
            MrSigner,
            MrEnclave,
            Attributes,
            MiscSelect,
            ConfigId,
            ConfigSecurityVersion,
            CpuSecurityVersion,
            ReportData,
        ) {
            (
                report_body.family_id(),
                report_body.product_id(),
                report_body.security_version(),
                report_body.extended_product_id(),
                report_body.mr_signer(),
                report_body.mr_enclave(),
                report_body.attributes(),
                report_body.misc_select(),
                report_body.config_id(),
                report_body.config_security_version(),
                report_body.cpu_security_version(),
                report_body.report_data(),
            )
        }

        to_tuple(self).cmp(&to_tuple(other))
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

impl PartialOrd for ReportBody {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl ReprBytes for ReportBody {
    type Size = U384;
    type Error = EncodingError;

    fn from_bytes(src: &GenericArray<u8, Self::Size>) -> Result<Self, Self::Error> {
        Self::try_from(src.as_slice())
    }

    fn to_bytes(&self) -> GenericArray<u8, Self::Size> {
        let mut retval = GenericArray::default();

        retval[CPU_SVN_START..CPU_SVN_END].copy_from_slice(self.cpu_security_version().as_ref());
        retval[MISC_SELECT_START..MISC_SELECT_END]
            .copy_from_slice(&self.misc_select().to_le_bytes());
        retval[EXT_PROD_ID_START..EXT_PROD_ID_END]
            .copy_from_slice(self.extended_product_id().as_ref());
        retval[ATTRIBUTES_START..ATTRIBUTES_END].copy_from_slice(&self.attributes().to_bytes());
        retval[MRENCLAVE_START..MRENCLAVE_END].copy_from_slice(self.mr_enclave().as_ref());
        retval[MRSIGNER_START..MRSIGNER_END].copy_from_slice(self.mr_signer().as_ref());
        retval[CONFIG_ID_START..CONFIG_ID_END].copy_from_slice(self.config_id().as_ref());
        retval[ISV_PROD_ID_START..ISV_PROD_ID_END]
            .copy_from_slice(&self.product_id().to_le_bytes());
        retval[ISV_SVN_START..ISV_SVN_END].copy_from_slice(&self.security_version().to_le_bytes());
        retval[CONFIG_SVN_START..CONFIG_SVN_END]
            .copy_from_slice(&self.config_security_version().to_le_bytes());
        retval[FAMILY_ID_START..FAMILY_ID_END].copy_from_slice(self.family_id().as_ref());
        retval[REPORT_DATA_START..REPORT_DATA_END].copy_from_slice(self.report_data().as_ref());

        retval
    }
}

impl TryFrom<&[u8]> for ReportBody {
    type Error = EncodingError;

    fn try_from(src: &[u8]) -> Result<Self, Self::Error> {
        if src.len() < REPORT_BODY_SIZE {
            return Err(EncodingError::InvalidInputLength);
        }

        let reserved1 = [0u8; SGX_REPORT_BODY_RESERVED1_BYTES];
        if src[RESERVED1_START..RESERVED1_END] != reserved1[..] {
            return Err(EncodingError::InvalidInput);
        }

        let reserved2 = [0u8; SGX_REPORT_BODY_RESERVED2_BYTES];
        if src[RESERVED2_START..RESERVED2_END] != reserved2[..] {
            return Err(EncodingError::InvalidInput);
        }

        let reserved3 = [0u8; SGX_REPORT_BODY_RESERVED3_BYTES];
        if src[RESERVED3_START..RESERVED3_END] != reserved3[..] {
            return Err(EncodingError::InvalidInput);
        }

        let reserved4 = [0u8; SGX_REPORT_BODY_RESERVED4_BYTES];
        if src[RESERVED4_START..RESERVED4_END] != reserved4[..] {
            return Err(EncodingError::InvalidInput);
        }

        Ok(Self(sgx_report_body_t {
            cpu_svn: CpuSecurityVersion::try_from(&src[CPU_SVN_START..CPU_SVN_END])?.into(),
            misc_select: u32::from_le_bytes(
                (&src[MISC_SELECT_START..MISC_SELECT_END])
                    .try_into()
                    .expect("Invalid misc_select size"),
            ),
            reserved1,
            isv_ext_prod_id: ExtendedProductId::try_from(&src[EXT_PROD_ID_START..EXT_PROD_ID_END])?
                .into(),
            attributes: Attributes::try_from(&src[ATTRIBUTES_START..ATTRIBUTES_END])?.into(),
            mr_enclave: MrEnclave::try_from(&src[MRENCLAVE_START..MRENCLAVE_END])?.into(),
            reserved2,
            mr_signer: MrSigner::try_from(&src[MRSIGNER_START..MRSIGNER_END])?.into(),
            reserved3,
            config_id: ConfigId::try_from(&src[CONFIG_ID_START..CONFIG_ID_END])?.into(),
            isv_prod_id: u16::from_le_bytes(
                (&src[ISV_PROD_ID_START..ISV_PROD_ID_END])
                    .try_into()
                    .expect("Invalid isv_prod_id size"),
            ),
            isv_svn: u16::from_le_bytes((&src[ISV_SVN_START..ISV_SVN_END]).try_into().unwrap()),
            config_svn: u16::from_le_bytes(
                (&src[CONFIG_SVN_START..CONFIG_SVN_END]).try_into().unwrap(),
            ),
            reserved4,
            isv_family_id: FamilyId::try_from(&src[FAMILY_ID_START..FAMILY_ID_END])?.into(),
            report_data: ReportData::try_from(&src[REPORT_DATA_START..REPORT_DATA_END])?.into(),
        }))
    }
}

#[cfg(test)]
mod test {
    use super::*;
    #[cfg(feature = "use_serde")]
    use bincode::{deserialize, serialize};
    use core::mem::size_of;
    use mc_sgx_core_types_sys::{
        sgx_attributes_t, sgx_cpu_svn_t, sgx_measurement_t, sgx_report_data_t,
    };

    const REPORT_BODY_SRC: sgx_report_body_t = sgx_report_body_t {
        cpu_svn: sgx_cpu_svn_t {
            svn: [1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16],
        },
        misc_select: 17,
        reserved1: [0u8; 12],
        isv_ext_prod_id: [1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16],
        attributes: sgx_attributes_t {
            flags: 0x0000_0000_0000_0001 | 0x0000_0000_0000_0004 | 0x0000_0000_0000_0080,
            xfrm: 0x0000_0000_0000_0006,
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
        let body1 = ReportBody::try_from(&REPORT_BODY_SRC).expect("Could not read report");
        let mut body2 = body1.clone();

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

    #[cfg(feature = "use_serde")]
    #[test]
    fn test_serde() {
        assert_eq!(REPORT_BODY_SIZE, size_of::<sgx_report_body_t>());

        let body = ReportBody::try_from(&REPORT_BODY_SRC).expect("Could not read report");
        let serialized = serialize(&body).expect("Error serializing report");
        let body2: ReportBody = deserialize(&serialized).expect("Error deserializing report");
        assert_eq!(body, body2);
        let dest: sgx_report_body_t = body2.into();
        assert_eq!(&REPORT_BODY_SRC.report_data.d[..], &dest.report_data.d[..]);
    }
}
