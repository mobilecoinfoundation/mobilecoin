// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Verifiers which operate on the [`ReportBody`](::mc_attest_core::ReportBody)
//! data structure.

use crate::{
    macros::{impl_kind_from_inner, impl_kind_from_verifier},
    Verify,
};
use mc_attest_core::{
    Attributes, ConfigId, ConfigSvn, CpuSvn, ExtendedProductId, FamilyId, IsvProductId, IsvSvn,
    MiscellaneousSelect, ReportBody, ReportDataMask,
};
use mc_sgx_core_types::AttributeFlags;
use serde::{Deserialize, Serialize};

/// An enumeration of known report body verifier types.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub enum Kind {
    /// Verify the attributes matches the one specified.
    Attributes(AttributesVerifier),
    /// Verify the config ID matches the one specified.
    ConfigId(ConfigIdVerifier),
    /// Verify the config version is at least the one specified.
    ConfigVersion(ConfigVersionVerifier),
    /// Verify the CPU version is at least the one specified.
    CpuVersion(CpuVersionVerifier),
    /// Verify the enclave is not running in debug mode.
    Debug(DebugVerifier),
    /// Verify whether the data matches.
    Data(DataVerifier),
    /// Verify the extended product ID matches the one specified.
    ExtendedProductId(ExtendedProductIdVerifier),
    /// Verify the family ID matches the one specified
    FamilyId(FamilyIdVerifier),
    /// Verify the misc select value matches the one specified.
    MiscSelect(MiscSelectVerifier),
    /// Verify the product ID matches the one specified.
    ProductId(ProductIdVerifier),
    /// Verify the version is at least as new as the one specified.
    Version(VersionVerifier),
}

impl_kind_from_inner! {
    AttributesVerifier, Attributes, Attributes;
    ConfigIdVerifier, ConfigId, ConfigId;
    CpuVersionVerifier, CpuVersion, CpuSvn;
    DataVerifier, Data, ReportDataMask;
    ExtendedProductIdVerifier, ExtendedProductId, ExtendedProductId;
    FamilyIdVerifier, FamilyId, FamilyId;
}

// FIXME: Type aliases should be removed so this can be simplified
impl_kind_from_verifier! {
    ConfigVersionVerifier, ConfigVersion, ConfigSvn;
    DebugVerifier, Debug, bool;
    MiscSelectVerifier, MiscSelect, MiscellaneousSelect;
    ProductIdVerifier, ProductId, IsvProductId;
    VersionVerifier, Version, IsvSvn;
}

impl Verify<ReportBody> for Kind {
    fn verify(&self, report_body: &ReportBody) -> bool {
        match self {
            Kind::Attributes(v) => v.verify(report_body),
            Kind::ConfigId(v) => v.verify(report_body),
            Kind::ConfigVersion(v) => v.verify(report_body),
            Kind::CpuVersion(v) => v.verify(report_body),
            Kind::Debug(v) => v.verify(report_body),
            Kind::Data(v) => v.verify(report_body),
            Kind::ExtendedProductId(v) => v.verify(report_body),
            Kind::FamilyId(v) => v.verify(report_body),
            Kind::MiscSelect(v) => v.verify(report_body),
            Kind::ProductId(v) => v.verify(report_body),
            Kind::Version(v) => v.verify(report_body),
        }
    }
}

/// A [`Verify<ReportBody>`] implementation that will check if the enclave flags
/// match the given attributes.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct AttributesVerifier(Attributes);

impl Verify<ReportBody> for AttributesVerifier {
    fn verify(&self, report_body: &ReportBody) -> bool {
        self.0 == report_body.attributes()
    }
}

/// A [`Verify<ReportBody>`] implementation that will check if the enclave
/// configuration ID matches the given value
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct ConfigIdVerifier(ConfigId);

impl Verify<ReportBody> for ConfigIdVerifier {
    fn verify(&self, report_body: &ReportBody) -> bool {
        self.0 == report_body.config_id()
    }
}

/// A [`Verify<ReportBody>`] implementation that will check if the enclave
/// configuration version is at least the version specified.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct ConfigVersionVerifier(ConfigSvn);

impl Verify<ReportBody> for ConfigVersionVerifier {
    fn verify(&self, report_body: &ReportBody) -> bool {
        self.0.as_ref() <= report_body.config_security_version().as_ref()
    }
}

/// A [`Verify<ReportBody>`] implementation that will check if the cpu version
/// is at least the version specified.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct CpuVersionVerifier(CpuSvn);

impl Verify<ReportBody> for CpuVersionVerifier {
    fn verify(&self, report_body: &ReportBody) -> bool {
        self.0 <= report_body.cpu_security_version()
    }
}

/// A [`Verify<ReportBody>`] implementation that will check if the enclave in
/// question is allowed to run in debug mode.
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub struct DebugVerifier(bool);

impl Verify<ReportBody> for DebugVerifier {
    fn verify(&self, report_body: &ReportBody) -> bool {
        self.0
            || (Attributes::default().set_flags(AttributeFlags::DEBUG) & report_body.attributes()
                == Attributes::default())
    }
}

/// A [`Verify<ReportBody>`] implementation that will check if the enclave's
/// report data matches the mask given.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct DataVerifier(ReportDataMask);

impl Verify<ReportBody> for DataVerifier {
    fn verify(&self, report_body: &ReportBody) -> bool {
        self.0 == report_body.report_data()
    }
}

/// A [`Verify<ReportBody>`] implementation that will check if the enclave's
/// extended product ID matches the one given.
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub struct ExtendedProductIdVerifier(ExtendedProductId);

impl Verify<ReportBody> for ExtendedProductIdVerifier {
    fn verify(&self, report_body: &ReportBody) -> bool {
        self.0 == report_body.extended_product_id()
    }
}

/// A [`Verify<ReportBody>`] implementation that will check if the enclave's
/// family ID matches the one given.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct FamilyIdVerifier(FamilyId);

impl Verify<ReportBody> for FamilyIdVerifier {
    fn verify(&self, report_body: &ReportBody) -> bool {
        self.0 == report_body.family_id()
    }
}

/// A [`Verify<ReportBody>`] implementation that will check if the enclave's
/// misc select value matches the one given.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct MiscSelectVerifier(MiscellaneousSelect);

impl Verify<ReportBody> for MiscSelectVerifier {
    fn verify(&self, report_body: &ReportBody) -> bool {
        self.0 == report_body.misc_select()
    }
}

/// A [`Verify<ReportBody>`] implementation that will check if the enclave's
/// product ID matches the one given.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct ProductIdVerifier(IsvProductId);

impl Verify<ReportBody> for ProductIdVerifier {
    fn verify(&self, report_body: &ReportBody) -> bool {
        self.0 == report_body.product_id()
    }
}

/// A [`Verify<ReportBody>`] implementation that will check if the enclave's
/// security version is at least the one given.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct VersionVerifier(IsvSvn);

impl Verify<ReportBody> for VersionVerifier {
    fn verify(&self, report_body: &ReportBody) -> bool {
        self.0.as_ref() <= report_body.security_version().as_ref()
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use mc_sgx_types::{
        sgx_attributes_t, sgx_cpu_svn_t, sgx_measurement_t, sgx_report_body_t, sgx_report_data_t,
        SGX_FLAGS_DEBUG,
    };

    const ONES: [u8; 64] = [0xffu8; 64];
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

    /// When the report contains the attributes we want
    #[test]
    fn attributes_success() {
        let report_body = ReportBody::from(&REPORT_BODY_SRC);
        let verifier = Kind::from(Attributes::from(REPORT_BODY_SRC.attributes));

        assert!(verifier.verify(&report_body));
    }

    /// When the report contains attributes we don't want
    #[test]
    fn attributes_fail() {
        let report_body = ReportBody::from(&REPORT_BODY_SRC);
        let mut attributes = REPORT_BODY_SRC.attributes;
        attributes.flags = 0;
        let verifier = Kind::from(Attributes::from(attributes));

        assert!(!verifier.verify(&report_body));
    }

    /// When the report contains the config ID we want
    #[test]
    fn config_id_success() {
        let report_body = ReportBody::from(&REPORT_BODY_SRC);
        let verifier = Kind::from(ConfigId::from(REPORT_BODY_SRC.config_id));

        assert!(verifier.verify(&report_body));
    }

    /// When the report contains a config ID we don't want
    #[test]
    fn config_id_fail() {
        let report_body = ReportBody::from(&REPORT_BODY_SRC);
        let mut config_id = REPORT_BODY_SRC.config_id;
        config_id[0] = 0;
        let verifier = Kind::from(ConfigId::from(config_id));

        assert!(!verifier.verify(&report_body));
    }

    /// When the report contains exactly the config version we want
    #[test]
    fn config_version_eq_pass() {
        let report_body = ReportBody::from(&REPORT_BODY_SRC);
        let verifier = Kind::from(ConfigVersionVerifier::from(ConfigSvn::from(
            REPORT_BODY_SRC.config_svn,
        )));

        assert!(verifier.verify(&report_body));
    }

    /// When the report contains a newer config version than we want (pass)
    #[test]
    fn config_version_newer_pass() {
        let report_body = ReportBody::from(&REPORT_BODY_SRC);
        let verifier = Kind::from(ConfigVersionVerifier::from(ConfigSvn::from(
            REPORT_BODY_SRC.config_svn - 1,
        )));

        assert!(verifier.verify(&report_body));
    }

    /// When the report contains an older config version than we want
    #[test]
    fn config_version_older_fail() {
        let report_body = ReportBody::from(&REPORT_BODY_SRC);
        let verifier = Kind::from(ConfigVersionVerifier::from(ConfigSvn::from(
            REPORT_BODY_SRC.config_svn + 1,
        )));

        assert!(!verifier.verify(&report_body));
    }

    /// When the report contains the CPU version we want
    #[test]
    fn cpu_svn_eq_pass() {
        let report_body = ReportBody::from(&REPORT_BODY_SRC);
        let verifier = Kind::from(CpuSvn::from(REPORT_BODY_SRC.cpu_svn));

        assert!(verifier.verify(&report_body));
    }

    /// When the report contains a CPU version newer than what we want
    #[test]
    fn cpu_svn_newer_pass() {
        let report_body = ReportBody::from(&REPORT_BODY_SRC);
        let mut cpu_svn = REPORT_BODY_SRC.cpu_svn;
        cpu_svn.svn[0] = 0;
        let verifier = Kind::from(CpuSvn::from(cpu_svn));

        assert!(verifier.verify(&report_body));
    }

    /// When the report contains a CPU version older than what we want
    #[test]
    fn cpu_svn_older_fail() {
        let report_body = ReportBody::from(&REPORT_BODY_SRC);
        let mut cpu_svn = REPORT_BODY_SRC.cpu_svn;
        cpu_svn.svn[0] = 0xff;
        let verifier = Kind::from(CpuSvn::from(cpu_svn));

        assert!(!verifier.verify(&report_body));
    }

    /// Allow debug means debug and non-debug both succeed
    #[test]
    fn debug_success() {
        let report_body = ReportBody::from(&REPORT_BODY_SRC);
        let verifier = Kind::from(DebugVerifier::from(true));

        assert!(verifier.verify(&report_body));
    }

    /// Allow debug off means only non-debug enclaves succeed
    #[test]
    fn no_debug_success() {
        let report_body = ReportBody::from(&REPORT_BODY_SRC);
        let verifier = Kind::from(DebugVerifier::from(false));

        assert!(verifier.verify(&report_body));
    }

    /// Allow debug off means debug enclaves fail
    #[test]
    fn no_debug_fail() {
        let mut report_body = REPORT_BODY_SRC;
        report_body.attributes.flags |= SGX_FLAGS_DEBUG;
        let report_body = ReportBody::from(report_body);
        let verifier = Kind::from(DebugVerifier::from(false));

        assert!(!verifier.verify(&report_body));
    }

    /// When the report contains the report data we expect
    #[test]
    fn data_success() {
        let report_body = ReportBody::from(&REPORT_BODY_SRC);
        let verifier = Kind::from(
            ReportDataMask::new_with_mask(&REPORT_BODY_SRC.report_data.d, &ONES[..])
                .expect("Could not create report data mask"),
        );

        assert!(verifier.verify(&report_body));
    }

    /// When the report contains report data we don't want
    #[test]
    fn data_fail() {
        let report_body = ReportBody::from(&REPORT_BODY_SRC);
        let mut data = REPORT_BODY_SRC.report_data.d;
        data[0] = 0;
        let verifier = Kind::from(
            ReportDataMask::new_with_mask(&data, &ONES[..])
                .expect("Could not create report data mask"),
        );

        assert!(!verifier.verify(&report_body));
    }

    /// When the report contains the extended product ID we want
    #[test]
    fn ext_prod_id_success() {
        let report_body = ReportBody::from(&REPORT_BODY_SRC);
        let verifier = Kind::from(ExtendedProductId::from(REPORT_BODY_SRC.isv_ext_prod_id));

        assert!(verifier.verify(&report_body));
    }

    /// When the report contains an extended product ID we don't want
    #[test]
    fn ext_prod_id_fail() {
        let report_body = ReportBody::from(&REPORT_BODY_SRC);
        let mut ext_prod_id = REPORT_BODY_SRC.isv_ext_prod_id;
        ext_prod_id[0] = 0;
        let verifier = Kind::from(ExtendedProductId::from(ext_prod_id));

        assert!(!verifier.verify(&report_body));
    }

    /// When the report contains the family ID we want
    #[test]
    fn family_id_success() {
        let report_body = ReportBody::from(&REPORT_BODY_SRC);
        let verifier = Kind::from(FamilyId::from(REPORT_BODY_SRC.isv_family_id));

        assert!(verifier.verify(&report_body));
    }

    /// When the report contains a family ID we don't want
    #[test]
    fn family_id_fail() {
        let report_body = ReportBody::from(&REPORT_BODY_SRC);
        let mut family_id = REPORT_BODY_SRC.isv_family_id;
        family_id[0] = 0;
        let verifier = Kind::from(FamilyId::from(family_id));

        assert!(!verifier.verify(&report_body));
    }

    /// When the report contains the product ID we want
    #[test]
    fn misc_select_success() {
        let report_body = ReportBody::from(&REPORT_BODY_SRC);
        let verifier = Kind::from(MiscSelectVerifier::from(MiscellaneousSelect::from(
            REPORT_BODY_SRC.misc_select,
        )));

        assert!(verifier.verify(&report_body));
    }

    /// When the report contains a product ID we don't want
    #[test]
    fn misc_select_fail() {
        let report_body = ReportBody::from(&REPORT_BODY_SRC);
        let verifier = Kind::from(MiscSelectVerifier::from(MiscellaneousSelect::from(
            REPORT_BODY_SRC.misc_select - 1,
        )));

        assert!(!verifier.verify(&report_body));
    }

    /// When the report contains the product ID we want
    #[test]
    fn product_id_success() {
        let report_body = ReportBody::from(&REPORT_BODY_SRC);
        let verifier = Kind::from(ProductIdVerifier::from(IsvProductId::from(
            REPORT_BODY_SRC.isv_prod_id,
        )));

        assert!(verifier.verify(&report_body));
    }

    /// When the report contains a product ID we don't want
    #[test]
    fn product_id_fail() {
        let report_body = ReportBody::from(&REPORT_BODY_SRC);
        let verifier = Kind::from(ProductIdVerifier::from(IsvProductId::from(
            REPORT_BODY_SRC.isv_prod_id - 1,
        )));

        assert!(!verifier.verify(&report_body));
    }

    /// When the report contains exactly the version we want
    #[test]
    fn version_eq_pass() {
        let report_body = ReportBody::from(&REPORT_BODY_SRC);
        let verifier = Kind::from(VersionVerifier::from(IsvSvn::from(REPORT_BODY_SRC.isv_svn)));

        assert!(verifier.verify(&report_body));
    }

    /// When the report contains a newer version than we want (pass)
    #[test]
    fn version_newer_pass() {
        let report_body = ReportBody::from(&REPORT_BODY_SRC);
        let verifier = Kind::from(VersionVerifier::from(IsvSvn::from(
            REPORT_BODY_SRC.isv_svn - 1,
        )));

        assert!(verifier.verify(&report_body));
    }

    /// When the report contains an older version than we want
    #[test]
    fn version_older_fail() {
        let report_body = ReportBody::from(&REPORT_BODY_SRC);
        let verifier = Kind::from(VersionVerifier::from(IsvSvn::from(
            REPORT_BODY_SRC.isv_svn + 1,
        )));

        assert!(!verifier.verify(&report_body));
    }
}
