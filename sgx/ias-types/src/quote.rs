// Copyright (c) 2018-2020 MobileCoin Inc.

//! IAS Quote Structure
//!
//! This is the "special" version of sgx_quote_t that's returned by IAS (it does
//! not contain the signature_len unsigned or variable-length signature fields)
//! but not actually provided anywhere in the SGX headers. We skip the byte
//! representation because this is never used during FFI, in favor of parsing it
//! directly into the rusty types that sit above FFI types.

use core::convert::{TryFrom, TryInto};
use mc_sgx_core_types::{ReportBody, SecurityVersion, REPORT_BODY_SIZE, SECURITY_VERSION_SIZE};
use mc_sgx_epid_types::{
    Basename, EpidGroupId, Quote as SgxQuote, QuoteSign, BASENAME_SIZE, EPID_GROUP_ID_SIZE,
};
use mc_util_encodings::{Error as EncodingError, FromBase64, INTEL_U16_SIZE, INTEL_U32_SIZE};
use mc_util_repr_bytes::{typenum::U432, GenericArray, ReprBytes};
#[cfg(feature = "use_prost")]
use prost::Message;

const VERSION_START: usize = 0;
const VERSION_SIZE: usize = INTEL_U16_SIZE;
const VERSION_END: usize = VERSION_START + VERSION_SIZE;

const SIGN_TYPE_START: usize = VERSION_END;
const SIGN_TYPE_SIZE: usize = INTEL_U16_SIZE;
const SIGN_TYPE_END: usize = SIGN_TYPE_START + SIGN_TYPE_SIZE;

const EPID_GROUP_ID_START: usize = SIGN_TYPE_END;
const EPID_GROUP_ID_END: usize = EPID_GROUP_ID_START + EPID_GROUP_ID_SIZE;

const QE_SVN_START: usize = EPID_GROUP_ID_END;
const QE_SVN_END: usize = QE_SVN_START + SECURITY_VERSION_SIZE;

const PCE_SVN_START: usize = QE_SVN_END;
const PCE_SVN_END: usize = PCE_SVN_START + SECURITY_VERSION_SIZE;

const XEID_START: usize = PCE_SVN_END;
const XEID_SIZE: usize = INTEL_U32_SIZE;
const XEID_END: usize = XEID_START + XEID_SIZE;

const BASENAME_START: usize = XEID_END;
const BASENAME_END: usize = BASENAME_START + BASENAME_SIZE;

const REPORT_BODY_START: usize = BASENAME_END;
const REPORT_BODY_END: usize = REPORT_BODY_START + REPORT_BODY_SIZE;

/// The quote structure returned by IAS.
///
/// This structure is nearly identical to the
/// EPID [`Quote`](mc_sgx_epid_types::Quote) structure, but does not contain the
/// variable-length signature and it's length.
#[cfg_attr(feature = "use_prost", derive(Message))]
#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Quote {
    /// The quote version
    #[cfg_attr(feature = "use_prost", prost(uint32, required))]
    version: u32,

    /// The quote signature type (linkable vs. unlinkable).
    #[cfg_attr(feature = "use_prost", prost(enumeration = "QuoteSign", required))]
    sign_type: i32,

    /// The EPID Group ID of the platform.
    #[cfg_attr(feature = "use_prost", prost(message, required))]
    epid_group_id: EpidGroupId,

    /// The security version of the original quoting enclave.
    #[cfg_attr(feature = "use_prost", prost(uint32, required))]
    qe_svn: u32,

    /// The security version of the provisioning certificate enclave.
    #[cfg_attr(feature = "use_prost", prost(uint32, required))]
    pce_svn: u32,

    /// The XEID
    #[cfg_attr(feature = "use_prost", prost(uint32, required))]
    xeid: u32,

    /// The basename
    #[cfg_attr(feature = "use_prost", prost(message, required))]
    basename: Basename,

    /// The quoted report body
    #[cfg_attr(feature = "use_prost", prost(message, required))]
    report_body: ReportBody,
}

impl Quote {
    /// Retrieve the quote version
    pub fn version(&self) -> u16 {
        u16::try_from(self.version).unwrap_or(0)
    }

    /// Retrieve the EPID Group ID from.
    pub fn epid_group_id(&self) -> &EpidGroupId {
        &self.epid_group_id
    }

    /// Retrieve the quoting enclave's security version
    pub fn qe_security_version(&self) -> SecurityVersion {
        u16::try_from(self.qe_svn).unwrap_or(0)
    }

    /// Retrieve the sealing enclave's security version
    pub fn pce_security_version(&self) -> SecurityVersion {
        u16::try_from(self.pce_svn).unwrap_or(0)
    }

    /// Retrieve the XEID
    pub fn xeid(&self) -> u32 {
        self.xeid
    }

    /// Retrieve the basename.
    pub fn basename(&self) -> &Basename {
        &self.basename
    }

    /// Retrieve the quoted EPID report body
    pub fn report_body(&self) -> &ReportBody {
        &self.report_body
    }
}

impl FromBase64 for Quote {
    type Error = EncodingError;

    fn from_base64(src: &str) -> Result<Self, Self::Error> {
        // We decode base64 into this buffer, then FromX64 the contents into our
        // components.
        let mut buffer = GenericArray::default();
        base64::decode_config_slice(src, base64::STANDARD, buffer.as_mut_slice())?;

        Self::from_bytes(&buffer)
    }
}

impl PartialEq<SgxQuote> for Quote {
    fn eq(&self, other: &SgxQuote) -> bool {
        other.version() as u32 == self.version
            && other.sign_type() == self.sign_type()
            && other.epid_group_id() == self.epid_group_id
            && other.qe_security_version() as u32 == self.qe_svn
            && other.pce_security_version() as u32 == self.pce_svn
            && other.xeid() == self.xeid
            && other.basename() == self.basename
            && other.report_body() == self.report_body
    }
}

impl ReprBytes for Quote {
    type Size = U432;
    type Error = EncodingError;

    fn from_bytes(src: &GenericArray<u8, Self::Size>) -> Result<Self, Self::Error> {
        let version = u16::from_le_bytes(
            src[VERSION_START..VERSION_END]
                .try_into()
                .expect("Invalid size of version field"),
        ) as u32;
        let sign_type = QuoteSign::try_from(u16::from_le_bytes(
            src[SIGN_TYPE_START..SIGN_TYPE_END]
                .try_into()
                .expect("Invalid size of sign type field"),
        ))? as i32;
        let epid_group_id = EpidGroupId::try_from(&src[EPID_GROUP_ID_START..EPID_GROUP_ID_END])?;
        let qe_svn = SecurityVersion::from_le_bytes(
            src[QE_SVN_START..QE_SVN_END]
                .try_into()
                .expect("Invalid size of QE SVN field"),
        ) as u32;
        let pce_svn = SecurityVersion::from_le_bytes(
            src[PCE_SVN_START..PCE_SVN_END]
                .try_into()
                .expect("Invalid size of PCE SVN field"),
        ) as u32;
        let xeid = u32::from_le_bytes(
            src[XEID_START..XEID_END]
                .try_into()
                .expect("Invalid size of XEID field"),
        );
        let basename = Basename::try_from(&src[BASENAME_START..BASENAME_END])?;
        let report_body = ReportBody::try_from(&src[REPORT_BODY_START..REPORT_BODY_END])?;

        Ok(Self {
            version,
            sign_type,
            epid_group_id,
            qe_svn,
            pce_svn,
            xeid,
            basename,
            report_body,
        })
    }

    fn to_bytes(&self) -> GenericArray<u8, Self::Size> {
        let mut retval = GenericArray::default();

        retval[VERSION_START..VERSION_END].copy_from_slice(&self.version.to_le_bytes());
        retval[SIGN_TYPE_START..SIGN_TYPE_END].copy_from_slice(&self.sign_type.to_le_bytes());
        retval[EPID_GROUP_ID_START..EPID_GROUP_ID_END].copy_from_slice(self.epid_group_id.as_ref());
        retval[QE_SVN_START..QE_SVN_END].copy_from_slice(&self.qe_svn.to_le_bytes());
        retval[PCE_SVN_START..PCE_SVN_END].copy_from_slice(&self.pce_svn.to_le_bytes());
        retval[XEID_START..XEID_END].copy_from_slice(&self.xeid.to_le_bytes());
        retval[BASENAME_START..BASENAME_END].copy_from_slice(self.basename.as_ref());
        retval[REPORT_BODY_START..REPORT_BODY_END]
            .copy_from_slice(self.report_body.to_bytes().as_slice());

        retval
    }
}
