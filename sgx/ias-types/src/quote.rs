// Copyright (c) 2018-2020 MobileCoin Inc.

//! IAS Quote Structure
//!
//! This is the "special" version of sgx_quote_t that's returned by IAS (it does not contain the
//! signature_len unsigned or variable-length signature fields) but not actually provided anywhere
//! in the SGX headers. We skip the byte representation, as it's never used during FFI, in favor of
//! parsing it directly into the rusty types that sit above the FFI types.

use base64::DecodeError;
use core::convert::{TryFrom, TryInto};
use displaydoc::Display;
use mc_sgx_core_types::{ReportBody, SecurityVersion, REPORT_BODY_SIZE, SECURITY_VERSION_SIZE};
use mc_sgx_epid_types::{
    Basename, EpidGroupId, Quote as SgxQuote, QuoteSign, BASENAME_SIZE, EPID_GROUP_ID_SIZE,
    QUOTE_MIN_SIZE,
};
use mc_util_encodings::{
    Error as EncodingError, FromBase64, FromX64, INTEL_U16_SIZE, INTEL_U32_SIZE,
};
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

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

/// An enumeration of errors which can occur when parsing base64 into a quote.
#[derive(Clone, Debug, Display, Eq, PartialEq)]
pub enum Error {
    /// There was an error decoding the Base64: {0}
    Base64(DecodeError),
    /// One (or more) of the fields contained invalid data: {0}
    Encoding(EncodingError),
}

impl From<DecodeError> for Error {
    fn from(src: DecodeError) -> Self {
        Error::Base64(src)
    }
}

impl From<EncodingError> for Error {
    fn from(src: EncodingError) -> Self {
        Error::Encoding(src)
    }
}

/// The quote structure returned by IAS.
///
/// This structure is nearly identical to the [`Quote`](mc_sgx_epid_types::Quote)
/// structure, but does not contain the variable-length signature and it's length.
#[cfg_attr(feature = "serde", derive(Deserialize, Serialize))]
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Quote {
    /// The quote version
    pub version: u16,

    /// The quote signature type (linkable vs. unlinkable).
    pub sign_type: QuoteSign,

    /// The EPID Group ID of the platform.
    pub epid_group_id: EpidGroupId,

    /// The security version of the original quoting enclave.
    pub qe_svn: SecurityVersion,

    /// The security version of the provisioning certificate enclave.
    pub pce_svn: SecurityVersion,

    /// The XEID
    pub xeid: u32,

    /// The basename
    pub basename: Basename,

    /// The quoted report body
    pub report_body: ReportBody,
}

impl FromBase64 for Quote {
    type Error = Error;

    fn from_base64(src: &str) -> Result<Self, Self::Error> {
        // We decode base64 into this buffer, then FromX64 the contents into our components.
        let mut buffer = [0u8; QUOTE_MIN_SIZE - INTEL_U32_SIZE];
        base64::decode_config_slice(src, base64::STANDARD, &mut buffer)?;

        let version = u16::from_le_bytes(
            buffer[VERSION_START..VERSION_END]
                .try_into()
                .expect("Invalid size of version field"),
        );
        let sign_type = QuoteSign::try_from(u16::from_le_bytes(
            buffer[SIGN_TYPE_START..SIGN_TYPE_END]
                .try_into()
                .expect("Invalid size of sign type field"),
        ))?;
        let epid_group_id = EpidGroupId::from_x64(&buffer[EPID_GROUP_ID_START..EPID_GROUP_ID_END])?;
        let qe_svn = SecurityVersion::from_le_bytes(
            buffer[QE_SVN_START..QE_SVN_END]
                .try_into()
                .expect("Invalid size of QE SVN field"),
        );
        let pce_svn = SecurityVersion::from_le_bytes(
            buffer[PCE_SVN_START..PCE_SVN_END]
                .try_into()
                .expect("Invalid size of PCE SVN field"),
        );
        let xeid = u32::from_le_bytes(
            buffer[XEID_START..XEID_END]
                .try_into()
                .expect("Invalid size of XEID field"),
        );
        let basename = Basename::from_x64(&buffer[BASENAME_START..BASENAME_END])?;
        let report_body = ReportBody::from_x64(&buffer[REPORT_BODY_START..REPORT_BODY_END])?;

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
}

impl PartialEq<SgxQuote> for Quote {
    fn eq(&self, other: &SgxQuote) -> bool {
        other.version() == self.version
            && other.sign_type() == self.sign_type
            && other.epid_group_id() == self.epid_group_id
            && other.qe_security_version() == self.qe_svn
            && other.pce_security_version() == self.pce_svn
            && other.xeid() == self.xeid
            && other.basename() == self.basename
            && other.report_body() == self.report_body
    }
}
