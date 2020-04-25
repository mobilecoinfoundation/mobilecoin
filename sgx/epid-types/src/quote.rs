// Copyright (c) 2018-2020 MobileCoin Inc.

//! SGX Quote wrapper

use crate::{
    basename::{Basename, BASENAME_SIZE},
    epid_group_id::{EpidGroupId, EPID_GROUP_ID_SIZE},
    quote_sign::QuoteSign,
};
use alloc::vec::Vec;
use core::{
    cmp::Ordering,
    convert::{TryFrom, TryInto},
    fmt::{Debug, Display, Formatter, Result as FmtResult},
    hash::{Hash, Hasher},
    ptr,
};
use hex_fmt::HexFmt;
use mc_encodings::{
    Error as EncodingError, FromX64, IntelLayout, ToX64, INTEL_U16_SIZE, INTEL_U32_SIZE,
};
use mc_sgx_core_types::{
    FfiWrapper, ReportBody, SecurityVersion, REPORT_BODY_SIZE, SECURITY_VERSION_SIZE,
};
use mc_sgx_epid_types_sys::sgx_quote_t;

const VERSION_START: usize = 0;
const VERSION_END: usize = VERSION_START + SECURITY_VERSION_SIZE;
// Note: even though sgx_quote_sign_type_t is unsized (u32) C enum, the value is encoded here as a
// u16.
const SIGN_TYPE_START: usize = VERSION_END;
const SIGN_TYPE_END: usize = SIGN_TYPE_START + INTEL_U16_SIZE;
const EPID_GROUP_ID_START: usize = SIGN_TYPE_END;
const EPID_GROUP_ID_END: usize = EPID_GROUP_ID_START + EPID_GROUP_ID_SIZE;
const QESVN_START: usize = EPID_GROUP_ID_END;
const QESVN_END: usize = QESVN_START + SECURITY_VERSION_SIZE;
const PCESVN_START: usize = QESVN_END;
const PCESVN_END: usize = PCESVN_START + SECURITY_VERSION_SIZE;
const XEID_START: usize = PCESVN_END;
const XEID_END: usize = XEID_START + INTEL_U32_SIZE;
const BASENAME_START: usize = XEID_END;
const BASENAME_END: usize = BASENAME_START + BASENAME_SIZE;
const REPORT_BODY_START: usize = BASENAME_END;
const REPORT_BODY_END: usize = REPORT_BODY_START + REPORT_BODY_SIZE;
const SIGLEN_START: usize = REPORT_BODY_END;
const SIGLEN_END: usize = SIGLEN_START + INTEL_U32_SIZE;
const SIGNATURE_START: usize = SIGLEN_END;

/// When we consume a quote from the Quoting Engine, the minimum size includes the quote len.
pub const MIN_SIZE: usize = SIGLEN_END;

/// Arbitrary maximum length for signatures, 4x larger than any reasonable cryptographic signature.
pub const SIGLEN_MAX: usize = 16384;

/// The output from the Quoting Enclave.
///
/// A quoting enclave will be given a [Report](mc_sgx_core_types::Report)
/// from the enclave under examination, and it will verify the report is from
/// the same platform, and quote the report in the QE's response. This quote
/// will be returned to the requester, who will transmit it to IAS for further
/// verification.
#[repr(transparent)]
pub struct Quote(Vec<u8>);

impl Quote {
    /// Read the quote version
    pub fn version(&self) -> u16 {
        u16::from_le_bytes((&self.0[VERSION_START..VERSION_END]).try_into().unwrap())
    }

    /// Read the signature type
    pub fn sign_type(&self) -> Result<QuoteSignType, QuoteSignTypeError> {
        u16::from_le_bytes((&self.0[SIGNTYPE_START..SIGNTYPE_END]).try_into().unwrap()).try_into()
    }

    /// Read the EPID Group ID
    pub fn epid_group_id(&self) -> EpidGroupId {
        EpidGroupId::try_from(&self.0[EPIDGROUP_ID_START..EPIDGROUP_ID_END])
            .expect("Could not create EpidGroupId from quote")
    }

    /// Read the SVN of the enclave which generated the quote
    pub fn qe_security_version(&self) -> SecurityVersion {
        u16::from_le_bytes((&self.0[QESVN_START..QESVN_END]).try_into().unwrap())
    }

    /// Read the SVN of the provisioning certificate enclave
    pub fn pce_security_version(&self) -> SecurityVersion {
        u16::from_le_bytes((&self.0[PCESVN_START..PCESVN_END]).try_into().unwrap())
    }

    /// Read the extended EPID Group ID
    pub fn xeid(&self) -> u32 {
        u32::from_le_bytes((&self.0[XEID_START..XEID_END]).try_into().unwrap())
    }

    /// Read the basename from the quote
    pub fn basename(&self) -> Basename {
        Basename::from_x64(&self.0[BASENAME_START..BASENAME_END])
            .expect("Programming error while reading basename, check offsets.")
    }

    /// Read the report body from the quote
    pub fn report_body(&self) -> Result<ReportBody, EncodingError> {
        ReportBody::from_x64(&self.0[REPORT_BODY_START..REPORT_BODY_END])
    }

    /// Read the signature length from the quote (may be zero)
    pub fn signature_len(&self) -> u32 {
        u32::from_le_bytes((&self.0[SIGLEN_START..SIGLEN_END]).try_into().unwrap())
    }

    pub fn signature(&self) -> Option<&[u8]> {}
}

impl AsMut<sgx_quote_t> for Quote {
    fn as_mut(&mut self) -> &mut sgx_quote_t {
        &mut self.0
    }
}

impl AsRef<sgx_quote_t> for Quote {
    fn as_ref(&self) -> &sgx_quote_t {
        &(unsafe { *(self.0.as_ptr() as *const sgx_quote_t) })
    }
}

impl AsMut<sgx_quote_t> for Quote {
    fn as_mut(&mut self) -> &mut sgx_quote_t {
        &(unsafe { *(self.0.as_mut_ptr() as *mut sgx_quote_t) })
    }
}

impl Debug for Quote {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        write!(
            f,
            "Quote: {{ version: {}, sign_type: {}, epid_group_id: {}, qe_svn: {}, pce_svn: {}, xeid: {}, basename: {:?}, report_body: {:?}, signature_len: {}, signature: {:?} }}",
            self.version(), self.sign_type(), self.epid_group_id(), self.qe_security_version(),
            self.pce_security_version(), self.xeid(), self.basename(), self.report_body(),
            self.signature_len(), self.signature().map(HexFmt)
        )
    }
}

impl Display for Quote {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        write!(
            f,
            "{} EPID Quote of {} by QE {}",
            self.sign_type(),
            self.report_body().mr_enclave(),
            self.qe_security_version()
        )
    }
}

impl Eq for Quote {}

impl From<sgx_quote_t> for Quote {
    fn from(src: sgx_quote_t) -> Quote {
        Self::from(&src)
    }
}

impl From<&sgx_quote_t> for Quote {
    fn from(src: &sgx_quote_t) -> Quote {
        let target_size = src.signature_len as usize + MIN_SIZE;

        // Figure out how large a buffer we need to allocate while maintaining Quote's alignment
        let layout = Layout::from_size_align(
            target_size.next_power_of_two(),
            Layout::new::<Quote>().align(),
        )
        .map_err(|_e| EncodingError::InvalidInput)?;

        // Allocate a new structure
        let mut retval = unsafe { ptr::read(alloc::alloc::alloc(layout) as *mut Quote) };

        // Copy the contents
        retval.0.version = src.version;
        retval.0.sign_type = src.sign_type;
        retval.0.epid_group_id = src.epid_group_id;
        retval.0.qe_svn = src.qe_svn;
        retval.0.pce_svn = src.pce_svn;
        retval.0.xeid = src.xeid;
        retval.0.basename = src.basename;
        retval.0.report_body = src.basename;
        retval.0.signature_len = src.signature_len;
        unsafe {
            retval
                .0
                .signature
                .as_mut_slice(retval.0.signature_len as usize)
                .copy_from_slice(src.signature.as_slice(src.signature_len as usize));
        }

        retval
    }
}

impl FromX64 for Quote {
    type Error = EncodingError;

    fn from_x64(src: &[u8]) -> Result<Self, EncodingError> {
        if src.len() < MIN_SIZE {
            return Err(EncodingError::InvalidInputLength);
        }

        let signature_len = u32::from_le_bytes(
            src[SIGLEN_START..SIGLEN_END]
                .try_into()
                .expect("Could not convert siglen into 4 byte array"),
        ) as usize;

        if signature_len > SIGLEN_MAX {
            return Err(EncodingError::InvalidInput);
        }

        let target_size = MIN_SIZE + signature_len;

        if src.len() != target_size {
            return Err(EncodingError::InvalidInputLength);
        }

        // Fallible member parsing (fail before we alloc)
        let sign_type = QuoteSign::try_from(u16::from_le_bytes(
            src[SIGN_TYPE_START..SIGN_TYPE_END]
                .try_into()
                .expect("Invalid length of quote sign type"),
        ))
        .map_err(|_e| EncodingError::InvalidInput)?;

        let epid_group_id = EpidGroupId::from_x64(&src[EPID_GROUP_ID_START..EPID_GROUP_ID_END])
            .map_err(|_e| EncodingError::InvalidInput)?;

        let basename = Basename::from_x64(&src[BASENAME_START..BASENAME_END])
            .map_err(|_e| EncodingError::InvalidInput)?;

        let report_body = ReportBody::from_x64(&src[REPORT_BODY_START..REPORT_BODY_END])
            .map_err(|_e| EncodingError::InvalidInput)?;

        // Figure out how large a buffer we need to allocate while maintaining Quote's alignment
        let layout = Layout::from_size_align(
            target_size.next_power_of_two(),
            Layout::new::<Quote>().align(),
        )
        .map_err(|_e| EncodingError::InvalidInput)?;

        // Allocate a new structure
        let mut retval = unsafe { ptr::read(alloc::alloc::alloc(layout) as *mut Quote) };

        // Fill in it's contents
        retval.0.version = u16::from_le_bytes(
            src[VERSION_START..VERSION_END]
                .try_into()
                .expect("Invalid length of version"),
        );
        retval.0.sign_type = sign_type.into();
        retval.0.epid_group_id = epid_group_id.into();
        retval.0.qe_svn = u16::from_le_bytes(
            src[QESVN_START..QESVN_END]
                .try_into()
                .expect("Invalid length of QE security version"),
        );
        retval.0.pce_svn = u16::from_le_bytes(
            src[PCESVN_START..PCESVN_END]
                .try_into()
                .expect("Invalid length of PCE security version"),
        );
        retval.0.xeid = u32::from_le_bytes(
            src[XEID_START..XEID_END]
                .try_into()
                .expect("Invalid length of XEID"),
        );
        retval.0.basename = basename.into();
        retval.0.report_body = report_body.into();
        retval.0.signature_len = signature_len as u32;
        retval.0.signature.Ok(retval)
    }
}

impl Hash for Quote {
    fn hash<H: Hasher>(&self, hasher: &mut H) {
        "mc_sgx_epid_types::quote::Quote".hash(hasher);
        self.version().hash(hasher);
        self.sign_type().hash(hasher);
        self.epid_group_id().hash(hasher);
        self.qe_security_version().hash(hasher);
        self.pce_security_version().hash(hasher);
        self.xeid().hash(hasher);
        self.basename().hash(hasher);
        self.report_body().hash(hasher);
    }
}

impl IntelLayout for Quote {
    const X86_64_CSIZE: usize = MIN_SIZE + SIGLEN_MAX;

    fn intel_size(&self) -> usize {
        MIN_SIZE + self.signature_len()
    }
}

impl Ord for Quote {
    fn cmp(&self, other: &Self) -> Ordering {
        match self.version().cmp(&other.version()) {
            Ordering::Equal => match self.sign_type().cmp(&other.sign_type()) {
                Ordering::Equal => match self.epid_group_id().cmp(&other.epid_group_id()) {
                    Ordering::Equal => {
                        match self.qe_security_version().cmp(&other.qe_security_version()) {
                            Ordering::Equal => match self
                                .pce_security_version()
                                .cmp(&other.pce_security_version())
                            {
                                Ordering::Equal => match self.xeid().cmp(&other.xeid()) {
                                    Ordering::Equal => match self.basename().cmp(&other.basename())
                                    {
                                        Ordering::Equal => {
                                            match self.report_body().cmp(&other.report_body()) {
                                                Ordering::Equal => match self
                                                    .signature_len()
                                                    .cmp(&other.signature_len())
                                                {
                                                    Ordering::Equal => {
                                                        self.signature().cmp(&other.signature())
                                                    }
                                                    other => other,
                                                },
                                                other => other,
                                            }
                                        }
                                        other => other,
                                    },
                                    other => other,
                                },
                                other => other,
                            },
                            other => other,
                        }
                    }
                    other => other,
                },
                other => other,
            },
            other => other,
        }
    }
}

impl PartialEq for Quote {
    fn eq(&self, other: &Self) -> bool {
        self.signature_len() == other.signature_len()
            && self.signature() == other.signature()
            && self.version() == other.version()
            && self.sign_type() == other.sign_type()
            && self.epid_group_id() == other.epid_group_id()
            && self.qe_security_version() == other.qe_security_version()
            && self.pce_security_version() == other.pce_security_version()
            && self.xeid() == other.xeid()
            && self.basename() == other.basename()
            && self.report_body() == other.report_body()
    }
}

impl PartialOrd for Quote {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl ToX64 for Quote {
    fn to_x64(&self, dest: &mut [u8]) -> Result<usize, usize> {
        let required_len = self.intel_size();
        if dest.len() < required_len {
            Err(required_len)
        } else {
            dest[VERSION_START..VERSION_END].copy_from_slice(&self.version().to_le_bytes());
            dest[SIGN_TYPE_START..SIGN_TYPE_END].copy_from_slice(&self.0.sign_type.to_le_bytes());

            self.epid_group_id()
                .to_x64(&mut dest[EPID_GROUP_ID_START..EPID_GROUP_ID_END])
                .map_err(|_e| required_len)?;

            dest[QESVN_START..QESVN_END].copy_from_slice(&self.qe_security_version().to_le_bytes());
            dest[PCESVN_START..PCESVN_END]
                .copy_from_slice(&self.pce_security_version().to_le_bytes());
            dest[XEID_START..XEID_END].copy_from_slice(&self.xeid().to_le_bytes());

            self.basename()
                .to_x64(&mut dest[BASENAME_START..BASENAME_END])
                .map_err(|_e| required_len)?;

            self.report_body()
                .to_x64(&mut dest[REPORT_BODY_START..REPORT_BODY_END])
                .map_err(|_e| required_len)?;

            dest[SIGLEN_START..SIGLEN_END].copy_from_slice(&self.0.signature_len.to_le_bytes());
            self.signature().and_then(|value| {
                dest[SIGNATURE_START..(SIGNATURE_START + value.len())].copy_from_slice(value);
                Some(value)
            });

            Ok(required_len)
        }
    }
}

impl FfiWrapper<sgx_quote_t> for Quote {}

#[cfg(test)]
mod test {
    extern crate std;

    use super::*;
    use bincode::{deserialize, serialize};
    use std::format;

    const OK: &[u8] = include_bytes!("test/quote_ok.bin");
    const OK_STR: &str = include_str!("test/quote_ok.txt");

    #[test]
    fn serde() {
        let quote = Quote::from_x64(OK).expect("Could not create quote from base64 string");
        let serialized = serialize(&quote).expect("Could not serialize quote.");
        let quote2 = deserialize::<Quote>(&serialized).expect("Could not deserialize quote.");
        assert_eq!(quote, quote2);
    }

    #[test]
    fn test_quote_debug_fmt() {
        let quote = Quote::from_base64(OK).expect("Could not create quote from base64 string");
        let debug_str = format!("{:?}", &quote);
        assert_eq!(OK_STR, debug_str);
    }
}
