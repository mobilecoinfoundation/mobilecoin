// Copyright (c) 2018-2020 MobileCoin Inc.

//! SGX Quote wrapper

use alloc::vec;

use crate::{
    basename::{Basename, BASENAME_SIZE},
    epid_group_id::{EpidGroupId, EPID_GROUP_ID_SIZE},
    quote_sign::QuoteSign,
};
use alloc::{alloc::Layout, vec::Vec};
use core::{
    cmp::Ordering,
    convert::TryFrom,
    fmt::{Debug, Display, Formatter, Result as FmtResult},
    hash::{Hash, Hasher},
    ops::Range,
};
use hex_fmt::HexFmt;
use mc_sgx_core_types::{ReportBody, SecurityVersion, REPORT_BODY_SIZE, SECURITY_VERSION_SIZE};
use mc_sgx_epid_types_sys::sgx_quote_t;
use mc_util_encodings::{FromX64, IntelLayout, INTEL_U16_SIZE, INTEL_U32_SIZE};

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

const SIGLEN_START: usize = REPORT_BODY_END;
const SIGLEN_SIZE: usize = INTEL_U32_SIZE;
const SIGLEN_END: usize = SIGLEN_START + SIGLEN_SIZE;

const SIGNATURE_START: usize = SIGLEN_END;

/// When we consume a quote from the Quoting Engine, the minimum size includes the quote len.
pub const QUOTE_MIN_SIZE: usize = SIGLEN_END;

/// Arbitrary maximum length for signatures, 4x larger than any reasonable cryptographic signature.
pub const QUOTE_SIGLEN_MAX: usize = 16384;

/// The output from the Quoting Enclave.
///
/// A quoting enclave will be given a [Report](mc_sgx_core_types::Report) from the enclave under
/// examination, and it will verify the report is from the same platform, and quote the report in
/// its response. This quote will be returned to the requester, who will transmit it to IAS for
/// further verification.
///
/// Internally, this struct contains a vector of bytes, with an internal object that is aligned to
/// the size of [`sgx_quote_t`](mc_sgx_epid_tyeps_sys::sgx_quote_t). By manipulating the bytes
/// directly, we can "safely" cast the internal bytes of the vector to an aligned pointer for use
/// in FFI.
///
/// This is necessary because the underlying FFI type is variable-length, which is not representable
/// directly in rust at this time.
#[repr(transparent)]
pub struct Quote(Vec<u8>);

impl Quote {
    /// Allocate a new quote structure with the given capacity
    pub fn with_capacity(capacity: usize) -> Result<Quote, Range<usize>> {
        let range = QUOTE_MIN_SIZE..QUOTE_MIN_SIZE + QUOTE_SIGLEN_MAX;
        if !range.contains(&capacity) {
            return Err(range);
        }

        Ok(Self(vec![
            0u8;
            capacity + Layout::new::<sgx_quote_t>().align()
        ]))
    }

    /// Find out how many bytes to skip in order to have our internal sgx_quote_t be aligned.
    fn head_len(&self) -> usize {
        let (head, _body, _tail) = unsafe { self.0.align_to::<sgx_quote_t>() };
        head.len()
    }

    /// Get a properly offset read-only slice
    fn aligned_slice(&self, start: usize, len: usize) -> &[u8] {
        let start = start + self.head_len();
        let end = start + len;

        &self.0[start..end]
    }

    /// Get a properly offset writeable slice
    fn aligned_mut(&mut self, start: usize, len: usize) -> &mut [u8] {
        let start = start + self.head_len();
        let end = start + len;

        &mut self.0[start..end]
    }

    /// Read the quote version
    pub fn version(&self) -> u16 {
        let inner: &sgx_quote_t = self.as_ref();
        u16::from_le(inner.version)
    }

    /// Read the signature type
    pub fn sign_type(&self) -> QuoteSign {
        let inner: &sgx_quote_t = self.as_ref();
        QuoteSign::try_from(u16::from_le(inner.sign_type)).expect("Invalid quote sign found")
    }

    /// Read the EPID Group ID
    pub fn epid_group_id(&self) -> EpidGroupId {
        let inner: &sgx_quote_t = self.as_ref();
        EpidGroupId::from(&inner.epid_group_id)
    }

    /// Read the SVN of the enclave which generated the quote
    pub fn qe_security_version(&self) -> SecurityVersion {
        let inner: &sgx_quote_t = self.as_ref();
        SecurityVersion::from_le(inner.qe_svn)
    }

    /// Read the SVN of the provisioning certificate enclave
    pub fn pce_security_version(&self) -> SecurityVersion {
        let inner: &sgx_quote_t = self.as_ref();
        SecurityVersion::from_le(inner.pce_svn)
    }

    /// Read the extended EPID Group ID
    pub fn xeid(&self) -> u32 {
        let inner: &sgx_quote_t = self.as_ref();
        u32::from_le(inner.xeid)
    }

    /// Read the basename from the quote
    pub fn basename(&self) -> Basename {
        let inner: &sgx_quote_t = self.as_ref();
        Basename::from(&inner.basename)
    }

    /// Read the report body from the quote
    pub fn report_body(&self) -> ReportBody {
        ReportBody::from_x64(self.aligned_slice(REPORT_BODY_START, REPORT_BODY_SIZE))
            .expect("Invalid report body")
    }

    /// Read the signature length from the quote (may be zero)
    pub fn signature_len(&self) -> u32 {
        let inner: &sgx_quote_t = self.as_ref();
        u32::from_le(inner.signature_len)
    }

    /// Retrieve a slice of the signature
    pub fn signature(&self) -> Option<&[u8]> {
        let siglen = self.signature_len();
        if siglen == 0 {
            return None;
        }

        Some(self.aligned_slice(SIGNATURE_START, siglen as usize))
    }
}

impl AsRef<sgx_quote_t> for Quote {
    fn as_ref(&self) -> &sgx_quote_t {
        let (_head, body, _tail) = unsafe { self.0.align_to::<sgx_quote_t>() };
        &body[0]
    }
}

impl AsMut<sgx_quote_t> for Quote {
    fn as_mut(&mut self) -> &mut sgx_quote_t {
        let (_head, body, _tail) = unsafe { self.0.align_to_mut::<sgx_quote_t>() };
        &mut body[0]
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

impl TryFrom<sgx_quote_t> for Quote {
    type Error = EncodingError;

    fn try_from(src: sgx_quote_t) -> Quote {
        Self::from(&src)
    }
}

impl From<&sgx_quote_t> for Quote {
    fn try_from(src: &sgx_quote_t) -> Quote {
        let target_size = src.signature_len as usize + QUOTE_MIN_SIZE;

        // Allocate a new buffer at least as large as the target size + sgx_quote_t's alignment
        let mut retval = Self::with_capacity(target_size).expect("")

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
    const X86_64_CSIZE: usize = QUOTE_MIN_SIZE + QUOTE_SIGLEN_MAX;

    fn intel_size(&self) -> usize {
        QUOTE_MIN_SIZE + self.signature_len() as usize
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
