// Copyright (c) 2018-2021 The MobileCoin Foundation

//! This module contains functionality related to the Intel SGX Quoting
//! Enclave

use alloc::vec;

use crate::{
    error::{QuoteError, QuoteSignTypeError, QuoteVerifyError},
    report::Report,
    types::{
        basename::Basename, epid_group_id::EpidGroupId, measurement::Measurement,
        report_body::ReportBody, report_data::ReportDataMask,
    },
    ProductId, SecurityVersion,
};
use alloc::vec::Vec;
use binascii::{b64decode, b64encode};
use core::{
    cmp::{max, min},
    convert::{TryFrom, TryInto},
    fmt::{Debug, Display, Formatter, Result as FmtResult},
    ops::Range,
};
use mc_sgx_types::{sgx_quote_sign_type_t, sgx_quote_t};
use mc_util_encodings::{
    base64_buffer_size, Error as EncodingError, FromBase64, IntelLayout, ToBase64, ToX64,
    INTEL_U16_SIZE, INTEL_U32_SIZE,
};
use serde::{Deserialize, Serialize};

const QUOTE_VERSION_START: usize = 0;
const QUOTE_VERSION_END: usize = QUOTE_VERSION_START + INTEL_U16_SIZE;
const QUOTE_SIGNTYPE_START: usize = QUOTE_VERSION_END;
const QUOTE_SIGNTYPE_END: usize = QUOTE_SIGNTYPE_START + INTEL_U16_SIZE;
const QUOTE_EPIDGID_START: usize = QUOTE_SIGNTYPE_END;
const QUOTE_EPIDGID_END: usize = QUOTE_EPIDGID_START + <EpidGroupId as IntelLayout>::X86_64_CSIZE;
const QUOTE_QESVN_START: usize = QUOTE_EPIDGID_END;
const QUOTE_QESVN_END: usize = QUOTE_QESVN_START + INTEL_U16_SIZE;
const QUOTE_PCESVN_START: usize = QUOTE_QESVN_END;
const QUOTE_PCESVN_END: usize = QUOTE_PCESVN_START + INTEL_U16_SIZE;
const QUOTE_XEID_START: usize = QUOTE_PCESVN_END;
const QUOTE_XEID_END: usize = QUOTE_XEID_START + INTEL_U32_SIZE;
const QUOTE_BASENAME_START: usize = QUOTE_XEID_END;
const QUOTE_BASENAME_END: usize = QUOTE_BASENAME_START + <Basename as IntelLayout>::X86_64_CSIZE;
const QUOTE_REPORTBODY_START: usize = QUOTE_BASENAME_END;
const QUOTE_REPORTBODY_END: usize =
    QUOTE_REPORTBODY_START + <ReportBody as IntelLayout>::X86_64_CSIZE;
const QUOTE_SIGLEN_START: usize = QUOTE_REPORTBODY_END;
const QUOTE_SIGLEN_END: usize = QUOTE_SIGLEN_START + INTEL_U32_SIZE;
const QUOTE_SIGNATURE_START: usize = QUOTE_SIGLEN_END;

// When we consume a quote from the Quoting Engine, the minimum size includes
// the quote len.
const QUOTE_MINSIZE: usize = QUOTE_SIGLEN_END;

// When we get a quote back from IAS, they strip both the signature and the
// signature len, which changes the structure's size and makes sgx_quote_t
// unusable directly.
const QUOTE_IAS_SIZE: usize = QUOTE_REPORTBODY_END;

// Arbitrary maximum length for signatures, 4x larger than any reasonable
// cryptographic signature.
const QUOTE_SIGLEN_MAX: usize = 16384;

/// An enumeration of viable quote signature types
#[derive(Clone, Copy, Debug, Deserialize, Hash, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[repr(u32)]
pub enum QuoteSignType {
    Unlinkable = 0,
    Linkable = 1,
}

impl Display for QuoteSignType {
    fn fmt(&self, formatter: &mut Formatter) -> FmtResult {
        let text = match self {
            QuoteSignType::Unlinkable => "Unlinkable",
            QuoteSignType::Linkable => "Linkable",
        };
        write!(formatter, "{}", text)
    }
}

impl TryFrom<u16> for QuoteSignType {
    type Error = QuoteSignTypeError;

    fn try_from(src: u16) -> Result<Self, QuoteSignTypeError> {
        match src {
            0 => Ok(QuoteSignType::Unlinkable),
            1 => Ok(QuoteSignType::Linkable),
            other => Err(QuoteSignTypeError::Unknown(u64::from(other))),
        }
    }
}

impl From<sgx_quote_sign_type_t> for QuoteSignType {
    fn from(src: sgx_quote_sign_type_t) -> Self {
        match src {
            sgx_quote_sign_type_t::SGX_UNLINKABLE_SIGNATURE => QuoteSignType::Unlinkable,
            sgx_quote_sign_type_t::SGX_LINKABLE_SIGNATURE => QuoteSignType::Linkable,
        }
    }
}

impl From<QuoteSignType> for sgx_quote_sign_type_t {
    fn from(src: QuoteSignType) -> sgx_quote_sign_type_t {
        match src {
            QuoteSignType::Unlinkable => sgx_quote_sign_type_t::SGX_UNLINKABLE_SIGNATURE,
            QuoteSignType::Linkable => sgx_quote_sign_type_t::SGX_LINKABLE_SIGNATURE,
        }
    }
}

/// The output from the Quoting Enclave.
///
/// A quoting enclave will be given a Report from the enclave under test,
/// and it will verify the report is from the same platform, and generate
/// a quote in response. This quote will be returned to the requester,
/// who will transmit it to IAS for further verification. IAS will generate
/// a VerificationReport in response, which can then be checked by the
/// requester.
///
/// The actual implementation of this is super squirelly, because the
/// structure that lives in C-land is variable-length in the usual way.
/// This would ordinarily mean that the rust FFI struct equivalent would
/// be a dynamically-sized type, which would prevent it from being
/// initialized safely (i.e. you always need to start with bytes, and cast
/// to what you want). However, since access to padding bytes is clearly
/// UB, the rust FFI structure in this case must be declared as
/// `repr(packed)`, which turns field accesses into UB.
///
/// The underlying FFI elides the DST problem by improperly declaring the
/// signature field as a zero-width type. Rather than doing
/// `signature: [u8]`, which would make the FFI type a DST, it uses a
/// C-style `[u8; 0]`, which means `()` in Rust (that is, a zero width
/// type). It does, however, continue to declare the structure as
/// `repr(packed)`, so field access is still UB. Fixing that FFI library
/// would break both source and binary compatibility, so the upshot of
/// all this is that you can't actually use `sgx_quote_t` as anything
/// other than a pointer label.
///
/// Which means we can't use it for anything, even though we need to ship
/// it's contents (or at least their x86_64 C representation) around. Instead,
/// we shall do it live. We'll write the bytes and we'll do it live.
#[derive(Clone, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub struct Quote(Vec<u8>);

impl Quote {
    /// Create a new, empty quote for the given size.
    ///
    /// The length should be at least as large as an unsized sgx_quote_t
    /// (436B).
    pub fn with_capacity(size: u32) -> Result<Self, QuoteError> {
        if (size as usize) < QUOTE_MINSIZE {
            Err(QuoteError::InvalidSize(size))
        } else {
            Ok(Self(vec![0u8; size as usize]))
        }
    }

    /// Get the underlying buffer as a a pointer to the sgx_quote_t FFI
    /// structure.
    pub fn as_mut_ptr(&mut self) -> *mut sgx_quote_t {
        self.0.as_mut_ptr() as *mut sgx_quote_t
    }

    /// Read the size of the internal buffer containing the quote (may be larger
    /// than the quote itself)
    pub fn capacity(&self) -> usize {
        self.0.len()
    }

    fn try_get_slice(&self, range: Range<usize>) -> Result<&[u8], EncodingError> {
        if self.capacity() < range.end {
            Err(EncodingError::InvalidInputLength)
        } else {
            Ok(&self.0[range])
        }
    }

    /// Read the quote version
    pub fn version(&self) -> Result<u16, EncodingError> {
        self.try_get_slice(QUOTE_VERSION_START..QUOTE_VERSION_END)
            .map(|bytes| u16::from_le_bytes(bytes.try_into().unwrap()))
    }

    /// Read the signature type
    pub fn sign_type(&self) -> Result<QuoteSignType, QuoteSignTypeError> {
        self.try_get_slice(QUOTE_SIGNTYPE_START..QUOTE_SIGNTYPE_END)
            .map(|bytes| u16::from_le_bytes(bytes.try_into().unwrap()))
            .map_err(QuoteSignTypeError::from)
            .and_then(QuoteSignType::try_from)
    }

    /// Read the EPID Group ID
    pub fn epid_group_id(&self) -> Result<EpidGroupId, EncodingError> {
        self.try_get_slice(QUOTE_EPIDGID_START..QUOTE_EPIDGID_END)
            .and_then(EpidGroupId::try_from)
    }

    /// Read the SVN of the enclave which generated the quote
    pub fn qe_security_version(&self) -> Result<SecurityVersion, EncodingError> {
        self.try_get_slice(QUOTE_QESVN_START..QUOTE_QESVN_END)
            .map(|bytes| SecurityVersion::from_le_bytes(bytes.try_into().unwrap()))
    }

    /// Read the SVN of the provisioning certificate enclave
    pub fn pce_security_version(&self) -> Result<SecurityVersion, EncodingError> {
        self.try_get_slice(QUOTE_PCESVN_START..QUOTE_PCESVN_END)
            .map(|bytes| SecurityVersion::from_le_bytes(bytes.try_into().unwrap()))
    }

    /// Read the extended EPID Group ID
    pub fn xeid(&self) -> Result<u32, EncodingError> {
        self.try_get_slice(QUOTE_XEID_START..QUOTE_XEID_END)
            .map(|bytes| u32::from_le_bytes(bytes.try_into().unwrap()))
    }

    /// Read the basename from the quote
    pub fn basename(&self) -> Result<Basename, EncodingError> {
        self.try_get_slice(QUOTE_BASENAME_START..QUOTE_BASENAME_END)
            .and_then(Basename::try_from)
    }

    /// Read the report body from the quote
    pub fn report_body(&self) -> Result<ReportBody, EncodingError> {
        self.try_get_slice(QUOTE_REPORTBODY_START..QUOTE_REPORTBODY_END)
            .and_then(ReportBody::try_from)
    }

    /// Read the signature length from the quote (may be zero)
    pub fn signature_len(&self) -> Result<u32, EncodingError> {
        if self.0.len() < QUOTE_IAS_SIZE {
            Err(EncodingError::InvalidInputLength)
        } else if self.0.len() < QUOTE_SIGLEN_END {
            Ok(0)
        } else {
            Ok(u32::from_le_bytes(
                (&self.0[QUOTE_SIGLEN_START..QUOTE_SIGLEN_END])
                    .try_into()
                    .unwrap(),
            ))
        }
    }

    /// Read the signature from the quote.
    ///
    /// If `signature_len()` is zero, `None` will be returned, otherwise
    /// a vector with the data will be. If the data structure is corrupt,
    /// (meaning the length at `signature_len()` actually indicates more
    /// data than exists), this will also return `None` anyways.
    pub fn signature(&self) -> Option<Vec<u8>> {
        match self.signature_len() {
            Ok(0) => None,
            Ok(siglen) => {
                let sig_end = QUOTE_SIGNATURE_START + siglen as usize;
                if sig_end > self.capacity() {
                    // Our structure is invalid, we have more signature claimed
                    // than can exist... return None.
                    None
                } else {
                    Some(Vec::from(&self.0[QUOTE_SIGNATURE_START..sig_end]))
                }
            }
            Err(_) => None,
        }
    }

    /// This operation is used to verify the contents of two quotes are
    /// equal, without regard to the signature
    pub fn contents_eq(&self, other: &Self) -> bool {
        if self.0.len() < QUOTE_IAS_SIZE || other.0.len() < QUOTE_IAS_SIZE {
            false
        } else {
            self.0[..QUOTE_IAS_SIZE] == other.0[..QUOTE_IAS_SIZE]
        }
    }

    /// Verify the contents of the quote against existing data.
    ///
    /// This will verify that the enclave which generated `qe_report` also
    /// created this quote, and that the report being quoted matches the
    /// `quoted_report`.
    pub fn verify_report(
        &self,
        qe_report: &Report,
        quoted_report: &Report,
    ) -> Result<(), QuoteError> {
        let qe_body = qe_report.body();
        if self.qe_security_version()? != qe_body.security_version() {
            return Err(QuoteVerifyError::QeVersionMismatch.into());
        }

        if self.report_body()? != quoted_report.body() {
            return Err(QuoteVerifyError::QuotedReportMismatch.into());
        }

        Ok(())
    }

    /// Verify the contents of the quote match the provided values.
    pub fn verify(
        &self,
        expected_gid: Option<EpidGroupId>,
        expected_type: QuoteSignType,
        allow_debug: bool,
        expected_measurements: &[Measurement],
        expected_product_id: ProductId,
        minimum_security_version: SecurityVersion,
        expected_data: &ReportDataMask,
    ) -> Result<(), QuoteError> {
        if let Some(expected) = expected_gid {
            let current = self.epid_group_id()?;
            if current != expected {
                return Err(QuoteVerifyError::GidMismatch(current, expected).into());
            }
        }

        // Check signature type
        let sign_type = self.sign_type()?;
        if expected_type != sign_type {
            return Err(QuoteSignTypeError::Mismatch(expected_type, sign_type).into());
        }

        // Check report body
        self.report_body()?.verify(
            allow_debug,
            expected_measurements,
            expected_product_id,
            minimum_security_version,
            expected_data,
        )?;

        Ok(())
    }
}

/// The AsRef implementation for Quote will return the valid bytes.
impl AsRef<[u8]> for Quote {
    fn as_ref(&self) -> &[u8] {
        &self.0[..self.intel_size()]
    }
}

impl Debug for Quote {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        write!(
            f,
            "Quote: {{ version: {}, sign_type: {}, epid_group_id: {}, qe_svn: {}, pce_svn: {}, xeid: {}, basename: {:?}, report_body: {:?}, signature_len: {}, signature: {:?} }}",
            self.version()?, self.sign_type()?, self.epid_group_id()?, self.qe_security_version()?,
            self.pce_security_version()?, self.xeid()?, self.basename()?, self.report_body()?,
            self.signature_len()?, self. signature()
        )
    }
}

impl FromBase64 for Quote {
    type Error = QuoteError;

    /// Parse a base64-encoded string containing a quote with optional
    /// signature.
    ///
    /// In addition to parsing the general case with a variable-length signature
    ///
    /// This method will allow the "body-only" responses from IAS, which
    /// is a binary-incompatible partial structure, minus the signature length
    /// and data.
    fn from_base64(s: &str) -> Result<Self, QuoteError> {
        if s.len() % 4 != 0 {
            return Err(EncodingError::InvalidInputLength.into());
        }

        let expected_len = s.len() / 4 * 3;
        // Don't try to decode any base64 string that's larger than our size limits or
        // smaller than our minimum size
        if !(QUOTE_IAS_SIZE..=QUOTE_MINSIZE + QUOTE_SIGLEN_MAX).contains(&expected_len) {
            return Err(EncodingError::InvalidInputLength.into());
        }

        // Clamp our length to at least QUOTE_MINSIZE, and no more than
        // MINSIZE + SIGLEN_MAX, and downcast to u32
        let expected_len = max(
            min(expected_len, QUOTE_MINSIZE + QUOTE_SIGLEN_MAX),
            QUOTE_MINSIZE,
        ) as u32;

        // Create an output buffer of at least MINSIZE bytes
        let mut retval = Quote::with_capacity(expected_len)?;
        match b64decode(s.as_bytes(), retval.0.as_mut_slice()) {
            Ok(buffer) => {
                let bufferlen = buffer.len();
                if bufferlen != QUOTE_IAS_SIZE && bufferlen != retval.intel_size() {
                    // The size of the decoded bytes does not match the size embedded in the bytes,
                    // and we're not handling an IAS/no-signature quote
                    Err(EncodingError::InvalidOutputLength.into())
                } else {
                    // We adjust the "body-only" variant into a normal quote with signature_len = 0.
                    retval.0.truncate(max(bufferlen, QUOTE_MINSIZE));
                    Ok(retval)
                }
            }
            Err(e) => Err(e.into()),
        }
    }
}

impl IntelLayout for Quote {
    /// The minimum size of an sgx_quote_t
    const X86_64_CSIZE: usize = QUOTE_MINSIZE;

    /// Retrieve the size of a byte buffer required to hold our data
    fn intel_size(&self) -> usize {
        Self::X86_64_CSIZE + (self.signature_len().unwrap_or(0) as usize)
    }
}

impl ToBase64 for Quote {
    /// Create a base64-encoded string representation of the given quote
    /// and it's signature (if any)
    fn to_base64(&self, dest: &mut [u8]) -> Result<usize, usize> {
        let required_len = base64_buffer_size(self.0.len());
        if dest.len() < required_len {
            Err(required_len)
        } else {
            match b64encode(&self.0[..], dest) {
                Ok(buffer) => Ok(buffer.len()),
                Err(_e) => Err(required_len),
            }
        }
    }
}

impl ToX64 for Quote {
    fn to_x64(&self, dest: &mut [u8]) -> Result<usize, usize> {
        let required_len = self.intel_size();
        if dest.len() < required_len {
            Err(required_len)
        } else {
            dest[..required_len].copy_from_slice(&self.0[..required_len]);
            Ok(required_len)
        }
    }
}

impl<'bytes> TryFrom<&'bytes [u8]> for Quote {
    type Error = QuoteError;

    fn try_from(src: &[u8]) -> Result<Self, QuoteError> {
        if src.len() < QUOTE_MINSIZE {
            if src.len() < QUOTE_IAS_SIZE {
                // Quote is simply imcomplete
                Err(EncodingError::InvalidInputLength.into())
            } else {
                // Quotes returned from IAS in a ValidationReport are
                // actually short because they don't have a signature_len
                // or signature.
                let mut data = vec![0u8; QUOTE_MINSIZE];
                data[..QUOTE_IAS_SIZE].copy_from_slice(&src[..QUOTE_IAS_SIZE]);
                // signature_len bytes are already zeroed
                Ok(Self(data))
            }
        } else {
            let siglen = u32::from_le_bytes(
                (&src[QUOTE_SIGLEN_START..QUOTE_SIGLEN_END])
                    .try_into()
                    .unwrap(),
            ) as usize;
            if siglen > QUOTE_SIGLEN_MAX || siglen + QUOTE_MINSIZE > src.len() {
                Err(EncodingError::InvalidInputLength.into())
            } else {
                Ok(Self(Vec::from(&src[..(QUOTE_MINSIZE + siglen)])))
            }
        }
    }
}

impl TryFrom<Vec<u8>> for Quote {
    type Error = QuoteError;

    fn try_from(src: Vec<u8>) -> Result<Self, QuoteError> {
        Self::try_from(&src[..])
    }
}

#[cfg(test)]
mod test {
    extern crate std;

    use super::*;
    use std::format;

    const QUOTE_OK: &str = include_str!("../data/test/quote_ok.txt");
    const QUOTE_OK_STR: &str = include_str!("../data/test/quote_ok_str.txt");

    const CONTENTS_EQ_TO_IAS: &str = include_str!("../data/test/contents_eq/to_ias.txt");
    const CONTENTS_EQ_FROM_IAS: &str = include_str!("../data/test/contents_eq/from_ias.txt");

    /// Test that the contents_eq method can properly compare full quote
    /// contents with IAS-truncated contents.
    #[test]
    fn contents_eq() {
        let to_ias = Quote::from_base64(CONTENTS_EQ_TO_IAS)
            .expect("Could not create quote from base64 string.");
        let from_ias = Quote::from_base64(CONTENTS_EQ_FROM_IAS)
            .expect("Could not create quote from base64 string.");
        assert!(to_ias.contents_eq(&from_ias));
    }

    /// Test the base64 decoding fails on truncated input
    #[test]
    fn bad_base64() {
        let short_quote = &QUOTE_OK[..(QUOTE_OK.len() - 1)];
        assert_eq!(
            Quote::from_base64(short_quote),
            Err(QuoteError::Encoding(EncodingError::InvalidInputLength))
        );
    }

    /// Round-trip test through serde
    #[test]
    fn serde_round_trip() {
        let quote =
            Quote::from_base64(QUOTE_OK).expect("Could not create quote from base64 string");
        let serialized = bincode::serialize(&quote).expect("Could not serialize quote.");
        let quote2: Quote =
            bincode::deserialize(&serialized).expect("Could not deserialize quote.");
        assert_eq!(quote, quote2);
    }

    /// Test that trying to create an undersize quote fails
    #[test]
    fn bad_capacity() {
        let len =
            u32::try_from(QUOTE_MINSIZE - 1).expect("Could not downcast QUOTE_MINSIZE to u32");
        assert_eq!(Quote::with_capacity(len), Err(QuoteError::InvalidSize(len)));
    }

    /// Test that the debug format is unchanged.
    ///
    /// This also ensures our offsets are still in the right place.
    #[test]
    fn debug_fmt() {
        let quote =
            Quote::from_base64(QUOTE_OK).expect("Could not create quote from base64 string");
        let debug_str = format!("{:?}", &quote);
        assert_eq!(QUOTE_OK_STR.trim(), debug_str.trim());
    }

    /// Test that the version method fails when the vector contents are too
    /// short.
    #[test]
    fn version_err() {
        assert_eq!(
            Err(EncodingError::InvalidInputLength),
            Quote(Vec::default()).version()
        );
    }

    /// Test that the sign_type method fails when the vector contents are too
    /// short.
    #[test]
    fn sign_type_err_len() {
        assert_eq!(
            Err(QuoteSignTypeError::Encoding(
                EncodingError::InvalidInputLength
            )),
            Quote(Vec::default()).sign_type()
        );
    }

    /// Test that the epid_group_id() method fails when the vector contents are
    /// too short.
    #[test]
    fn epid_group_id_err() {
        assert_eq!(
            Err(EncodingError::InvalidInputLength),
            Quote(Vec::default()).epid_group_id()
        );
    }

    /// Test that the qe_security_version() method fails when the vector
    /// contents are too short.
    #[test]
    fn qe_security_version_err() {
        assert_eq!(
            Err(EncodingError::InvalidInputLength),
            Quote(Vec::default()).qe_security_version()
        );
    }

    /// Test that the pce_security_version() method fails when the vector
    /// contents are too short.
    #[test]
    fn pce_security_version_err() {
        assert_eq!(
            Err(EncodingError::InvalidInputLength),
            Quote(Vec::default()).pce_security_version()
        );
    }

    /// Test that the xeid() method fails when the vector contents are too
    /// short.
    #[test]
    fn xeid_err() {
        assert_eq!(
            Err(EncodingError::InvalidInputLength),
            Quote(Vec::default()).xeid()
        );
    }

    /// Test that the basename() method fails when the vector contents are too
    /// short.
    #[test]
    fn basename_err() {
        assert_eq!(
            Err(EncodingError::InvalidInputLength),
            Quote(Vec::default()).basename()
        );
    }

    /// Test that the report_body() method fails when the vector contents are
    /// too short.
    #[test]
    fn report_body_err() {
        assert_eq!(
            Err(EncodingError::InvalidInputLength),
            Quote(Vec::default()).report_body()
        );
    }

    /// Test that the signature_len() method fails when the vector contents are
    /// too short.
    #[test]
    fn signature_len_err() {
        assert_eq!(
            Err(EncodingError::InvalidInputLength),
            Quote(Vec::default()).signature_len()
        );
    }
}
