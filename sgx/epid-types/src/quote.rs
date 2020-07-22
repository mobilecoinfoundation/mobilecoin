// Copyright (c) 2018-2020 MobileCoin Inc.

//! SGX Quote wrapper

use alloc::{format, vec};

use crate::{
    basename::{Basename, BASENAME_SIZE},
    epid_group_id::{EpidGroupId, EPID_GROUP_ID_SIZE},
    quote_sign::QuoteSign,
};
use alloc::{alloc::Layout, string::ToString, vec::Vec};
#[cfg(feature = "use_prost")]
use bytes::{Buf, BufMut};
use core::{
    convert::{TryFrom, TryInto},
    fmt::{Debug, Display, Formatter, Result as FmtResult},
    ops::Range,
};
use hex_fmt::HexFmt;
use mc_sgx_core_types::{
    AttributeFlags, AttributeXfeatures, ConfigId, CpuSecurityVersion, FamilyId, MrEnclave,
    MrSigner, ReportBody, ReportData, SecurityVersion, REPORT_BODY_SIZE, SECURITY_VERSION_SIZE,
};
use mc_sgx_core_types_sys::{sgx_attributes_t, sgx_report_body_t};
use mc_sgx_epid_types_sys::sgx_quote_t;
use mc_util_encodings::{
    Error as EncodingError, FromX64, IntelLayout, ToX64, INTEL_U16_SIZE, INTEL_U32_SIZE,
};
use mc_util_repr_bytes::ReprBytes;
#[cfg(feature = "use_prost")]
use prost::{
    encoding::{self, DecodeContext, WireType},
    DecodeError, Message,
};
#[cfg(feature = "use_serde")]
use serde::{
    de::{Error as DeserializeError, SeqAccess, Visitor},
    Deserialize, Deserializer, Serialize, Serializer,
};

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
/// A quoting enclave will be given a [`Report`](mc_sgx_core_types::Report) from the enclave under
/// examination, and it will verify the report is from the same platform, and quote the report in
/// its response. This quote will be returned to the requester, who will transmit it to IAS for
/// further verification.
///
/// Internally, this struct contains a vector of bytes, with an internal object that is aligned to
/// the size of [`sgx_quote_t`](mc_sgx_epid_types_sys::sgx_quote_t). We use the unsafe
/// [`core::slice::align_to()`] method to reference the bytes in native order at the
/// proper alignment.
#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(transparent)]
pub struct Quote(Vec<u8>);

impl Quote {
    /// Allocate a new quote structure with the given capacity.
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
        inner.version
    }

    /// Read the signature type
    pub fn sign_type(&self) -> QuoteSign {
        let inner: &sgx_quote_t = self.as_ref();
        QuoteSign::try_from(inner.sign_type).expect("Invalid quote sign found")
    }

    /// Read the EPID Group ID
    pub fn epid_group_id(&self) -> EpidGroupId {
        let inner: &sgx_quote_t = self.as_ref();
        EpidGroupId::from(&inner.epid_group_id)
    }

    /// Read the SVN of the enclave which generated the quote
    pub fn qe_security_version(&self) -> SecurityVersion {
        let inner: &sgx_quote_t = self.as_ref();
        inner.qe_svn
    }

    /// Read the SVN of the provisioning certificate enclave
    pub fn pce_security_version(&self) -> SecurityVersion {
        let inner: &sgx_quote_t = self.as_ref();
        inner.pce_svn
    }

    /// Read the extended EPID Group ID
    pub fn xeid(&self) -> u32 {
        let inner: &sgx_quote_t = self.as_ref();
        inner.xeid
    }

    /// Read the basename from the quote
    pub fn basename(&self) -> Basename {
        let inner: &sgx_quote_t = self.as_ref();
        Basename::from(&inner.basename)
    }

    /// Read the report body from the quote
    pub fn report_body(&self) -> ReportBody {
        let inner: &sgx_quote_t = self.as_ref();

        let mut retval = ReportBody::default();
        let body: &mut sgx_report_body_t = retval.as_mut();

        body.cpu_svn = CpuSecurityVersion::from(&inner.report_body.cpu_svn).into();
        body.misc_select = inner.report_body.misc_select;
        body.isv_ext_prod_id = inner.report_body.isv_ext_prod_id;
        body.attributes = sgx_attributes_t {
            flags: AttributeFlags::from_bits(inner.report_body.attributes.flags)
                .expect("Invalid attribute flags found")
                .bits(),
            xfrm: AttributeXfeatures::from_bits(inner.report_body.attributes.xfrm)
                .expect("Invalid attribute X features")
                .bits(),
        };
        body.mr_enclave = MrEnclave::from(&inner.report_body.mr_enclave).into();
        body.mr_signer = MrSigner::from(&inner.report_body.mr_signer).into();
        body.config_id = ConfigId::from(&inner.report_body.config_id).into();
        body.isv_prod_id = inner.report_body.isv_prod_id;
        body.isv_svn = inner.report_body.isv_svn;
        body.config_svn = inner.report_body.config_svn;
        body.isv_family_id = FamilyId::from(&inner.report_body.isv_family_id).into();
        body.report_data = ReportData::from(&inner.report_body.report_data).into();

        retval
    }

    /// Read the signature length from the quote (may be zero)
    pub fn signature_len(&self) -> u32 {
        let inner: &sgx_quote_t = self.as_ref();
        u32::from_le(inner.signature_len)
    }

    /// Retrieve a read-only slice of the signature, if one exists
    pub fn signature(&self) -> Option<&[u8]> {
        let siglen = self.signature_len();
        if siglen == 0 {
            return None;
        }

        Some(self.aligned_slice(SIGNATURE_START, siglen as usize))
    }
}

impl AsRef<[u8]> for Quote {
    fn as_ref(&self) -> &[u8] {
        self.aligned_slice(0, QUOTE_MIN_SIZE + self.signature_len() as usize)
    }
}

impl AsRef<sgx_quote_t> for Quote {
    fn as_ref(&self) -> &sgx_quote_t {
        let (_head, body, _tail) = unsafe { self.0.align_to::<sgx_quote_t>() };
        &body[0]
    }
}

impl AsMut<[u8]> for Quote {
    fn as_mut(&mut self) -> &mut [u8] {
        self.aligned_mut(0, QUOTE_MIN_SIZE + self.signature_len() as usize)
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

#[cfg(feature = "use_serde")]
impl<'de> Deserialize<'de> for Quote {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct ByteVisitor;

        impl<'de> Visitor<'de> for ByteVisitor {
            type Value = Quote;

            fn expecting(&self, f: &mut Formatter) -> FmtResult {
                write!(f, "byte contents of Quote")
            }

            fn visit_bytes<E: DeserializeError>(self, value: &[u8]) -> Result<Self::Value, E> {
                Self::Value::from_x64(value)
                    .map_err(|err| E::custom(format!("Could not parse Quote: {}", err)))
            }

            fn visit_borrowed_bytes<E: DeserializeError>(
                self,
                value: &'de [u8],
            ) -> Result<Self::Value, E> {
                Self::Value::from_x64(value)
                    .map_err(|err| E::custom(format!("Could not parse Quote: {}", err)))
            }

            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A::Error: DeserializeError,
            {
                let mut bytes = Vec::<u8>::with_capacity(seq.size_hint().unwrap_or(1024usize));
                while let Some(byte) = seq.next_element()? {
                    bytes.push(byte)
                }

                Self::Value::from_x64(bytes.as_slice())
                    .map_err(|err| A::Error::custom(format!("Could not parse Quote: {}", err)))
            }
        }

        struct NewtypeVisitor;

        impl<'de> Visitor<'de> for NewtypeVisitor {
            type Value = Quote;

            fn expecting(&self, f: &mut Formatter) -> FmtResult {
                write!(f, "struct Quote")
            }

            fn visit_newtype_struct<D: Deserializer<'de>>(
                self,
                deserializer: D,
            ) -> Result<Self::Value, D::Error> {
                deserializer.deserialize_bytes(ByteVisitor)
            }
        }

        deserializer.deserialize_newtype_struct("Quote", NewtypeVisitor)
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

impl FromX64 for Quote {
    type Error = EncodingError;

    fn from_x64(src: &[u8]) -> Result<Self, Self::Error> {
        let src_len = src.len();
        if src_len < QUOTE_MIN_SIZE {
            return Err(EncodingError::InvalidInputLength);
        }

        let signature_len = u32::from_le_bytes(
            src[SIGLEN_START..SIGLEN_END]
                .try_into()
                .expect("Could not convert siglen into 4 byte array"),
        ) as usize;

        if signature_len > QUOTE_SIGLEN_MAX {
            return Err(EncodingError::InvalidInput);
        }

        if src_len != QUOTE_MIN_SIZE + signature_len {
            return Err(EncodingError::InvalidInputLength);
        }

        // Fallible member parsing (fail before we alloc)
        let sign_type = QuoteSign::try_from(u16::from_le_bytes(
            src[SIGN_TYPE_START..SIGN_TYPE_END]
                .try_into()
                .expect("Invalid length of quote sign type"),
        ))
        .map_err(|_e| EncodingError::InvalidInput)?;

        let epid_group_id = EpidGroupId::try_from(&src[EPID_GROUP_ID_START..EPID_GROUP_ID_END])
            .map_err(|_e| EncodingError::InvalidInput)?;

        let basename = Basename::try_from(&src[BASENAME_START..BASENAME_END])
            .map_err(|_e| EncodingError::InvalidInput)?;

        let report_body = ReportBody::try_from(&src[REPORT_BODY_START..REPORT_BODY_END])
            .map_err(|_e| EncodingError::InvalidInput)?;

        let mut retval =
            Self::with_capacity(src_len).map_err(|_e| EncodingError::InvalidInputLength)?;

        let inner: &mut sgx_quote_t = retval.as_mut();
        inner.version = u16::from_le_bytes(
            src[VERSION_START..VERSION_END]
                .try_into()
                .expect("Invalid length of version"),
        );
        inner.sign_type = sign_type.into();
        inner.epid_group_id = epid_group_id.into();
        inner.qe_svn = u16::from_le_bytes(
            src[QE_SVN_START..QE_SVN_END]
                .try_into()
                .expect("Invalid length of QE security version"),
        );
        inner.pce_svn = u16::from_le_bytes(
            src[PCE_SVN_START..PCE_SVN_END]
                .try_into()
                .expect("Invalid length of PCE security version"),
        );
        inner.xeid = u32::from_le_bytes(
            src[XEID_START..XEID_END]
                .try_into()
                .expect("Invalid length of XEID"),
        );
        inner.basename = basename.into();
        inner.report_body = report_body.into();
        inner.signature_len = signature_len as u32;

        retval
            .aligned_mut(SIGNATURE_START, signature_len)
            .copy_from_slice(&src[SIGNATURE_START..SIGNATURE_START + signature_len]);

        Ok(retval)
    }
}

impl IntelLayout for Quote {
    const X86_64_CSIZE: usize = QUOTE_MIN_SIZE + QUOTE_SIGLEN_MAX;

    fn intel_size(&self) -> usize {
        QUOTE_MIN_SIZE + self.signature_len() as usize
    }
}

/// A custom implementation of protobuf serialization as a message with a single opaque byte
/// structure.
///
/// Unfortunately we can't just use the ReprBytes macros here, because our data is variable length.
#[cfg(feature = "use_prost")]
impl Message for Quote {
    fn encode_raw<B>(&self, buf: &mut B)
    where
        B: BufMut,
    {
        encoding::bytes::encode(1, &self.to_x64_vec(), buf)
    }

    fn merge_field<B>(
        &mut self,
        tag: u32,
        wire_type: WireType,
        buf: &mut B,
        ctx: DecodeContext,
    ) -> Result<(), DecodeError>
    where
        B: Buf,
    {
        if tag == 1 {
            let mut vbuf = Vec::new();
            encoding::bytes::merge(wire_type, &mut vbuf, buf, ctx)?;
            *self = Self::from_x64(&vbuf[..]).map_err(|e| DecodeError::new(e.to_string()))?;
            Ok(())
        } else {
            encoding::skip_field(wire_type, tag, buf, ctx)
        }
    }

    fn encoded_len(&self) -> usize {
        self.intel_size()
    }

    fn clear(&mut self) {
        self.0.clear();
    }
}

#[cfg(feature = "use_serde")]
impl Serialize for Quote {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let bytes = self.to_x64_vec();
        serializer.serialize_newtype_struct("Quote", &bytes[..])
    }
}

impl ToX64 for Quote {
    fn to_x64(&self, dest: &mut [u8]) -> Result<usize, usize> {
        let signature_len = self.signature_len();
        let required_len = signature_len as usize + QUOTE_MIN_SIZE;
        let dest_len = dest.len();
        if dest_len < required_len {
            return Err(required_len);
        }

        dest[VERSION_START..VERSION_END].copy_from_slice(&self.version().to_le_bytes());
        let value: u16 = self.sign_type().into();
        dest[SIGN_TYPE_START..SIGN_TYPE_END].copy_from_slice(&value.to_le_bytes());

        dest[EPID_GROUP_ID_START..EPID_GROUP_ID_END].copy_from_slice(self.epid_group_id().as_ref());

        dest[QE_SVN_START..QE_SVN_END].copy_from_slice(&self.qe_security_version().to_le_bytes());
        dest[PCE_SVN_START..PCE_SVN_END]
            .copy_from_slice(&self.pce_security_version().to_le_bytes());
        dest[XEID_START..XEID_END].copy_from_slice(&self.xeid().to_le_bytes());

        dest[BASENAME_START..BASENAME_END].copy_from_slice(self.basename().as_ref());
        dest[REPORT_BODY_START..REPORT_BODY_END]
            .copy_from_slice(self.report_body().to_bytes().as_slice());
        dest[SIGLEN_START..SIGLEN_END].copy_from_slice(&signature_len.to_le_bytes());

        if let Some(sigslice) = self.signature() {
            dest[SIGNATURE_START..(SIGNATURE_START + sigslice.len())].copy_from_slice(sigslice);
        }

        Ok(required_len)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    #[cfg(feature = "use_serde")]
    use bincode::{deserialize, serialize};

    const QUOTE: &[u8] = include_bytes!("test/quote_ok.bin");

    #[cfg(feature = "use_serde")]
    #[test]
    fn serde() {
        let quote = Quote::from_x64(QUOTE).expect("Could not create quote from x64.");
        let serialized = serialize(&quote).expect("Could not serialize quote.");
        let quote2 = deserialize::<Quote>(&serialized).expect("Could not deserialize quote.");

        eprintln!("quote1({}) vs. quote2({})", quote.0.len(), quote2.0.len());
        for i in 0..(quote.0.len()) {
            if quote.0[i] != quote2.0[i] {
                eprintln!("Byte difference found at {}", i);
            }
        }
        assert_eq!(quote, quote2);
    }
}
