// Copyright (c) 2018-2020 MobileCoin Inc.

//! IAS Quote Structure
//!
//! This is the "special" version of sgx_quote_t that's returned by IAS (it does not contain the
//! signature_len unsigned or variable-length signature fields) but not actually provided anywhere
//! in the SGX headers. We skip the byte representation because this is never used during FFI, in
//! favor of parsing it directly into the rusty types that sit above FFI types.

#[cfg(feature = "use_prost")]
use bytes::{Buf, BufMut};
use core::convert::{TryFrom, TryInto};
use mc_sgx_core_types::{ReportBody, SecurityVersion, REPORT_BODY_SIZE, SECURITY_VERSION_SIZE};
use mc_sgx_epid_types::{
    Basename, EpidGroupId, Quote as SgxQuote, QuoteSign, BASENAME_SIZE, EPID_GROUP_ID_SIZE,
};
use mc_util_encodings::{Error as EncodingError, FromBase64, INTEL_U16_SIZE, INTEL_U32_SIZE};
use mc_util_repr_bytes::{typenum::U432, GenericArray, ReprBytes};
#[cfg(feature = "use_prost")]
use prost::{
    encoding::{self, message, uint32, DecodeContext, WireType},
    DecodeError, Message,
};
#[cfg(feature = "use_serde")]
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

/// The quote structure returned by IAS.
///
/// This structure is nearly identical to the [`Quote`](mc_sgx_epid_types::Quote)
/// structure, but does not contain the variable-length signature and it's length.
#[cfg_attr(feature = "use_serde", derive(Deserialize, Serialize))]
#[derive(Clone, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Quote {
    /// The quote version
    // prost(uint32, required, tag = "1")
    pub version: u16,

    /// The quote signature type (linkable vs. unlinkable).
    // prost(enumeration = "QuoteSign", required, tag = "2")
    pub sign_type: QuoteSign,

    /// The EPID Group ID of the platform.
    // prost(message, required, tag = "3")
    pub epid_group_id: EpidGroupId,

    /// The security version of the original quoting enclave.
    // prost(uint32, required, tag = "4")
    pub qe_svn: SecurityVersion,

    /// The security version of the provisioning certificate enclave.
    // prost(uint32, required, tag = "5")
    pub pce_svn: SecurityVersion,

    /// The XEID
    // prost(uint32, required, tag = "6")
    pub xeid: u32,

    /// The basename
    // prost(message, required, tag = "7")
    pub basename: Basename,

    /// The quoted report body
    // prost(message, required, tag = "8")
    pub report_body: ReportBody,
}

impl FromBase64 for Quote {
    type Error = EncodingError;

    fn from_base64(src: &str) -> Result<Self, Self::Error> {
        // We decode base64 into this buffer, then FromX64 the contents into our components.
        let mut buffer = GenericArray::default();
        base64::decode_config_slice(src, base64::STANDARD, buffer.as_mut_slice())?;

        Self::from_bytes(&buffer)
    }
}

const TAG_VERSION: u32 = 1;
const TAG_SIGN_TYPE: u32 = 2;
const TAG_EPID_GROUP_ID: u32 = 3;
const TAG_QE_SVN: u32 = 4;
const TAG_PCE_SVN: u32 = 5;
const TAG_XEID: u32 = 6;
const TAG_BASENAME: u32 = 7;
const TAG_REPORT_BODY: u32 = 8;

/// An implementation of Message for IAS Quote structures
#[cfg(feature = "use_prost")]
impl Message for Quote {
    fn encode_raw<B>(&self, buf: &mut B)
    where
        B: BufMut,
        Self: Sized,
    {
        uint32::encode(TAG_VERSION, &(self.version as u32), buf);

        encoding::encode_key(TAG_SIGN_TYPE, WireType::Varint, buf);
        encoding::encode_varint(self.sign_type as u64, buf);

        message::encode(TAG_EPID_GROUP_ID, &self.epid_group_id, buf);
        uint32::encode(TAG_QE_SVN, &(self.qe_svn as u32), buf);
        uint32::encode(TAG_PCE_SVN, &(self.pce_svn as u32), buf);
        uint32::encode(TAG_XEID, &self.xeid, buf);
        message::encode(TAG_BASENAME, &self.basename, buf);
        message::encode(TAG_REPORT_BODY, &self.report_body, buf);
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
        Self: Sized,
    {
        match tag {
            TAG_VERSION => {
                self.version = {
                    let mut value = 0u32;
                    uint32::merge(wire_type, &mut value, buf, ctx)?;
                    u16::try_from(value).map_err(|_e| DecodeError::new("version not u16"))?
                }
            }
            TAG_SIGN_TYPE => {
                self.sign_type = QuoteSign::try_from(encoding::decode_varint(buf)?)
                    .map_err(|_e| DecodeError::new("quote_sign not a valid enum value"))?
            }
            TAG_EPID_GROUP_ID => message::merge(wire_type, &mut self.epid_group_id, buf, ctx)?,
            TAG_QE_SVN => {
                self.qe_svn = {
                    let mut value = 0u32;
                    uint32::merge(wire_type, &mut value, buf, ctx)?;
                    u16::try_from(value).map_err(|_e| DecodeError::new("qe_svn not u16"))?
                }
            }
            TAG_PCE_SVN => {
                self.pce_svn = {
                    let mut value = 0u32;
                    uint32::merge(wire_type, &mut value, buf, ctx)?;
                    u16::try_from(value).map_err(|_e| DecodeError::new("pce_svn not u16"))?
                }
            }
            TAG_XEID => uint32::merge(wire_type, &mut self.xeid, buf, ctx)?,
            TAG_BASENAME => message::merge(wire_type, &mut self.basename, buf, ctx)?,
            TAG_REPORT_BODY => message::merge(wire_type, &mut self.report_body, buf, ctx)?,
            other => encoding::skip_field(wire_type, other, buf, ctx)?,
        }
        Ok(())
    }

    fn encoded_len(&self) -> usize {
        uint32::encoded_len(TAG_VERSION, &(self.version as u32))
            + encoding::key_len(TAG_SIGN_TYPE)
            + encoding::encoded_len_varint(self.sign_type as u64)
            + message::encoded_len(TAG_EPID_GROUP_ID, &self.epid_group_id)
            + uint32::encoded_len(TAG_QE_SVN, &(self.qe_svn as u32))
            + uint32::encoded_len(TAG_PCE_SVN, &(self.pce_svn as u32))
            + uint32::encoded_len(TAG_XEID, &self.xeid)
            + message::encoded_len(TAG_BASENAME, &self.basename)
            + message::encoded_len(TAG_REPORT_BODY, &self.report_body)
    }

    fn clear(&mut self) {
        *self = Self::default();
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

impl ReprBytes for Quote {
    type Size = U432;
    type Error = EncodingError;

    fn from_bytes(src: &GenericArray<u8, Self::Size>) -> Result<Self, Self::Error> {
        let version = u16::from_le_bytes(
            src[VERSION_START..VERSION_END]
                .try_into()
                .expect("Invalid size of version field"),
        );
        let sign_type = QuoteSign::try_from(u16::from_le_bytes(
            src[SIGN_TYPE_START..SIGN_TYPE_END]
                .try_into()
                .expect("Invalid size of sign type field"),
        ))?;
        let epid_group_id = EpidGroupId::try_from(&src[EPID_GROUP_ID_START..EPID_GROUP_ID_END])?;
        let qe_svn = SecurityVersion::from_le_bytes(
            src[QE_SVN_START..QE_SVN_END]
                .try_into()
                .expect("Invalid size of QE SVN field"),
        );
        let pce_svn = SecurityVersion::from_le_bytes(
            src[PCE_SVN_START..PCE_SVN_END]
                .try_into()
                .expect("Invalid size of PCE SVN field"),
        );
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
        retval[SIGN_TYPE_START..SIGN_TYPE_END]
            .copy_from_slice(self.sign_type.to_bytes().as_slice());
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
