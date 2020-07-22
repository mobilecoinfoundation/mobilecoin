// Copyright (c) 2018-2020 MobileCoin Inc.

//! Miscellaneous attributes structure

/// A mask of select bits, currently this must be initialized to zero.
pub use mc_sgx_core_types_sys::sgx_misc_select_t as MiscSelect;

/// The size of a [MiscSelect], in bytes.
pub use mc_util_encodings::INTEL_U32_SIZE as MISC_SELECT_SIZE;

/// The size of the x64 representation of a [MiscAttribute], in bytes.
///
/// As the underlying [`sgx_misc_attribute_t`] is 20 unpacked bytes, this size
/// includes 4 bytes of padding.
pub const MISC_ATTRIBUTE_SIZE: usize = SELECT_END + INTEL_U32_SIZE;

use crate::{
    _macros::FfiWrapper,
    attributes::{Attributes, ATTRIBUTES_SIZE},
    impl_ffi_wrapper_base,
};
use core::{
    cmp::Ordering,
    convert::{TryFrom, TryInto},
    fmt::{Debug, Display, Formatter, Result as FmtResult},
    hash::{Hash, Hasher},
};
use hex::FromHex;
use mc_sgx_core_types_sys::sgx_misc_attribute_t;
use mc_util_encodings::{Error as EncodingError, FromBase64, INTEL_U32_SIZE};
#[cfg(feature = "use_prost")]
use mc_util_repr_bytes::derive_prost_message_from_repr_bytes;
#[cfg(feature = "use_serde")]
use mc_util_repr_bytes::derive_serde_from_repr_bytes;
use mc_util_repr_bytes::{
    derive_into_vec_from_repr_bytes, derive_try_from_slice_from_repr_bytes, typenum::U32,
    GenericArray, ReprBytes,
};

const ATTRIBUTES_START: usize = 0;
const ATTRIBUTES_END: usize = ATTRIBUTES_START + ATTRIBUTES_SIZE;
const SELECT_START: usize = ATTRIBUTES_END;
const SELECT_END: usize = ATTRIBUTES_END + MISC_SELECT_SIZE;

/// Enclave `misc_select` and attributes definition structure.
#[derive(Default)]
#[repr(transparent)]
pub struct MiscAttribute(sgx_misc_attribute_t);

impl_ffi_wrapper_base! {
    MiscAttribute, sgx_misc_attribute_t;
}

derive_try_from_slice_from_repr_bytes!(MiscAttribute);
derive_into_vec_from_repr_bytes!(MiscAttribute);

#[cfg(feature = "use_prost")]
derive_prost_message_from_repr_bytes!(MiscAttribute);

#[cfg(feature = "use_serde")]
derive_serde_from_repr_bytes!(MiscAttribute);

impl MiscAttribute {
    /// Retrieve the attributes
    pub fn attributes(&self) -> Attributes {
        Attributes::try_from(&self.0.secs_attr).expect("Invalid attributes stored")
    }

    /// Retrieve the attribute selection mask
    pub fn misc_select(&self) -> MiscSelect {
        self.0.misc_select
    }
}

impl Debug for MiscAttribute {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        write!(
            f,
            "MiscAttribute: {{ attributes: {:?}, misc_select: {:?} }}",
            self.attributes(),
            self.misc_select()
        )
    }
}

impl Display for MiscAttribute {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        write!(
            f,
            "Miscellaneous Enclave Attributes: {}/{}",
            self.attributes(),
            self.misc_select()
        )
    }
}

impl FfiWrapper<sgx_misc_attribute_t> for MiscAttribute {}

impl FromBase64 for MiscAttribute {
    type Error = EncodingError;

    fn from_base64(src: &str) -> Result<Self, Self::Error> {
        let mut bytes = GenericArray::default();
        if base64::decode_config_slice(src, base64::STANDARD, bytes.as_mut_slice())?
            != MISC_ATTRIBUTE_SIZE
        {
            return Err(EncodingError::InvalidInput);
        }
        Self::from_bytes(&bytes)
    }
}

impl FromHex for MiscAttribute {
    type Error = EncodingError;

    fn from_hex<T: AsRef<[u8]>>(hex: T) -> Result<Self, Self::Error> {
        let mut bytes = GenericArray::default();
        hex::decode_to_slice(hex, bytes.as_mut_slice())?;
        Self::from_bytes(&bytes)
    }
}

impl Hash for MiscAttribute {
    fn hash<H: Hasher>(&self, state: &mut H) {
        "MiscAttribute".hash(state);
        self.attributes().hash(state);
        self.misc_select().hash(state);
    }
}

impl Ord for MiscAttribute {
    fn cmp(&self, other: &Self) -> Ordering {
        match self.attributes().cmp(&other.attributes()) {
            Ordering::Equal => self.misc_select().cmp(&other.misc_select()),
            other => other,
        }
    }
}

impl PartialEq for MiscAttribute {
    fn eq(&self, other: &Self) -> bool {
        self.attributes() == other.attributes() && self.misc_select() == other.misc_select()
    }
}

impl PartialOrd for MiscAttribute {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl ReprBytes for MiscAttribute {
    type Size = U32;
    type Error = EncodingError;

    fn from_bytes(src: &GenericArray<u8, Self::Size>) -> Result<Self, Self::Error> {
        let mut inner = sgx_misc_attribute_t::default();
        inner.secs_attr = Attributes::try_from(&src[ATTRIBUTES_START..ATTRIBUTES_END])?.into();
        inner.misc_select = u32::from_le_bytes(src[SELECT_START..SELECT_END].try_into()?);
        Ok(Self(inner))
    }

    fn to_bytes(&self) -> GenericArray<u8, Self::Size> {
        let mut retval = GenericArray::default();
        retval.copy_from_slice(self.attributes().to_bytes().as_slice());
        retval[SELECT_START..SELECT_END].copy_from_slice(&self.misc_select().to_le_bytes());
        retval
    }
}

impl TryFrom<&sgx_misc_attribute_t> for MiscAttribute {
    type Error = EncodingError;

    fn try_from(src: &sgx_misc_attribute_t) -> Result<Self, Self::Error> {
        Ok(Self(sgx_misc_attribute_t {
            secs_attr: Attributes::try_from(&src.secs_attr)?.into(),
            misc_select: src.misc_select,
        }))
    }
}
