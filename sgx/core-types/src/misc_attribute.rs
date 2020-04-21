// Copyright (c) 2018-2020 MobileCoin Inc.

//! Miscellaneous attributes structure

/// A mask of select bits, currently this must be initialized to zero.
pub use mc_sgx_core_types_sys::sgx_misc_select_t as MiscSelect;

/// The size of a [MiscSelect], in bytes.
pub use mc_encodings::INTEL_U32_SIZE as MISC_SELECT_SIZE;

use crate::{
    _macros::FfiWrapper,
    attributes::{Attributes, ATTRIBUTES_SIZE},
    impl_ffi_wrapper_base, impl_serialize_to_x64,
};
use core::{
    cmp::Ordering,
    convert::TryInto,
    fmt::{Debug, Display, Formatter, Result as FmtResult},
    hash::{Hash, Hasher},
};
use mc_encodings::{Error as EncodingError, FromX64, ToX64, INTEL_U32_SIZE};
use mc_sgx_core_types_sys::sgx_misc_attribute_t;

const ATTRIBUTES_START: usize = 0;
const ATTRIBUTES_END: usize = ATTRIBUTES_START + ATTRIBUTES_SIZE;
const SELECT_START: usize = ATTRIBUTES_END;
const SELECT_END: usize = ATTRIBUTES_END + MISC_SELECT_SIZE;

/// The size of the x64 representation of a [MiscAttribute], in bytes.
pub const MISC_ATTRIBUTE_SIZE: usize = SELECT_END + INTEL_U32_SIZE;

/// Enclave `misc_select` and attributes definition structure.
#[derive(Default)]
#[repr(transparent)]
pub struct MiscAttribute(sgx_misc_attribute_t);

impl_ffi_wrapper_base! {
    MiscAttribute, sgx_misc_attribute_t, MISC_ATTRIBUTE_SIZE;
}

impl_serialize_to_x64! {
    MiscAttribute, MISC_ATTRIBUTE_SIZE;
}

impl MiscAttribute {
    /// Retrieve the attributes
    pub fn attributes(&self) -> Attributes {
        Attributes::from(&self.0.secs_attr)
    }

    /// Retrieve the attribute selection mask
    pub fn misc_select(&self) -> MiscSelect {
        self.0.misc_select.into()
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

impl From<&sgx_misc_attribute_t> for MiscAttribute {
    fn from(src: &sgx_misc_attribute_t) -> Self {
        Self(sgx_misc_attribute_t {
            secs_attr: Attributes::from(&src.secs_attr).into(),
            misc_select: src.misc_select,
        })
    }
}

impl Hash for MiscAttribute {
    fn hash<H: Hasher>(&self, hasher: &mut H) {
        self.attributes().hash(hasher);
        self.misc_select().hash(hasher);
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

impl ToX64 for MiscAttribute {
    fn to_x64(&self, dest: &mut [u8]) -> Result<usize, usize> {
        if dest.len() < MISC_ATTRIBUTE_SIZE {
            Err(MISC_ATTRIBUTE_SIZE)
        } else {
            self.attributes()
                .to_x64(&mut dest[ATTRIBUTES_START..ATTRIBUTES_END])
                .expect("Improper inner serialization of secs_attr");
            dest[SELECT_START..SELECT_END].copy_from_slice(&self.misc_select().to_le_bytes());
            Ok(MISC_ATTRIBUTE_SIZE)
        }
    }
}

impl FromX64 for MiscAttribute {
    type Error = EncodingError;

    fn from_x64(src: &[u8]) -> Result<Self, Self::Error> {
        if src.len() < MISC_ATTRIBUTE_SIZE {
            return Err(EncodingError::InvalidInputLength);
        }

        Ok(Self(sgx_misc_attribute_t {
            secs_attr: Attributes::from_x64(&src[ATTRIBUTES_START..ATTRIBUTES_END])?.into(),
            misc_select: MiscSelect::from_le_bytes(
                (&src[SELECT_START..SELECT_END])
                    .try_into()
                    .expect("Could not get bytes for misc_select value"),
            ),
        }))
    }
}

impl FfiWrapper<sgx_misc_attribute_t> for MiscAttribute {}
