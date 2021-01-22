// Copyright (c) 2018-2021 The MobileCoin Foundation

//! This module contains the wrapper type for an sgx_attributes_t

use crate::{impl_sgx_wrapper_reqs, traits::SgxWrapperType};
use alloc::vec::Vec;
use core::{
    cmp::Ordering,
    convert::{TryFrom, TryInto},
    fmt::{Debug, Formatter, Result as FmtResult},
    hash::{Hash, Hasher},
    mem::size_of,
};
use mc_sgx_types::sgx_attributes_t;
use mc_util_encodings::Error as EncodingError;

const ATTRIBUTES_FLAGS_START: usize = 0;
const ATTRIBUTES_FLAGS_END: usize = ATTRIBUTES_FLAGS_START + size_of::<u64>();
const ATTRIBUTES_XFRM_START: usize = ATTRIBUTES_FLAGS_END;
const ATTRIBUTES_XFRM_END: usize = ATTRIBUTES_XFRM_START + size_of::<u64>();
const ATTRIBUTES_SIZE: usize = ATTRIBUTES_XFRM_END;

/// A type indicating the attribute flags used by an enclave.
#[derive(Clone, Copy, Default)]
#[repr(transparent)]
pub struct Attributes(sgx_attributes_t);

impl Attributes {
    pub fn flags(&self) -> u64 {
        self.0.flags
    }

    pub fn xfrm(&self) -> u64 {
        self.0.xfrm
    }
}

impl_sgx_wrapper_reqs! {
    Attributes, sgx_attributes_t, ATTRIBUTES_SIZE;
}

impl Debug for Attributes {
    fn fmt(&self, formatter: &mut Formatter) -> FmtResult {
        write!(
            formatter,
            "Attributes {{ flags: {}, xfrm: {} }}",
            self.0.flags, self.0.xfrm
        )
    }
}

impl Hash for Attributes {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.flags.hash(state);
        self.0.xfrm.hash(state);
    }
}

impl Ord for Attributes {
    fn cmp(&self, other: &Self) -> Ordering {
        match self.0.flags.cmp(&other.0.flags) {
            Ordering::Equal => self.0.xfrm.cmp(&other.0.xfrm),
            other => other,
        }
    }
}

impl PartialEq for Attributes {
    fn eq(&self, other: &Self) -> bool {
        self.0.flags == other.0.flags && self.0.xfrm == other.0.xfrm
    }
}

/// Support serialization into an x86_64 struct representation
impl SgxWrapperType<sgx_attributes_t> for Attributes {
    fn write_ffi_bytes(src: &sgx_attributes_t, dest: &mut [u8]) -> Result<usize, EncodingError> {
        if dest.len() < ATTRIBUTES_SIZE {
            return Err(EncodingError::InvalidOutputLength);
        }

        dest[ATTRIBUTES_FLAGS_START..ATTRIBUTES_FLAGS_END]
            .copy_from_slice(&src.flags.to_le_bytes());
        dest[ATTRIBUTES_XFRM_START..ATTRIBUTES_XFRM_END].copy_from_slice(&src.xfrm.to_le_bytes());
        Ok(ATTRIBUTES_SIZE)
    }
}

/// Support deserialization from x86_64 bytes
impl<'bytes> TryFrom<&'bytes [u8]> for Attributes {
    type Error = EncodingError;

    fn try_from(src: &[u8]) -> Result<Self, EncodingError> {
        if src.len() < ATTRIBUTES_SIZE {
            return Err(EncodingError::InvalidInputLength);
        }

        Ok(Self(sgx_attributes_t {
            flags: u64::from_le_bytes(
                (&src[ATTRIBUTES_FLAGS_START..ATTRIBUTES_FLAGS_END])
                    .try_into()
                    .unwrap(),
            ),
            xfrm: u64::from_le_bytes(
                (&src[ATTRIBUTES_XFRM_START..ATTRIBUTES_XFRM_END])
                    .try_into()
                    .unwrap(),
            ),
        }))
    }
}

/// Support deserialization from x86_64 bytes
impl TryFrom<Vec<u8>> for Attributes {
    type Error = EncodingError;

    fn try_from(src: Vec<u8>) -> Result<Self, EncodingError> {
        Self::try_from(&src[..])
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use mc_util_serial::{deserialize, serialize};

    #[test]
    fn test_serde() {
        let src = sgx_attributes_t {
            flags: 0x0102_0304_0506_0708,
            xfrm: 0x0807_0605_0403_0201,
        };

        let attrs: Attributes = src.into();
        let attr_ser = serialize(&attrs).expect("Could not serialize attributes");
        let attrs2: Attributes = deserialize(&attr_ser).expect("Could not deserialize attributes");
        assert_eq!(attrs, attrs2);
        assert_eq!(0x0102_0304_0506_0708, attrs2.flags());
        assert_eq!(0x0807_0605_0403_0201, attrs2.xfrm());
    }
}
