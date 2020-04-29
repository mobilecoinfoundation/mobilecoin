// Copyright (c) 2018-2020 MobileCoin Inc.

//! The wrapper type for an sgx_attributes_t

use crate::{_macros::FfiWrapper, impl_ffi_wrapper_base, impl_serialize_to_x64};
use bitflags::bitflags;
use core::{
    cmp::Ordering,
    convert::{TryFrom, TryInto},
    fmt::{Debug, Display, Formatter, Result as FmtResult},
    hash::{Hash, Hasher},
};
use mc_sgx_core_types_sys::sgx_attributes_t;
use mc_util_encodings::{Error as EncodingError, FromX64, ToX64, INTEL_U64_SIZE};

bitflags! {
    /// A set of bitflags which can be set on an attributes structure.
    pub struct AttributeFlags: u64 {
        /// The enclave has been initialized.
        const INITIALIZED = 0x0000_0000_0000_0001;
        /// The enclave is configured for debug mode.
        const DEBUG = 0x0000_0000_0000_0002;
        /// The enclave is built for 64-bit execution
        const MODE_64_BIT = 0x0000_0000_0000_0004;
        /// The enclave has access to the provisioning key
        const PROVISION_KEY = 0x0000_0000_0000_0010;
        /// The enclave has access to the loader initialization token
        const ENCLAVE_INIT_TOKEN = 0x0000_0000_0000_0020;
        /// The enclave uses key separation features
        const KSS = 0x0000_0000_0000_0080;
    }
}

impl Display for AttributeFlags {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        let mut previous = if self.contains(AttributeFlags::INITIALIZED) {
            write!(f, "Initialized")?;
            true
        } else {
            false
        };

        if self.contains(AttributeFlags::DEBUG) {
            if previous {
                write!(f, ", ")?;
            }
            write!(f, "Debug")?;
            previous = true;
        }

        if self.contains(AttributeFlags::MODE_64_BIT) {
            if previous {
                write!(f, ", ")?;
            }
            write!(f, "64-bit")?;
            previous = true;
        } else {
            if previous {
                write!(f, ", ")?;
            }
            write!(f, "32-bit")?;
            previous = true;
        }

        if self.contains(AttributeFlags::PROVISION_KEY) {
            if previous {
                write!(f, ", ")?;
            }
            write!(f, "Provision key")?;
            previous = true;
        }

        if self.contains(AttributeFlags::ENCLAVE_INIT_TOKEN) {
            if previous {
                write!(f, ", ")?;
            }
            write!(f, "Enclave initialization token")?;
            previous = true;
        }

        if self.contains(AttributeFlags::KSS) {
            if previous {
                write!(f, ", ")?;
            }
            write!(f, "Extended Product ID")?;
        }

        Ok(())
    }
}

bitflags! {
    /// The flags which can be set on an X-Feature Request Mask.
    pub struct AttributeXfeatures: u64 {
        /// The enclave uses legacy XSAVE features
        const LEGACY = 0x0000_0000_0000_0003;
        /// The enclave uses modern AVX features
        const AVX = 0x0000_0000_0000_0006;
    }
}

impl Display for AttributeXfeatures {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        let previous = if self.contains(AttributeXfeatures::LEGACY) {
            write!(f, "Legacy AVX")?;
            true
        } else {
            false
        };

        if self.contains(AttributeXfeatures::AVX) {
            if previous {
                write!(f, ", ")?;
            }
            write!(f, "AVX")?;
        }

        Ok(())
    }
}

const FLAGS_START: usize = 0;
const FLAGS_END: usize = FLAGS_START + INTEL_U64_SIZE;
const XFRM_START: usize = FLAGS_END;
const XFRM_END: usize = XFRM_START + INTEL_U64_SIZE;

/// The size of the x64 representation of [Attributes], in bytes.
pub const ATTRIBUTES_SIZE: usize = XFRM_END;

/// A type indicating the attribute flags used by an enclave.
#[derive(Default)]
#[repr(transparent)]
pub struct Attributes(sgx_attributes_t);

impl Attributes {
    /// Retrieve the enclave flags.
    pub fn flags(&self) -> AttributeFlags {
        AttributeFlags::from_bits(self.0.flags).unwrap()
    }

    /// Retrieve the enclave X-Features Request Mask.
    pub fn xfrm(&self) -> AttributeXfeatures {
        AttributeXfeatures::from_bits(self.0.xfrm).unwrap()
    }
}

impl_ffi_wrapper_base! {
    Attributes, sgx_attributes_t, ATTRIBUTES_SIZE;
}

impl_serialize_to_x64! {
    Attributes, ATTRIBUTES_SIZE;
}

impl Debug for Attributes {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        write!(
            f,
            "Attributes: {{ flags: 0x{:08x}, xfrm: 0x{:08x} }}",
            self.0.flags, self.0.xfrm
        )
    }
}

impl Display for Attributes {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        write!(f, "{} | {}", self.flags(), self.xfrm())
    }
}

impl TryFrom<&sgx_attributes_t> for Attributes {
    type Error = EncodingError;

    fn try_from(src: &sgx_attributes_t) -> Result<Attributes, Self::Error> {
        Ok(Self(sgx_attributes_t {
            flags: AttributeFlags::from_bits(src.flags)
                .ok_or(EncodingError::InvalidInput)?
                .bits,
            xfrm: AttributeXfeatures::from_bits(src.xfrm)
                .ok_or(EncodingError::InvalidInput)?
                .bits,
        }))
    }
}

impl FromX64 for Attributes {
    type Error = EncodingError;

    fn from_x64(src: &[u8]) -> Result<Self, EncodingError> {
        if src.len() < ATTRIBUTES_SIZE {
            return Err(EncodingError::InvalidInputLength);
        }

        let flags = u64::from_le_bytes((&src[FLAGS_START..FLAGS_END]).try_into().unwrap());
        AttributeFlags::from_bits(flags).ok_or(EncodingError::InvalidInput)?;

        let xfrm = u64::from_le_bytes((&src[XFRM_START..XFRM_END]).try_into().unwrap());
        AttributeXfeatures::from_bits(xfrm).ok_or(EncodingError::InvalidInput)?;

        Ok(Self(sgx_attributes_t { flags, xfrm }))
    }
}

impl Hash for Attributes {
    fn hash<H: Hasher>(&self, state: &mut H) {
        "Attributes".hash(state);
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

impl ToX64 for Attributes {
    fn to_x64(&self, dest: &mut [u8]) -> Result<usize, usize> {
        if dest.len() < ATTRIBUTES_SIZE {
            return Err(ATTRIBUTES_SIZE);
        }

        dest[FLAGS_START..FLAGS_END].copy_from_slice(&self.0.flags.to_le_bytes());
        dest[XFRM_START..XFRM_END].copy_from_slice(&self.0.xfrm.to_le_bytes());
        Ok(ATTRIBUTES_SIZE)
    }
}

impl FfiWrapper<sgx_attributes_t> for Attributes {}

#[cfg(test)]
mod test {
    use super::*;
    use bincode::{deserialize, serialize};

    #[test]
    fn bad_flags_from_x64() {
        let src = [
            0x01u8, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x08, 0x07, 0x06, 0x05, 0x04, 0x03,
            0x02, 0x01,
        ];

        assert!(Attributes::from_x64(&src[..]).is_err());
    }

    #[test]
    fn bad_xfrm_from_x64() {
        let src = [
            0x00u8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x08, 0x07, 0x06, 0x05, 0x04, 0x03,
            0x02, 0x01,
        ];

        assert!(Attributes::from_x64(&src[..]).is_err());
    }

    #[test]
    fn good_serde() {
        let src = sgx_attributes_t {
            flags: 0x0000_0000_0000_0001 | 0x0000_0000_0000_0004 | 0x0000_0000_0000_0080,
            xfrm: 0x0000_0000_0000_0006,
        };

        let attrs = Attributes::try_from(&src).expect("Could not create attributes");
        let bytes = serialize(&attrs).expect("Could not serialize attributes");
        let attrs2 = deserialize::<Attributes>(&bytes).expect("Could not deserialize attributes");

        assert_eq!(attrs, attrs2);
        assert_eq!(
            0x0000_0000_0000_0001 | 0x0000_0000_0000_0004 | 0x0000_0000_0000_0080,
            attrs2.flags().bits
        );
        assert_eq!(0x0000_0000_0000_0006, attrs2.xfrm().bits);
    }
}
