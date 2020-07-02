// Copyright (c) 2018-2020 MobileCoin Inc.

//! SGX EPID Quote signature type

use core::{
    convert::TryFrom,
    fmt::{Display, Formatter, Result as FmtResult},
};
use mc_sgx_core_types::impl_hex_base64_with_repr_bytes;
use mc_sgx_epid_types_sys::{SGX_LINKABLE_SIGNATURE, SGX_UNLINKABLE_SIGNATURE};
use mc_util_encodings::Error as EncodingError;
use mc_util_repr_bytes::{
    derive_into_vec_from_repr_bytes, derive_try_from_slice_from_repr_bytes, typenum::U4,
    GenericArray, ReprBytes,
};
#[cfg(feature = "use_serde")]
use serde::{Deserialize, Serialize};

/// An enumeration of viable EPID quote signature types
#[cfg_attr(feature = "use_serde", derive(Deserialize, Serialize))]
#[derive(Clone, Copy, Debug, Hash, Eq, Ord, PartialEq, PartialOrd)]
#[repr(u32)]
pub enum QuoteSign {
    /// The EPID pseudonym will not be linkable between reports.
    Unlinkable = SGX_UNLINKABLE_SIGNATURE,
    /// The EPID pseudonym will be linkable between reports.
    Linkable = SGX_LINKABLE_SIGNATURE,
}

impl Default for QuoteSign {
    fn default() -> QuoteSign {
        QuoteSign::Unlinkable
    }
}

macro_rules! _impl_conversions {
    ($($numeric:ty;)*) => {$(
        impl From<QuoteSign> for $numeric {
            fn from(src: QuoteSign) -> $numeric {
                match src {
                    QuoteSign::Unlinkable => SGX_UNLINKABLE_SIGNATURE as $numeric,
                    QuoteSign::Linkable => SGX_LINKABLE_SIGNATURE as $numeric,
                }
            }
        }

        impl TryFrom<$numeric> for QuoteSign {
            type Error = EncodingError;

            fn try_from(src: $numeric) -> Result<Self, Self::Error> {
                match src {
                    0 => Ok(QuoteSign::Unlinkable),
                    1 => Ok(QuoteSign::Linkable),
                    _other => Err(EncodingError::InvalidInput),
                }
            }
        }
    )*}
}

_impl_conversions! {
    u8; u16; u32; u64; u128; i8; i16; i32; i64; i128;
}

impl_hex_base64_with_repr_bytes!(QuoteSign);
derive_try_from_slice_from_repr_bytes!(QuoteSign);
derive_into_vec_from_repr_bytes!(QuoteSign);

impl QuoteSign {
    /// Check if the given i32 value is a valid value.
    //
    // This method is normally implemented by prost via derive(Enumeration), but the SGX SDK chooses
    // to use a u32 for the in-situ data type.
    pub fn is_valid(value: i32) -> bool {
        Self::from_i32(value).is_some()
    }

    /// Create a new Error from the given i32 value.
    //
    // This method is normally implemented by prost via derive(Enumeration), but the SGX SDK chooses
    // to use a u32 for the in-situ data type.
    pub fn from_i32(value: i32) -> Option<Self> {
        Self::try_from(value).ok()
    }
}

impl Display for QuoteSign {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        let text = match self {
            QuoteSign::Unlinkable => "Unlinkable",
            QuoteSign::Linkable => "Linkable",
        };
        write!(f, "{}", text)
    }
}

impl ReprBytes for QuoteSign {
    type Size = U4;
    type Error = EncodingError;

    fn from_bytes(src: &GenericArray<u8, Self::Size>) -> Result<Self, Self::Error> {
        Self::try_from(u32::from_le_bytes(src.clone().into()))
    }

    fn to_bytes(&self) -> GenericArray<u8, Self::Size> {
        GenericArray::from(u32::from(*self).to_le_bytes())
    }
}
