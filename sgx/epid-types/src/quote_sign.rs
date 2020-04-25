// Copyright (c) 2018-2020 MobileCoin Inc.

//! SGX EPID Quote signature type

use core::{
    convert::TryFrom,
    fmt::{Display, Formatter, Result as FmtResult},
};
use mc_encodings::Error as EncodingError;
use mc_sgx_epid_types_sys::{SGX_LINKABLE_SIGNATURE, SGX_UNLINKABLE_SIGNATURE};
use serde::{Deserialize, Serialize};

/// An enumeration of viable EPID quote signature types
#[derive(Clone, Copy, Debug, Deserialize, Hash, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[repr(u32)]
pub enum QuoteSign {
    Unlinkable = SGX_UNLINKABLE_SIGNATURE,
    Linkable = SGX_LINKABLE_SIGNATURE,
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

macro_rules! _impl_conversions {
    ($($numeric:ty;)*) => {$(
        impl Into<$numeric> for QuoteSign {
            fn into(self) -> $numeric {
                match self {
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
