// Copyright (c) 2018-2020 MobileCoin Inc.

//! Macros and re-exports to support a common interface across all FFI-wrapping SGX types.

// Re-export stuff our macros are using
pub use alloc::vec::Vec;
pub use base64;
pub use hex;
pub use hex_fmt::HexFmt;
pub use mc_util_encodings::{base64_size, Error as EncodingError, FromBase64, ToBase64};
pub use mc_util_repr_bytes::{
    derive_core_cmp_from_as_ref, derive_into_vec_from_repr_bytes,
    derive_repr_bytes_from_as_ref_and_try_from, typenum::Unsigned, GenericArray, ReprBytes,
};
pub use subtle::{Choice, ConstantTimeEq};

use ::core::{
    convert::TryFrom,
    fmt::{Debug, Display},
    hash::Hash,
};

/// A helper marker trait which SGX-wrapper newtypes should implement to ensure a consistent API.
///
/// Note that types which are not `repr(transparent)` newtypes should manually implement
/// `AsRef<FFI>` and `AsMut<FFI>`.
pub trait FfiWrapper<FFI>:
    AsRef<FFI>
    + AsMut<FFI>
    + Clone
    + Debug
    + Default
    + Display
    + Eq
    + FromBase64
    + hex::FromHex
    + ReprBytes
    + Hash
    + Into<FFI>
    + Into<Vec<u8>>
    + Ord
    + PartialEq
    + PartialOrd
    + TryFrom<FFI>
    + for<'any> TryFrom<&'any FFI>
    + for<'any> TryFrom<&'any [u8]>
{
}

/// A boilerplate macro which implements the FFI-type-related traits required by the
/// FfiWrapper trait.
#[macro_export]
macro_rules! impl_ffi_wrapper_base {
    ($($wrapper:ty, $inner:ty;)*) => {$(
        impl AsMut<$inner> for $wrapper {
            fn as_mut(&mut self) -> &mut $inner {
                &mut self.0
            }
        }

        impl AsRef<$inner> for $wrapper {
            fn as_ref(&self) -> &$inner {
                &self.0
            }
        }

        impl Clone for $wrapper {
            fn clone(&self) -> Self {
                use ::core::convert::TryFrom;

                Self::try_from(&self.0).expect("Invalid data, cannot clone")
            }
        }

        impl Eq for $wrapper {}

        impl From<$inner> for $wrapper {
            fn from(src: $inner) -> Self {
                Self(src)
            }
        }

        impl Into<$inner> for $wrapper {
            fn into(self) -> $inner {
                self.0
            }
        }
    )*}
}

/// A boilerplate macro which implements the FfiWrapper type and its dependencies for a newtype
/// structure which wraps an FFI type.
#[macro_export]
macro_rules! impl_ffi_wrapper {
    ($($wrapper:ty, $inner:ty, $size:ty;)*) => {$(
        $crate::impl_ffi_wrapper_base! {
            $wrapper, $inner;
        }


        $crate::_macros::derive_core_cmp_from_as_ref!($wrapper, [u8]);
        $crate::_macros::derive_repr_bytes_from_as_ref_and_try_from!($wrapper, $size);
        $crate::_macros::derive_into_vec_from_repr_bytes!($wrapper);

        impl AsRef<[u8]> for $wrapper {
            fn as_ref(&self) -> &[u8] {
                &self.0[..]
            }
        }

        impl AsMut<[u8]> for $wrapper {
            fn as_mut(&mut self) -> &mut [u8] {
                &mut self.0[..]
            }
        }

        impl $crate::_macros::ConstantTimeEq for $wrapper {
            fn ct_eq(&self, other: &Self) -> $crate::_macros::Choice {
                self.0[..].ct_eq(&other.0[..])
            }
        }

        impl ::core::fmt::Debug for $wrapper {
            fn fmt(&self, formatter: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
                write!(formatter, "{}: {}", stringify!($wrapper), $crate::_macros::HexFmt(&self))
            }
        }

        impl ::core::fmt::Display for $wrapper {
            fn fmt(&self, formatter: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
                write!(formatter, "{}", $crate::_macros::HexFmt(&self))
            }
        }

        impl From<&$inner> for $wrapper {
            fn from(src: &$inner) -> Self {
                let mut new_inner = [0u8; <$size as $crate::_macros::Unsigned>::USIZE];
                new_inner.copy_from_slice(&src[..]);
                Self::from(new_inner)
            }
        }

        impl $crate::_macros::FromBase64 for $wrapper {
            type Error = $crate::_macros::EncodingError;

            fn from_base64(s: &str) -> ::core::result::Result<Self, $crate::_macros::EncodingError> {
                if (s.len() + 3) / 4 * 3 > <$size as $crate::_macros::Unsigned>::USIZE {
                    return Err($crate::_macros::EncodingError::InvalidInputLength);
                }

                let mut retval = Self::default();
                let len = $crate::_macros::base64::decode_config_slice(
                    s,
                    $crate::_macros::base64::STANDARD,
                    &mut retval.0[..],
                )?;
                if len != <$size as $crate::_macros::Unsigned>::USIZE {
                    return Err($crate::_macros::EncodingError::InvalidInputLength);
                }

                Ok(retval)
            }
        }

        impl $crate::_macros::hex::FromHex for $wrapper {
            type Error = $crate::_macros::EncodingError;

            fn from_hex<S: AsRef<[u8]>>(s: S) -> ::core::result::Result<Self, Self::Error> {
                if s.as_ref().len() / 2 != <$size as $crate::_macros::Unsigned>::USIZE {
                    return Err($crate::_macros::EncodingError::InvalidInputLength);
                }

                let mut retval = Self::default();
                $crate::_macros::hex::decode_to_slice(s, &mut retval.0[..])?;
                Ok(retval)
            }
        }

        impl<'src> ::core::convert::TryFrom<&'src [u8]> for $wrapper {
            type Error = $crate::_macros::EncodingError;

            fn try_from(src: &[u8]) -> ::core::result::Result<Self, $crate::_macros::EncodingError> {
                if src.len() < <$size as $crate::_macros::Unsigned>::USIZE {
                    return Err($crate::_macros::EncodingError::InvalidInputLength);
                }
                let mut retval = Self::default();
                retval.0[..].copy_from_slice(&src[..<$size as $crate::_macros::Unsigned>::USIZE]);
                Ok(retval)
            }
        }
    )*};
    ($($wrapper:ty, $inner:ty, $size:ty, $fieldname:ident;)*) => {$(
        $crate::impl_ffi_wrapper_base! {
            $wrapper, $inner;
        }

        $crate::_macros::derive_core_cmp_from_as_ref!($wrapper, [u8]);
        $crate::_macros::derive_repr_bytes_from_as_ref_and_try_from!($wrapper, $size);
        $crate::_macros::derive_into_vec_from_repr_bytes!($wrapper);

        impl AsRef<[u8]> for $wrapper {
            fn as_ref(&self) -> &[u8] {
                &(self.0).$fieldname[..]
            }
        }

        impl AsMut<[u8]> for $wrapper {
            fn as_mut(&mut self) -> &mut [u8] {
                &mut (self.0).$fieldname[..]
            }
        }

        impl ::core::fmt::Debug for $wrapper {
            fn fmt(&self, formatter: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
                write!(formatter, "{}: {}", stringify!($wrapper), $crate::_macros::HexFmt(&self))
            }
        }

        impl ::core::fmt::Display for $wrapper {
            fn fmt(&self, formatter: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
                write!(formatter, "{}", $crate::_macros::HexFmt(&self))
            }
        }

        impl $crate::_macros::ConstantTimeEq for $wrapper {
            fn ct_eq(&self, other: &Self) -> $crate::_macros::Choice {
                (self.0).$fieldname[..].ct_eq(&(other.0).$fieldname[..])
            }
        }

        impl From<&$inner> for $wrapper {
            fn from(src: &$inner) -> Self {
                let mut new_inner = <$inner>::default();
                new_inner.$fieldname.copy_from_slice(&src.$fieldname[..]);
                Self::from(new_inner)
            }
        }

        impl $crate::_macros::FromBase64 for $wrapper {
            type Error = $crate::_macros::EncodingError;

            fn from_base64(s: &str) -> ::core::result::Result<Self, $crate::_macros::EncodingError> {
                if (s.len() + 3) / 4 * 3 > <$size as $crate::_macros::Unsigned>::USIZE {
                    return Err($crate::_macros::EncodingError::InvalidInputLength);
                }

                let mut retval = Self::default();
                let len = $crate::_macros::base64::decode_config_slice(
                    s,
                    $crate::_macros::base64::STANDARD,
                    &mut (retval.0).$fieldname[..],
                )?;
                if len != <$size as $crate::_macros::Unsigned>::USIZE {
                    return Err($crate::_macros::EncodingError::InvalidInputLength);
                }

                Ok(retval)
            }
        }

        impl $crate::_macros::hex::FromHex for $wrapper {
            type Error = $crate::_macros::EncodingError;

            fn from_hex<S: AsRef<[u8]>>(s: S) -> ::core::result::Result<Self, Self::Error> {
                if s.as_ref().len() / 2 != <$size as $crate::_macros::Unsigned>::USIZE {
                    return Err($crate::_macros::EncodingError::InvalidInputLength);
                }

                let mut retval = Self::default();
                $crate::_macros::hex::decode_to_slice(s, &mut (retval.0).$fieldname[..])?;
                Ok(retval)
            }
        }

        impl<'src> ::core::convert::TryFrom<&'src [u8]> for $wrapper {
            type Error = $crate::_macros::EncodingError;

            fn try_from(src: &[u8]) -> ::core::result::Result<Self, Self::Error> {
                if src.len() < <$size as $crate::_macros::Unsigned>::USIZE {
                    return Err($crate::_macros::EncodingError::InvalidInputLength);
                }

                let mut retval = Self::default();
                &(retval.0).$fieldname[..].copy_from_slice(
                    &src[..<$size as $crate::_macros::Unsigned>::USIZE]
                );
                Ok(retval)
            }
        }
    )*}
}

/// A boilerplate macro which implements the [`hex::FromHex`] and [`mc_util_encodings::FromBase64`]
/// traits for a type which implements ReprBytes.
#[macro_export]
macro_rules! impl_hex_base64_with_repr_bytes {
    ($wrapper:ty) => {
        impl $crate::_macros::FromBase64 for $wrapper {
            type Error = $crate::_macros::EncodingError;

            fn from_base64(
                input: &str,
            ) -> ::core::result::Result<Self, $crate::_macros::EncodingError> {
                use $crate::_macros::ReprBytes;

                let mut output = $crate::_macros::GenericArray::default();
                if $crate::_macros::base64::decode_config_slice(
                    input,
                    $crate::_macros::base64::STANDARD,
                    output.as_mut_slice(),
                )? != <<$wrapper as $crate::_macros::ReprBytes>::Size as $crate::_macros::Unsigned>::USIZE
                {
                    return Err($crate::_macros::EncodingError::InvalidInputLength);
                }
                Self::from_bytes(&output)
            }
        }

        impl $crate::_macros::hex::FromHex for $wrapper {
            type Error = $crate::_macros::EncodingError;

            fn from_hex<S: AsRef<[u8]>>(data: S) -> ::core::result::Result<Self, Self::Error> {
                use $crate::_macros::ReprBytes;

                let mut out = $crate::_macros::GenericArray::default();
                $crate::_macros::hex::decode_to_slice(data, out.as_mut_slice())?;
                Self::from_bytes(&out)
            }
        }
    };
}
