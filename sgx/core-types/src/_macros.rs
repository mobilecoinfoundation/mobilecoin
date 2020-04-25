// Copyright (c) 2018-2020 MobileCoin Inc.

//! Macros and re-exports to support a common interface across all FFI-wrapping SGX types.

// Re-export macros our macros are using
pub use alloc::format as _alloc_format;

// Re-export types our macros are using
pub use alloc::vec::Vec;
pub use binascii::{b64decode, b64encode, bin2hex, hex2bin};
pub use hex_fmt::HexFmt;
pub use mc_util_encodings::{
    base64_buffer_size, base64_size, Error as EncodingError, FromBase64, FromHex, FromX64,
    IntelLayout, ToBase64, ToHex, ToX64,
};
pub use serde::{
    de::{
        Deserialize, DeserializeOwned, Deserializer, Error as DeserializeError, SeqAccess, Visitor,
    },
    ser::{Error as SerializeError, Serialize, Serializer},
};
pub use subtle::{Choice, ConstantTimeEq};

use core::{
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
    + DeserializeOwned
    + Display
    + Eq
    + From<FFI>
    + FromX64
    + Hash
    + Into<FFI>
    + Ord
    + PartialEq
    + PartialOrd
    + Serialize
    + ToX64
    + for<'any> From<&'any FFI>
{
}

/// A boilerplate macro which implements the FFI-type-related traits required by the
/// FfiWrapper trait.
#[macro_export]
macro_rules! impl_ffi_wrapper_base {
    ($($wrapper:ident, $inner:ty, $size:ident;)*) => {$(
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
                Self::from(&self.0)
            }
        }

        impl<'de> $crate::_macros::Deserialize<'de> for $wrapper {
            fn deserialize<D: $crate::_macros::Deserializer<'de>>(deserializer: D) -> core::result::Result<Self, D::Error> {
                struct ByteVisitor;

                impl<'de> $crate::_macros::Visitor<'de> for ByteVisitor {
                    type Value = $wrapper;

                    fn expecting(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
                        write!(f, "byte contents of {}", stringify!($wrapper))
                    }

                    fn visit_borrowed_bytes<E: $crate::_macros::DeserializeError>(
                        self,
                        value: &'de [u8],
                    ) -> core::result::Result<Self::Value, E> {
                        use $crate::_macros::FromX64;
                        Self::Value::from_x64(value)
                            .map_err(|convert_error| {
                                E::custom(
                                    $crate::_macros::_alloc_format!(
                                        "Could not parse {}/{} bytes: {}",
                                        value.len(),
                                        <Self::Value as $crate::_macros::IntelLayout>::X86_64_CSIZE,
                                        convert_error
                                    )
                                )
                            })
                    }

                    fn visit_bytes<E: $crate::_macros::DeserializeError>(
                        self,
                        value: &[u8],
                    ) -> core::result::Result<Self::Value, E> {
                        use $crate::_macros::FromX64;

                        Self::Value::from_x64(value)
                            .map_err(|convert_error| {
                                E::custom(
                                    $crate::_macros::_alloc_format!(
                                        "Could not parse {}/{} bytes: {}",
                                        value.len(),
                                        <Self::Value as $crate::_macros::IntelLayout>::X86_64_CSIZE,
                                        convert_error
                                    )
                                )
                            })
                    }

                    fn visit_seq<A: $crate::_macros::SeqAccess<'de>>(
                        self,
                        mut seq: A,
                    ) -> core::result::Result<Self::Value, A::Error>
                    where
                        A::Error: $crate::_macros::DeserializeError
                    {
                        use $crate::_macros::FromX64;

                        let mut bytes =
                            $crate::_macros::Vec::<u8>::with_capacity(seq.size_hint().unwrap_or(1024usize));
                        loop {
                            match seq.next_element()? {
                                Some(byte) => bytes.push(byte),
                                None => break,
                            }
                        }

                        let bytelen = bytes.len();
                        Self::Value::from_x64(bytes.as_mut_slice())
                            .map_err(|convert_error| {
                                use $crate::_macros::DeserializeError;

                                A::Error::custom(
                                    $crate::_macros::_alloc_format!(
                                        "Could not parse {}/{} bytes: {}",
                                        bytelen,
                                        <Self::Value as $crate::_macros::IntelLayout>::X86_64_CSIZE,
                                        convert_error
                                    )
                                )
                            })
                    }
                }

                struct NewtypeVisitor;

                impl<'de> serde::de::Visitor<'de> for NewtypeVisitor {
                    type Value = $wrapper;

                    fn expecting(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
                        write!(f, "struct {}", stringify!($wrapper))
                    }

                    fn visit_newtype_struct<D: $crate::_macros::Deserializer<'de>>(
                        self,
                        deserializer: D,
                    ) -> core::result::Result<Self::Value, D::Error> {
                        deserializer.deserialize_bytes(ByteVisitor)
                    }
                }

                deserializer.deserialize_newtype_struct(stringify!($wrapper), NewtypeVisitor)
            }
        }

        impl Eq for $wrapper {}

        impl From<$inner> for $wrapper {
            fn from(src: $inner) -> Self {
                Self(src)
            }
        }

        impl $crate::_macros::IntelLayout for $wrapper {
            const X86_64_CSIZE: usize = $size as usize;
        }

        impl Into<$inner> for $wrapper {
            fn into(self) -> $inner {
                self.0
            }
        }

        impl PartialOrd for $wrapper {
            fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
                Some(self.cmp(other))
            }
        }
    )*}
}

/// A boilerplate macro which implements Serde's Serialize trait for a type which implements the
/// ToX64 trait already.
#[macro_export]
macro_rules! impl_serialize_to_x64 {
    ($($wrapper:ident, $size:ident;)*) => {$(
        impl $crate::_macros::Serialize for $wrapper {
            fn serialize<S>(&self, serializer: S) -> core::result::Result<S::Ok, S::Error>
            where
                S: $crate::_macros::Serializer
            {
                use $crate::_macros::ToX64;

                let mut bytes = [0u8; $size as usize];
                self.to_x64(&mut bytes[..])
                    .map_err(|_e| {
                        use $crate::_macros::SerializeError;
                        S::Error::custom("Invalid size given to impl_serialize_for_x64 macro")
                    })?;
                serializer.serialize_newtype_struct(stringify!($wrapper), &bytes[..])
            }
        }
    )*}
}

/// A boilerplate macro which implements the FfiWrapper type and its dependencies for a newtype
/// structure which wraps an FFI type.
#[macro_export]
macro_rules! impl_ffi_wrapper {
    ($($wrapper:ident, $inner:ty, $size:ident;)*) => {$(
        $crate::impl_ffi_wrapper_base! {
            $wrapper, $inner, $size;
        }

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

        impl core::fmt::Debug for $wrapper {
            fn fmt(&self, formatter: &mut core::fmt::Formatter) -> core::fmt::Result {
                write!(formatter, "{}: {}", stringify!($wrapper), $crate::_macros::HexFmt(&self))
            }
        }

        impl core::fmt::Display for $wrapper {
            fn fmt(&self, formatter: &mut core::fmt::Formatter) -> core::fmt::Result {
                write!(formatter, "{}", $crate::_macros::HexFmt(&self))
            }
        }

        impl From<&$inner> for $wrapper {
            fn from(src: &$inner) -> Self {
                let mut new_inner = [0u8; $size];
                new_inner.copy_from_slice(&src[..]);
                Self::from(new_inner)
            }
        }

        impl $crate::_macros::FromBase64 for $wrapper {
            type Error = $crate::_macros::EncodingError;

            fn from_base64(s: &str) -> core::result::Result<Self, $crate::_macros::EncodingError> {
                if s.len() % 4 != 0 {
                    return Err($crate::_macros::EncodingError::InvalidInputLength);
                }

                // Don't try to decode any base64 string that's larger than our size limits or smaller
                // than our minimum size
                if s.len() != $crate::_macros::base64_size($size) {
                    return Err($crate::_macros::EncodingError::InvalidInputLength);
                }

                // Create an output buffer of at least MINSIZE bytes
                let mut retval = Self::default();
                $crate::_macros::b64decode(s.as_bytes(), &mut retval.0[..])?;
                Ok(retval)
            }
        }

        impl $crate::_macros::FromHex for $wrapper {
            type Error = $crate::_macros::EncodingError;

            fn from_hex(s: &str) -> core::result::Result<Self, $crate::_macros::EncodingError> {
                if s.len() % 2 != 0 {
                    return Err($crate::_macros::EncodingError::InvalidInputLength);
                }

                if s.len() / 2 != $size {
                    return Err($crate::_macros::EncodingError::InvalidInputLength);
                }

                let mut retval = Self::default();
                $crate::_macros::hex2bin(s.as_bytes(), &mut retval.0[..])?;
                Ok(retval)
            }
        }

        impl<'src> $crate::_macros::FromX64 for $wrapper {
            type Error = $crate::_macros::EncodingError;

            fn from_x64(src: &[u8]) -> core::result::Result<Self, $crate::_macros::EncodingError> {
                if src.len() < $size {
                    return Err($crate::_macros::EncodingError::InvalidInputLength);
                }
                let mut retval = Self::default();
                retval.0[..].copy_from_slice(&src[..$size]);
                Ok(retval)
            }
        }

        impl core::hash::Hash for $wrapper {
            fn hash<H: core::hash::Hasher>(&self, hasher: &mut H) {
                (&self.0[..]).hash(hasher)
            }
        }

        impl Ord for $wrapper {
            fn cmp(&self, other: &Self) -> core::cmp::Ordering {
                (&self.0[..]).cmp(&other.0[..])
            }
        }

        impl PartialEq for $wrapper {
            fn eq(&self, other: &Self) -> bool {
                &self.0[..] == &other.0[..]
            }
        }

        impl $crate::_macros::Serialize for $wrapper {
            fn serialize<S>(&self, serializer: S) -> core::result::Result<S::Ok, S::Error>
            where
                S: $crate::_macros::Serializer
            {
                serializer.serialize_newtype_struct(stringify!($wrapper), &self.0[..])
            }
        }

        impl $crate::_macros::ToBase64 for $wrapper {
            fn to_base64(&self, dest: &mut [u8]) -> core::result::Result<usize, usize> {
                let required_buffer_len = $crate::_macros::base64_buffer_size($size);
                if dest.len() < required_buffer_len {
                    Err(required_buffer_len)
                } else {
                    match $crate::_macros::b64encode(&self.0[..], dest) {
                        Ok(buffer) => Ok(buffer.len()),
                        Err(_convert) => Err(required_buffer_len)
                    }
                }
            }
        }

        impl $crate::_macros::ToHex for $wrapper {
            fn to_hex(&self, dest: &mut [u8]) -> core::result::Result<usize, usize> {
                match $crate::_macros::bin2hex(&self.0[..], dest) {
                    Ok(buffer) => Ok(buffer.len()),
                    Err(_e) => Err($size * 2),
                }
            }
        }

        impl $crate::_macros::ToX64 for $wrapper {
            fn to_x64(&self, dest: &mut [u8]) -> core::result::Result<usize, usize> {
                if dest.len() < $size {
                    return Err($size);
                }
                dest[..$size].copy_from_slice(&self.0[..$size]);
                Ok($size)
            }
        }
    )*};
    ($($wrapper:ident, $inner:ty, $size:ident, $fieldname:ident;)*) => {$(
        $crate::impl_ffi_wrapper_base! {
            $wrapper, $inner, $size;
        }

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

        impl core::fmt::Debug for $wrapper {
            fn fmt(&self, formatter: &mut core::fmt::Formatter) -> core::fmt::Result {
                write!(formatter, "{}: {}", stringify!($wrapper), $crate::_macros::HexFmt(&self))
            }
        }

        impl core::fmt::Display for $wrapper {
            fn fmt(&self, formatter: &mut core::fmt::Formatter) -> core::fmt::Result {
                write!(formatter, "{}", $crate::_macros::HexFmt(&self))
            }
        }

        impl $crate::_macros::ConstantTimeEq for $wrapper {
            fn ct_eq(&self, other: &Self) -> subtle::Choice {
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

            fn from_base64(s: &str) -> core::result::Result<Self, $crate::_macros::EncodingError> {
                if s.len() % 4 != 0 {
                    return Err($crate::_macros::EncodingError::InvalidInputLength);
                }

                // Don't try to decode any base64 string that's smaller than our minimum size
                if s.len() < $crate::_macros::base64_size($size) {
                    return Err($crate::_macros::EncodingError::InvalidInputLength);
                }

                // Create an output buffer of at least MINSIZE bytes
                let mut retval = Self::default();
                $crate::_macros::b64decode(s.as_bytes(), &mut (retval.0).$fieldname[..])?;
                Ok(retval)
            }
        }

        impl $crate::_macros::FromHex for $wrapper {
            type Error = $crate::_macros::EncodingError;

            fn from_hex(s: &str) -> core::result::Result<Self, $crate::_macros::EncodingError> {
                if s.len() % 2 != 0 {
                    return Err($crate::_macros::EncodingError::InvalidInputLength);
                }

                if s.len() / 2 != $size {
                    return Err($crate::_macros::EncodingError::InvalidInputLength);
                }

                let mut retval = Self::default();
                $crate::_macros::hex2bin(s.as_bytes(), &mut (retval.0).$fieldname[..])?;
                Ok(retval)
            }
        }

        impl $crate::_macros::FromX64 for $wrapper {
            type Error = $crate::_macros::EncodingError;

            fn from_x64(src: &[u8]) -> core::result::Result<Self, Self::Error> {
                if src.len() < $size {
                    return Err($crate::_macros::EncodingError::InvalidInputLength);
                }

                let mut retval = $wrapper::default();
                &(retval.0).$fieldname[..].copy_from_slice(&src[..$size]);
                Ok(retval)
            }
        }

        impl core::hash::Hash for $wrapper {
            fn hash<H: core::hash::Hasher>(&self, hasher: &mut H) {
                (self.0).$fieldname[..].hash(hasher)
            }
        }

        impl Ord for $wrapper {
            fn cmp(&self, other: &Self) -> core::cmp::Ordering {
                (self.0).$fieldname[..].cmp(&(other.0).$fieldname[..])
            }
        }

        impl PartialEq for $wrapper {
            fn eq(&self, other: &Self) -> bool {
                (self.0).$fieldname[..] == (other.0).$fieldname[..]
            }
        }

        impl $crate::_macros::Serialize for $wrapper {
            fn serialize<S>(&self, serializer: S) -> core::result::Result<S::Ok, S::Error>
            where
                S: $crate::_macros::Serializer
            {
                serializer.serialize_newtype_struct(stringify!($wrapper), &(self.0).$fieldname[..])
            }
        }

        impl $crate::_macros::ToBase64 for $wrapper {
            fn to_base64(&self, dest: &mut [u8]) -> core::result::Result<usize, usize> {
                let required_buffer_len = $crate::_macros::base64_buffer_size($size);
                if dest.len() < required_buffer_len {
                    Err(required_buffer_len)
                } else {
                    match $crate::_macros::b64encode(&(self.0).$fieldname[..], dest) {
                        Ok(buffer) => Ok(buffer.len()),
                        Err(_convert) => Err(required_buffer_len)
                    }
                }
            }
        }

        impl $crate::_macros::ToHex for $wrapper {
            fn to_hex(&self, dest: &mut [u8]) -> core::result::Result<usize, usize> {
                match $crate::_macros::bin2hex(&(self.0).$fieldname[..], dest) {
                    Ok(buffer) => Ok(buffer.len()),
                    Err(_e) => Err($size * 2),
                }
            }
        }

        impl $crate::_macros::ToX64 for $wrapper {
            fn to_x64(&self, dest: &mut [u8]) -> core::result::Result<usize, usize> {
                if dest.len() < $size {
                    return Err($size);
                }

                &dest[..$size].copy_from_slice(&(self.0).$fieldname[..]);
                Ok($size)
            }
        }
    )*}
}
