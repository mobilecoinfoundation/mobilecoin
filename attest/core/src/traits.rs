// Copyright (c) 2018-2021 The MobileCoin Foundation

//! Trait definitions for rust structures with an FFI analogue

// Re-export macros our macros are using
pub(crate) use alloc::format as _alloc_format;

// Re-export types our macros are using
pub(crate) use alloc::vec::Vec;
pub(crate) use binascii::{b64decode, b64encode, bin2hex, hex2bin};
pub(crate) use core::{
    cmp::{Ord, Ordering},
    convert::TryFrom,
    fmt::{Debug, Display, Formatter, Result as FmtResult},
    hash::{Hash, Hasher},
};
pub(crate) use hex_fmt::HexFmt;
pub(crate) use mc_util_encodings::{
    base64_buffer_size, base64_size, Error as EncodingError, FromBase64, FromHex, IntelLayout,
    ToBase64, ToHex, ToX64,
};
pub(crate) use serde::{
    de::{
        Deserialize, DeserializeOwned, Deserializer, Error as DeserializeError, SeqAccess, Visitor,
    },
    ser::{Serialize, Serializer},
};
pub(crate) use subtle::ConstantTimeEq;

/// A marker trait used to enforce the existence of other traits.
pub trait SgxType:
    Clone + Debug + Default + DeserializeOwned + Eq + Hash + Ord + PartialEq + PartialOrd + Serialize
{
}

/// A trait which SGX-wrapper newtypes should implement to ensure reasonable
/// trait implementations and consistent serialization into/out of x86_64
/// bytes. Note that types which are not repr(transparent) newtypes should
/// manually implement AsRef<FFI> and AsMut<FFI>.
pub trait SgxWrapperType<FFI>:
    AsRef<FFI> + AsMut<FFI> + From<FFI> + for<'src> From<&'src FFI> + ToX64 + Into<FFI> + SgxType
{
    /// Copy the backing store of this type into a byte slice in x86_64 C layout
    fn write_ffi_bytes(src: &FFI, dest: &mut [u8]) -> Result<usize, EncodingError>;
}

/// Boilerplate macro to fill in any trait implementations required by
/// an SgxWrapperType that don't depend on the contents of the inner
/// type.
#[macro_export]
macro_rules! impl_sgx_wrapper_reqs {
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

        impl<'de> $crate::traits::Deserialize<'de> for $wrapper {
            fn deserialize<D: $crate::traits::Deserializer<'de>>(deserializer: D) -> core::result::Result<Self, D::Error> {
                struct ByteVisitor;

                impl<'de> $crate::traits::Visitor<'de> for ByteVisitor {
                    type Value = $wrapper;

                    #[inline]
                    fn expecting(&self, formatter: &mut $crate::traits::Formatter) -> $crate::traits::FmtResult {
                        write!(formatter, "byte contents of {}", stringify!($wrapper))
                    }

                    #[inline]
                    fn visit_borrowed_bytes<E: $crate::traits::DeserializeError>(
                        self,
                        value: &'de [u8],
                    ) -> core::result::Result<Self::Value, E> {
                        use $crate::traits::TryFrom;
                        Self::Value::try_from(value)
                            .map_err(|convert_error| {
                                E::custom(
                                    $crate::traits::_alloc_format!(
                                        "Could not parse {}/{} bytes: {}",
                                        value.len(),
                                        <Self::Value as $crate::traits::IntelLayout>::X86_64_CSIZE,
                                        convert_error
                                    )
                                )
                            })
                    }

                    #[inline]
                    fn visit_bytes<E: $crate::traits::DeserializeError>(
                        self,
                        value: &[u8],
                    ) -> core::result::Result<Self::Value, E> {
                        use $crate::traits::TryFrom;

                        Self::Value::try_from(value)
                            .map_err(|convert_error| {
                                E::custom(
                                    $crate::traits::_alloc_format!(
                                        "Could not parse {}/{} bytes: {}",
                                        value.len(),
                                        <Self::Value as $crate::traits::IntelLayout>::X86_64_CSIZE,
                                        convert_error
                                    )
                                )
                            })
                    }

                    #[inline]
                    fn visit_seq<A: $crate::traits::SeqAccess<'de>>(
                        self,
                        mut seq: A,
                    ) -> core::result::Result<Self::Value, A::Error>
                    where
                        A::Error: $crate::traits::DeserializeError
                    {
                        use $crate::traits::TryFrom;
                        use $crate::traits::DeserializeError;

                        let mut bytes = $crate::traits::Vec::<u8>::with_capacity(<Self::Value as $crate::traits::IntelLayout>::X86_64_CSIZE);
                        let mut position = 0;
                        loop {
                            // Clamp the maximum number of bytes read to the CSIZE
                            if position > <Self::Value as $crate::traits::IntelLayout>::X86_64_CSIZE {
                                return Err(A::Error::invalid_length(position, &"fewer bytes than were given"));
                            }

                            match seq.next_element()? {
                                Some(byte) => bytes.push(byte),
                                None => break,
                            }

                            position += 1;
                        }

                        let bytelen = bytes.len();
                        Self::Value::try_from(bytes)
                            .map_err(|convert_error| {
                                A::Error::custom(
                                    $crate::traits::_alloc_format!(
                                        "Could not parse {}/{} bytes: {}",
                                        bytelen,
                                        <Self::Value as $crate::traits::IntelLayout>::X86_64_CSIZE,
                                        convert_error
                                    )
                                )
                            })
                    }
                }

                struct NewtypeVisitor;

                impl<'de> serde::de::Visitor<'de> for NewtypeVisitor {
                    type Value = $wrapper;

                    #[inline]
                    fn expecting(&self, formatter: &mut $crate::traits::Formatter) -> $crate::traits::FmtResult {
                        write!(formatter, "struct {}", stringify!($wrapper))
                    }

                    #[inline]
                    fn visit_newtype_struct<D: $crate::traits::Deserializer<'de>>(
                        self,
                        deserializer: D,
                    ) -> core::result::Result<Self::Value, D::Error> {
                        deserializer.deserialize_bytes(ByteVisitor)
                    }
                }

                deserializer.deserialize_newtype_struct(stringify!($wrapper), NewtypeVisitor)
            }
        }

        impl From<$inner> for $wrapper {
            fn from(src: $inner) -> Self {
                Self(src)
            }
        }

        impl Eq for $wrapper {}

        impl<'src> From<&'src $inner> for $wrapper {
            fn from(src: &$inner) -> Self {
                Self(src.clone())
            }
        }

        impl $crate::traits::IntelLayout for $wrapper {
            const X86_64_CSIZE: usize = $size;
        }

        impl $crate::traits::ToX64 for $wrapper {
            fn to_x64(&self, dest: &mut [u8]) -> core::result::Result<usize, usize> {
                use $crate::traits::{IntelLayout, SgxWrapperType};

                let len = self.intel_size();
                $wrapper::write_ffi_bytes(self.as_ref(), dest).or(Err(len))?;
                Ok(len)
            }
        }

        impl From<$wrapper> for $inner {
            fn from(src: $wrapper) -> $inner {
                src.0
            }
        }

        impl PartialOrd for $wrapper {
            fn partial_cmp(&self, other: &$wrapper) -> Option<core::cmp::Ordering> {
                Some(self.cmp(other))
            }
        }

        impl $crate::traits::Serialize for $wrapper {
            fn serialize<S>(&self, serializer: S) -> core::result::Result<S::Ok, S::Error>
            where
                S: $crate::traits::Serializer
            {
                use $crate::traits::ToX64;

                serializer.serialize_newtype_struct(stringify!($wrapper), self.to_x64_vec().as_slice())
            }
        }

        impl $crate::traits::SgxType for $wrapper {}
    )*}
}

/// This macro provides common byte-handling operations when the type being
/// wrapped is a struct containing a single fixed-size array of bytes.
///
/// This should be called from within within a private submodule.
#[macro_export]
macro_rules! impl_sgx_newtype_for_bytestruct {
    ($($wrapper:ident, $inner:ty, $size:ident, $fieldname:ident;)*) => {$(
        $crate::impl_sgx_wrapper_reqs! {
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

        impl $crate::traits::Debug for $wrapper {
            fn fmt(&self, formatter: &mut core::fmt::Formatter) -> $crate::traits::FmtResult {
                write!(formatter, "{}: {:?}", stringify!($wrapper), &(self.0).$fieldname[..])
            }
        }

        impl $crate::traits::Display for $wrapper {
            fn fmt(&self, formatter: &mut $crate::traits::Formatter) -> $crate::traits::FmtResult {
                write!(formatter, "{}", $crate::traits::HexFmt(&self))
            }
        }

        impl $crate::traits::Hash for $wrapper {
            fn hash<H: $crate::traits::Hasher>(&self, state: &mut H) {
                (self.0).$fieldname.hash(state)
            }
        }

        impl $crate::traits::Ord for $wrapper {
            fn cmp(&self, other: &$wrapper) -> $crate::traits::Ordering {
                (self.0).$fieldname.cmp(&(other.0).$fieldname)
            }
        }

        impl PartialEq for $wrapper {
            fn eq(&self, other: &$wrapper) -> bool {
                use subtle::ConstantTimeEq;
                (self.ct_eq(other)).into()
            }
        }

        impl $crate::traits::ConstantTimeEq for $wrapper {
            fn ct_eq(&self, other: &Self) -> subtle::Choice {
                (self.0).$fieldname[..].ct_eq(&(other.0).$fieldname[..])
            }
        }

        impl $crate::traits::SgxWrapperType<$inner> for $wrapper {
            fn write_ffi_bytes(
                src: &$inner,
                dest: &mut [u8]
            ) -> core::result::Result<usize, $crate::traits::EncodingError> {
                if dest.len() < $size {
                    return Err($crate::traits::EncodingError::InvalidOutputLength);
                }

                &dest[..$size].copy_from_slice(&src.$fieldname[..]);
                Ok($size)
            }
        }

        impl<'bytes> $crate::traits::TryFrom<&'bytes [u8]> for $wrapper {
            type Error = $crate::traits::EncodingError;

            fn try_from(src: &[u8]) -> core::result::Result<Self, Self::Error> {
                if src.len() < $size {
                    return Err($crate::traits::EncodingError::InvalidInputLength);
                }

                let mut retval = $wrapper::default();
                &(retval.0).$fieldname[..].copy_from_slice(&src[..$size]);
                Ok(retval)
            }
        }

        impl $crate::traits::TryFrom<$crate::traits::Vec<u8>> for $wrapper {
            type Error = $crate::traits::EncodingError;

            fn try_from(src: $crate::traits::Vec<u8>) -> core::result::Result<Self, Self::Error> {
                if src.len() < $size {
                    return Err($crate::traits::EncodingError::InvalidInputLength);
                }

                let mut retval = $wrapper::default();
                &(retval.0).$fieldname[..].copy_from_slice(&src[..$size]);
                Ok(retval)
            }
        }
    )*}
}

#[macro_export]
macro_rules! impl_base64str_for_bytestruct {
    ($($wrapper:ident, $size:ident, $fieldname:ident;)*) => {$(
        impl $crate::traits::FromBase64 for $wrapper {
            type Error = $crate::traits::EncodingError;

            fn from_base64(s: &str) -> core::result::Result<Self, $crate::traits::EncodingError> {
                if s.len() % 4 != 0 {
                    return Err($crate::traits::EncodingError::InvalidInputLength);
                }

                // Don't try to decode any base64 string that's smaller than our minimum size
                if s.len() < $crate::traits::base64_size($size) {
                    return Err($crate::traits::EncodingError::InvalidInputLength);
                }

                // Create an output buffer of at least MINSIZE bytes
                let mut retval = Self::default();
                $crate::traits::b64decode(s.as_bytes(), &mut (retval.0).$fieldname[..])?;
                Ok(retval)
            }
        }

        impl $crate::traits::ToBase64 for $wrapper {
            fn to_base64(&self, dest: &mut [u8]) -> core::result::Result<usize, usize> {
                let required_buffer_len = $crate::traits::base64_buffer_size($size);
                if dest.len() < required_buffer_len {
                    Err(required_buffer_len)
                } else {
                    match $crate::traits::b64encode(&(self.0).$fieldname[..], dest) {
                        Ok(buffer) => Ok(buffer.len()),
                        Err(_convert) => Err(required_buffer_len)
                    }
                }
            }
        }
    )*}
}

#[macro_export]
macro_rules! impl_hexstr_for_bytestruct {
    ($($wrapper:ident, $size:ident, $fieldname:ident;)*) => {$(
        impl $crate::traits::FromHex for $wrapper {
            type Error = $crate::traits::EncodingError;

            fn from_hex(s: &str) -> core::result::Result<Self, $crate::traits::EncodingError> {
                if s.len() % 2 != 0 {
                    return Err($crate::traits::EncodingError::InvalidInputLength);
                }

                if s.len() / 2 != $size {
                    return Err($crate::traits::EncodingError::InvalidInputLength);
                }

                let mut retval = Self::default();
                $crate::traits::hex2bin(s.as_bytes(), &mut (retval.0).$fieldname[..])?;
                Ok(retval)
            }
        }

        impl $crate::traits::ToHex for $wrapper {
            fn to_hex(&self, dest: &mut [u8]) -> core::result::Result<usize, usize> {
                match $crate::traits::bin2hex(&(self.0).$fieldname[..], dest) {
                    Ok(buffer) => Ok(buffer.len()),
                    Err(_e) => Err($size * 2),
                }
            }
        }
    )*}
}

/// Boilerplate implementations for traits on a newtype struct that is
/// wrapping an SGX type which is itself simply a type alias for a byte
/// array.
///
/// This should be wrapped within a module in order to prevent duplicate
/// use statements for traits.
#[macro_export]
macro_rules! impl_sgx_newtype_for_bytearray {
    ($($wrapper:ident, $inner:ty, $size:ident;)*) => {$(
        $crate::impl_sgx_wrapper_reqs! {
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

        impl Default for $wrapper {
            fn default() -> Self {
                Self([0u8; $size])
            }
        }

        impl $crate::traits::Debug for $wrapper {
            fn fmt(&self, formatter: &mut core::fmt::Formatter) -> $crate::traits::FmtResult {
                write!(formatter, "{}: {:?}", stringify!($wrapper), &self.0[..])
            }
        }

        impl $crate::traits::Display for $wrapper {
            fn fmt(&self, formatter: &mut $crate::traits::Formatter) -> $crate::traits::FmtResult {
                write!(formatter, "{}", $crate::traits::HexFmt(&self))
            }
        }

        impl $crate::traits::Hash for $wrapper {
            fn hash<H: $crate::traits::Hasher>(&self, state: &mut H) {
                self.0.hash(state)
            }
        }

        impl Ord for $wrapper {
            fn cmp(&self, other: &Self) -> $crate::traits::Ordering {
                (&self.0[..]).cmp(&other.0[..])
            }
        }

        impl PartialEq for $wrapper {
            fn eq(&self, other: &Self) -> bool {
                use subtle::ConstantTimeEq;
                self.ct_eq(other).into()
            }
        }

        impl $crate::traits::ConstantTimeEq for $wrapper {
            fn ct_eq(&self, other: &Self) -> subtle::Choice {
                self.0[..].ct_eq(&other.0[..])
            }
        }

        impl $crate::traits::SgxWrapperType<$inner> for $wrapper {
            fn write_ffi_bytes(src: &$inner, dest: &mut [u8]) -> core::result::Result<usize, $crate::traits::EncodingError> {
                if dest.len() < $size {
                    return Err($crate::traits::EncodingError::InvalidOutputLength);
                }
                dest[..$size].copy_from_slice(&src[..$size]);
                Ok($size)
            }
        }

        impl<'src> $crate::traits::TryFrom<&'src [u8]> for $wrapper {
            type Error = $crate::traits::EncodingError;

            fn try_from(src: &[u8]) -> core::result::Result<Self, $crate::traits::EncodingError> {
                if src.len() < $size {
                    return Err($crate::traits::EncodingError::InvalidInputLength);
                }
                let mut retval = Self::default();
                retval.0[..].copy_from_slice(&src[..$size]);
                Ok(retval)
            }
        }

        impl $crate::traits::TryFrom<$crate::traits::Vec<u8>> for $wrapper {
            type Error = $crate::traits::EncodingError;

            fn try_from(src: $crate::traits::Vec<u8>) -> core::result::Result<Self, $crate::traits::EncodingError> {
                if src.len() < $size {
                    return Err($crate::traits::EncodingError::InvalidInputLength);
                }
                let mut retval = Self::default();
                retval.0[..].copy_from_slice(&src[..$size]);
                Ok(retval)
            }
        }
    )*}
}

#[macro_export]
macro_rules! impl_base64str_for_bytearray {
    ($($wrapper:ident, $size:ident;)*) => {$(
        impl $crate::traits::FromBase64 for $wrapper {
            type Error = $crate::traits::EncodingError;

            fn from_base64(s: &str) -> core::result::Result<Self, $crate::traits::EncodingError> {
                if s.len() % 4 != 0 {
                    return Err($crate::traits::EncodingError::InvalidInputLength);
                }

                // Don't try to decode any base64 string that's larger than our size limits or smaller
                // than our minimum size
                if s.len() != $crate::traits::base64_size($size) {
                    return Err($crate::traits::EncodingError::InvalidInputLength);
                }

                // Create an output buffer of at least MINSIZE bytes
                let mut retval = Self::default();
                $crate::traits::b64decode(s.as_bytes(), &mut retval.0[..])?;
                Ok(retval)
            }
        }

        impl $crate::traits::ToBase64 {
            fn to_base64(&self, dest: &mut [u8]) -> core::result::Result<usize, usize> {
                let required_buffer_len = $crate::traits::base64_buffer_size($size)
                if dest.len() < required_buffer_len {
                    Err(required_buffer_len)
                } else {
                    match $crate::traits::b64encode(&self.0[..], &mut outbuf[..]) {
                        Ok(buffer) => Ok(buffer.len()),
                        Err(_convert) => Err(required_buffer_len)
                    }
                }
            }
        }
    )*}
}

#[macro_export]
macro_rules! impl_hexstr_for_bytearray {
    ($($wrapper:ident, $size:ident;)*) => {$(
        impl $crate::traits::FromHex for $wrapper {
            type Error = $crate::traits::EncodingError;

            fn from_hex(s: &str) -> core::result::Result<Self, $crate::traits::EncodingError> {
                if s.len() % 2 != 0 {
                    return Err($crate::traits::EncodingError::InvalidInputLength);
                }

                if s.len() / 2 != $size {
                    return Err($crate::traits::EncodingError::InvalidInputLength);
                }

                let mut retval = Self::default();
                $crate::traits::hex2bin(s.as_bytes(), &mut retval.0[..])?;
                Ok(retval)
            }
        }

        impl $crate::traits::ToHex for $wrapper {
            fn to_hex(&self, dest: &mut [u8]) -> core::result::Result<usize, usize> {
                match bin2hex(&self.0[..], dest) {
                    Ok(buffer) => Ok(buffer.len()),
                    Err(_e) => Err($size * 2),
                }
            }
        }
    )*}
}
