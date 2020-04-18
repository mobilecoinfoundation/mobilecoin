// Copyright (c) 2018-2020 MobileCoin Inc.

//! This module helps with generating core traits and serialization code for
//! cryptographic primitves.
//! It defines a trait ReprBytes32 for types that have a 32 byte serialized
//! representation.
//! To get traits defined on your type, you implement this trait, and then invoke
//! some macros depending on what you need.
//!
//! prost_message_helper32 gets you prost::Message
//! serde_helper32 gets you serde Serialize and Deserialize
//! try_from_helper32 gets you try_from<&[u8;32]> and try_from<&[u8]>

/// ReprBytes32 is for a type that can be represented by exactly 32 bytes
/// and implements conversions to and from [u8; 32].
///
/// The error types are constrained with Display so that both Prost and Serde can make effective use of them
pub trait ReprBytes32: Default {
    type Error: core::fmt::Display;
    fn to_bytes(&self) -> [u8; 32];
    fn from_bytes(src: &[u8; 32]) -> Result<Self, <Self as ReprBytes32>::Error>;
}

/// It would be nice if we could make a blanket impl for prost::Message based on ReprBytes32,
/// but we cannot because of coherence rules, we would have to ensure that the trait is only
/// on a local type according to rust.
/// Instead the user uses this macro in the crate where they defined the struct.
///
/// TODO(chris): prost::bytes re-export is undocumented, we should re-export that from this
/// helper crate instead, and then endeavor to keep it at the same version that prost is using
/// I guess... Or convince Dan Burkert that it should be a documented re-export
#[macro_export]
macro_rules! prost_message_helper32 {
    ($mytype:ty) => {
        impl $crate::prost::Message for $mytype {
            #[inline]
            fn encode_raw<B>(&self, buf: &mut B)
            where
                B: $crate::prost::bytes::BufMut,
            {
                use $crate::prost::encoding::*;
                let tag = 1;
                let value = <Self as $crate::helpers::ReprBytes32>::to_bytes(self);
                encode_key(tag, WireType::LengthDelimited, buf);
                encode_varint(32 as u64, buf);
                buf.put_slice(&value[..]);
            }

            #[inline]
            fn merge_field<B>(
                &mut self,
                tag: u32,
                wire_type: $crate::prost::encoding::WireType,
                buf: &mut B,
                ctx: $crate::prost::encoding::DecodeContext,
            ) -> Result<(), $crate::prost::DecodeError>
            where
                B: $crate::prost::bytes::Buf,
            {
                use alloc::string::ToString;
                use core::convert::TryInto;
                use $crate::prost::encoding::*;
                if tag == 1 {
                    check_wire_type(WireType::LengthDelimited, wire_type)?;
                    let len = decode_varint(buf)?;
                    if len > buf.remaining() as u64 {
                        return Err($crate::prost::DecodeError::new("buffer underflow"));
                    }
                    if len != 32 {
                        return Err($crate::prost::DecodeError::new(concat!(
                            stringify!($mytype),
                            " expects exactly 32 bytes"
                        )));
                    }
                    let result = <Self as $crate::helpers::ReprBytes32>::from_bytes(
                        (&buf.bytes()[0..32]).try_into().unwrap(),
                    );
                    buf.advance(32);
                    *self = result.map_err(|e| $crate::prost::DecodeError::new(e.to_string()))?;
                    Ok(())
                } else {
                    skip_field(wire_type, tag, buf, ctx)
                }
            }

            #[inline]
            fn encoded_len(&self) -> usize {
                use $crate::prost::encoding::*;
                key_len(1) + encoded_len_varint(32 as u64) + 32
            }

            #[inline]
            fn clear(&mut self) {
                *self = Self::default();
            }
        }
    };
}

/// Same thing as prost_message_helper32 but for serde
#[macro_export]
macro_rules! serde_helper32 {
    ($mytype:ty) => {
        impl ::serde::ser::Serialize for $mytype {
            #[inline]
            fn serialize<S: ::serde::ser::Serializer>(
                &self,
                serializer: S,
            ) -> Result<S::Ok, S::Error> {
                serializer.serialize_bytes(&<Self as ReprBytes32>::to_bytes(self))
            }
        }

        impl<'de> ::serde::de::Deserialize<'de> for $mytype {
            fn deserialize<D: ::serde::de::Deserializer<'de>>(
                deserializer: D,
            ) -> Result<$mytype, D::Error> {
                struct KeyVisitor;

                impl<'de> ::serde::de::Visitor<'de> for KeyVisitor {
                    type Value = $mytype;

                    fn expecting(
                        &self,
                        formatter: &mut ::core::fmt::Formatter,
                    ) -> core::fmt::Result {
                        write!(
                            formatter,
                            concat!("A ", stringify!($mytype), " as array of bytes")
                        )
                    }

                    #[inline]
                    fn visit_bytes<E: ::serde::de::Error>(
                        self,
                        value: &[u8],
                    ) -> Result<Self::Value, E> {
                        let temp: &[u8; 32] = value.try_into().map_err(|_| {
                            <E as ::serde::de::Error>::custom($crate::helpers::LengthMismatch32(
                                value.len(),
                            ))
                        })?;
                        Ok(<Self::Value as ReprBytes32>::from_bytes(temp)
                            .map_err(|err| <E as ::serde::de::Error>::custom(err))?)
                    }
                    #[inline]
                    fn visit_seq<V>(self, mut seq: V) -> Result<Self::Value, V::Error>
                    where
                        V: ::serde::de::SeqAccess<'de>,
                    {
                        let mut res = [0u8; 32];
                        let mut idx = 0;
                        while let Some(elem) = seq.next_element()? {
                            if idx >= 32 {
                                return Err(<V::Error as ::serde::de::Error>::custom(
                                    "Expected exactly 32 bytes, got too many",
                                ));
                            }
                            res[idx] = elem;
                            idx += 1;
                        }
                        if idx != 32 {
                            return Err(<V::Error as ::serde::de::Error>::custom(
                                $crate::helpers::LengthMismatch32(idx),
                            ));
                        }
                        self.visit_bytes(&res)
                    }
                }

                deserializer.deserialize_bytes(KeyVisitor)
            }
        }
    };
}

// Deduce TryFrom for byte slice types based on ReprBytes32
// Requires that your error type allows conversion from core::array::TryFromSliceError
#[macro_export]
macro_rules! try_from_helper32 {
    ($mytype:ty) => {
        impl TryFrom<&[u8; 32]> for $mytype {
            type Error = <Self as ReprBytes32>::Error;
            fn try_from(src: &[u8; 32]) -> Result<Self, <Self as ReprBytes32>::Error> {
                <Self as ReprBytes32>::from_bytes(src)
            }
        }

        impl TryFrom<&[u8]> for $mytype {
            type Error = <Self as ReprBytes32>::Error;
            fn try_from(src: &[u8]) -> Result<Self, <Self as ReprBytes32>::Error> {
                use core::convert::TryInto;
                let temp: &[u8; 32] = src
                    .try_into()
                    .map_err(|_| $crate::helpers::LengthMismatch32(src.len()))?;
                <Self as ReprBytes32>::from_bytes(temp)
            }
        }
    };
}

/// Error that indicates that we got a different number of bytes than 32 which we expected
pub struct LengthMismatch32(pub usize);

impl core::fmt::Display for LengthMismatch32 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter) -> core::fmt::Result {
        write!(formatter, "Expected exactly 32 bytes, got {}", self.0)
    }
}

////
// These macros are for deducing things from AsRef<[u8;32]>
////

// Deduce many core traits, Ord, PartialOrd, PartialEq, Hash from AsRef<[u8;32]>.
// Don't do this on private keys!!!
#[macro_export]
macro_rules! deduce_core_traits_from_public_bytes {
    ($mytype:ty) => {
        impl PartialOrd for $mytype {
            fn partial_cmp(&self, other: &Self) -> Option<::core::cmp::Ordering> {
                <Self as AsRef<[u8; 32]>>::as_ref(self)
                    .partial_cmp(<Self as AsRef<[u8; 32]>>::as_ref(other))
            }
        }

        impl Ord for $mytype {
            fn cmp(&self, other: &Self) -> ::core::cmp::Ordering {
                <Self as AsRef<[u8; 32]>>::as_ref(self)
                    .cmp(<Self as AsRef<[u8; 32]>>::as_ref(other))
            }
        }

        impl PartialEq for $mytype {
            fn eq(&self, other: &Self) -> bool {
                <Self as AsRef<[u8; 32]>>::as_ref(self).eq(<Self as AsRef<[u8; 32]>>::as_ref(other))
            }
        }
        impl core::hash::Hash for $mytype {
            fn hash<H: core::hash::Hasher>(&self, hasher: &mut H) {
                use core::hash::Hash;
                <Self as AsRef<[u8; 32]>>::as_ref(self).hash(hasher)
            }
        }
    };
}
