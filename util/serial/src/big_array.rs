// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Contains serialization and deserialization methods for arrays that are
//! bigger than 32 bits.

use core::fmt;
use serde::{
    de::{Deserializer, Error, SeqAccess, Visitor},
    ser::{SerializeTuple, Serializer},
};

pub trait BigArray<'de>: Sized {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer;
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>;
}

macro_rules! big_array {
    ($($len:expr,)+) => {
        $(
            impl<'de> BigArray<'de> for [u8; $len]
            {
                fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
                    where S: Serializer
                {
                    let mut seq = serializer.serialize_tuple(self.len())?;
                    for elem in &self[..] {
                        seq.serialize_element(elem)?;
                    }
                    seq.end()
                }

                fn deserialize<D>(deserializer: D) -> Result<[u8; $len], D::Error>
                    where D: Deserializer<'de>
                {
                    struct ByteVisitor;

                    impl<'de> Visitor<'de> for ByteVisitor
                    {
                        type Value = [u8; $len];

                        fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                            formatter.write_str(concat!("an array of length ", $len))
                        }

                        #[inline]
                        fn visit_borrowed_bytes<E: Error>(
                            self,
                            value: &'de [u8],
                        ) -> core::result::Result<Self::Value, E> {
                            Self::Value::try_from(value).map_err(|_e| E::custom("Could not create array from slice"))
                        }

                        #[inline]
                        fn visit_bytes<E: Error>(
                            self,
                            value: &[u8],
                        ) -> core::result::Result<Self::Value, E> {
                            Self::Value::try_from(value).map_err(|_e| E::custom("Could not create array from slice"))
                        }


                        #[inline]
                        fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
                            where A: SeqAccess<'de>
                        {
                            let mut arr = [0; $len];
                            for i in 0..$len {
                                arr[i] = seq.next_element()?
                                    .ok_or_else(|| Error::invalid_length(i, &self))?;
                            }
                            Ok(arr)
                        }

                    }

                    let visitor = ByteVisitor {};
                    deserializer.deserialize_tuple($len, visitor)
                }
            }
        )+
    }
}

big_array! { 64, }
