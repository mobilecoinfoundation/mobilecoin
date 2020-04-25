// Copyright (c) 2018-2020 MobileCoin Inc.

//! A public type used for mobilecoind database keys.
//! Keys are aliases for DatabaseByteArrayKey, which is a newtype for [u8; 32]

use crate::error::Error;
use mc_crypto_digestible::Digestible;
use mc_util_serial::{prost_message_helper32, ReprBytes32};
use std::{
    convert::{AsRef, TryFrom},
    fmt,
    ops::Deref,
};

#[derive(Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Digestible)]
pub struct DatabaseByteArrayKey([u8; 32]);

impl DatabaseByteArrayKey {
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl ReprBytes32 for DatabaseByteArrayKey {
    type Error = Error;

    fn to_bytes(&self) -> [u8; 32] {
        self.0
    }

    fn from_bytes(src: &[u8; 32]) -> Result<Self, <Self as ReprBytes32>::Error> {
        Ok(Self(*src))
    }
}

impl Deref for DatabaseByteArrayKey {
    type Target = [u8];
    #[inline]
    fn deref(&self) -> &[u8] {
        &self.0
    }
}

impl AsRef<[u8]> for DatabaseByteArrayKey {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}
impl AsRef<[u8; 32]> for DatabaseByteArrayKey {
    fn as_ref(&self) -> &[u8; 32] {
        self.as_bytes()
    }
}
impl From<&[u8; 32]> for DatabaseByteArrayKey {
    fn from(src: &[u8; 32]) -> Self {
        Self(*src)
    }
}
impl From<[u8; 32]> for DatabaseByteArrayKey {
    fn from(src: [u8; 32]) -> Self {
        Self(src)
    }
}
impl TryFrom<&Vec<u8>> for DatabaseByteArrayKey {
    type Error = Error;

    fn try_from(src: &Vec<u8>) -> Result<Self, <Self as TryFrom<&Vec<u8>>>::Error> {
        if src.len() != 32 {
            return Err(Error::InvalidArgument(
                "src".to_string(),
                "length needs to be 32".to_string(),
            ));
        }
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(src);
        Ok(Self(bytes))
    }
}

impl<'bytes> TryFrom<&'bytes [u8]> for DatabaseByteArrayKey {
    type Error = Error;

    fn try_from(src: &[u8]) -> Result<Self, <Self as TryFrom<&'bytes [u8]>>::Error> {
        if src.len() != 32 {
            return Err(Error::InvalidArgument(
                "src".to_string(),
                "length needs to be 32".to_string(),
            ));
        }
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(src);
        Ok(Self(bytes))
    }
}

impl fmt::Display for DatabaseByteArrayKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", hex_fmt::HexFmt(self.0))
    }
}
impl fmt::Debug for DatabaseByteArrayKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", hex_fmt::HexFmt(self.0))
    }
}

prost_message_helper32! { DatabaseByteArrayKey }
