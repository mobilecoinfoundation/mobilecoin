// Copyright (c) 2018-2022 The MobileCoin Foundation

//! The Responder ID type

use alloc::{
    string::{String, ToString},
    vec::Vec,
};
use core::{
    fmt::{Display, Formatter, Result as FmtResult},
    str::FromStr,
};
use displaydoc::Display;
use mc_crypto_digestible::Digestible;
use prost::{
    bytes::{Buf, BufMut},
    encoding, Message,
};
use serde::{Deserialize, Serialize};

/// Potential parse errors
#[derive(Debug, Display, Eq, Ord, PartialOrd, PartialEq, Clone)]
pub enum ResponderIdParseError {
    /// Failure from Utf8 for {0:0x?}
    FromUtf8Error(Vec<u8>),
    /// Invalid Format for {0}
    InvalidFormat(String),
}

#[cfg(feature = "std")]
impl std::error::Error for ResponderIdParseError {}

/// Node unique identifier.
#[derive(
    Clone, Default, Debug, Eq, Serialize, Deserialize, PartialEq, PartialOrd, Ord, Hash, Digestible,
)]
pub struct ResponderId(#[digestible(never_omit)] pub String);

impl Display for ResponderId {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        write!(f, "{}", self.0)
    }
}

impl FromStr for ResponderId {
    type Err = ResponderIdParseError;

    fn from_str(src: &str) -> Result<ResponderId, Self::Err> {
        // ResponderId is expected to be host:port, so at least ensure we have a single
        // colon as a small sanity test.
        if !src.contains(':') {
            return Err(ResponderIdParseError::InvalidFormat(src.to_string()));
        }

        Ok(Self(src.to_string()))
    }
}

// This is needed for SCPNetworkState's NetworkState implementation.
impl AsRef<ResponderId> for ResponderId {
    fn as_ref(&self) -> &Self {
        self
    }
}

// Encode ResponderId as a proto string
impl Message for ResponderId {
    fn encode_raw<B>(&self, buf: &mut B)
    where
        B: BufMut,
        Self: Sized,
    {
        String::encode_raw(&self.0, buf)
    }

    fn merge_field<B>(
        &mut self,
        tag: u32,
        wire_type: encoding::WireType,
        buf: &mut B,
        ctx: encoding::DecodeContext,
    ) -> Result<(), prost::DecodeError>
    where
        B: Buf,
        Self: Sized,
    {
        String::merge_field(&mut self.0, tag, wire_type, buf, ctx)
    }

    fn encoded_len(&self) -> usize {
        String::encoded_len(&self.0)
    }

    fn clear(&mut self) {
        self.0.clear()
    }
}
