// Copyright (c) 2018-2020 MobileCoin Inc.

//! The Responder ID type

use alloc::{
    string::{String, ToString},
    vec::Vec,
};
use core::{
    convert::TryFrom,
    fmt::{Display, Formatter, Result as FmtResult},
    str::FromStr,
};
use failure::Fail;
use serde::{Deserialize, Serialize};

/// The type of data used by a ResponderId (must implement AsRef<[u8]>, Display,
pub type ResponderIdType = String;

/// Potential parse errors
#[derive(Debug, Fail, Ord, PartialOrd, Eq, PartialEq, Clone)]
pub enum ResponderIdParseError {
    #[fail(display = "Failure from Utf8 for {:?}", _0)]
    FromUtf8Error(Vec<u8>),
    #[fail(display = "Invalid Format for {}", _0)]
    InvalidFormat(String),
}

/// Node unique identifier (this will eventually be the node's TLS name).
#[derive(Clone, Default, Debug, Eq, Serialize, Deserialize, PartialEq, PartialOrd, Ord, Hash)]
pub struct ResponderId(pub ResponderIdType);

impl Display for ResponderId {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        write!(f, "{}", self.0)
    }
}

impl AsRef<[u8]> for ResponderId {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl FromStr for ResponderId {
    type Err = ResponderIdParseError;

    fn from_str(src: &str) -> Result<ResponderId, Self::Err> {
        // ResponderId is expected to be host:port, so at least ensure we have a single colon as a
        // small sanity test.
        if !src.contains(':') {
            return Err(ResponderIdParseError::InvalidFormat(src.to_string()));
        }

        Ok(Self(src.to_string()))
    }
}

impl TryFrom<Vec<u8>> for ResponderId {
    type Error = ResponderIdParseError;

    fn try_from(val: Vec<u8>) -> Result<Self, Self::Error> {
        Self::from_str(
            &String::from_utf8(val.clone())
                .map_err(|_| ResponderIdParseError::FromUtf8Error(val))?,
        )
    }
}

impl ResponderId {
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

// This is needed for SCPNetworkState's NetworkState implementation.
impl AsRef<ResponderId> for ResponderId {
    fn as_ref(&self) -> &Self {
        self
    }
}
