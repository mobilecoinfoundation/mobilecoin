// Copyright (c) 2018-2020 MobileCoin Inc.

//! The Responder ID type

use alloc::{
    string::{String, ToString},
    vec::Vec,
};
use core::{
    fmt::{Display, Formatter, Result as FmtResult},
    str::FromStr,
};
use failure::Fail;
use mc_crypto_digestible::Digestible;
use regex::Regex;
use serde::{Deserialize, Serialize};

/// Potential parse errors
#[derive(Debug, Fail, Ord, PartialOrd, Eq, PartialEq, Clone)]
pub enum ResponderIdParseError {
    #[fail(display = "Failure from Utf8 for {:?}", _0)]
    FromUtf8Error(Vec<u8>),
    #[fail(display = "Invalid Format for {}", _0)]
    InvalidFormat(String),
}

/// Node unique identifier.
#[derive(
    Clone, Default, Debug, Eq, Serialize, Deserialize, PartialEq, PartialOrd, Ord, Hash, Digestible,
)]
pub struct ResponderId {
    /// The node's host name. See https://tools.ietf.org/html/rfc1123
    pub host: String,
    /// The node's port.
    pub port: u16,
}

impl ResponderId {
    /// Create a new ResponderId
    ///
    /// # Arguments
    /// * `host` - Node's host name
    /// * `port` - Node's port number
    pub fn new(host: &str, port: u16) -> Self {
        let host_port = format!("{}:{}", host, port);
        ResponderId::from_str(&host_port).unwrap() // TODO
    }
}

impl Display for ResponderId {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        write!(f, "{}:{}", self.host, self.port)
    }
}

impl FromStr for ResponderId {
    type Err = ResponderIdParseError;

    fn from_str(src: &str) -> Result<ResponderId, Self::Err> {
        // host:port
        let re = Regex::new(r#"(?P<host>[^:]+):(?P<port>[0-9]{1,5})"#).unwrap();

        let captures = re
            .captures(src)
            .ok_or(ResponderIdParseError::InvalidFormat(src.to_string()))?;

        let host: &str = captures
            .name("host")
            .map(|host| host.as_str())
            .ok_or(ResponderIdParseError::InvalidFormat(src.to_string()))?;

        let port_str: &str = captures
            .name("port")
            .map(|port| port.as_str())
            .ok_or(ResponderIdParseError::InvalidFormat(src.to_string()))?;

        let port = port_str
            .parse::<u16>()
            .map_err(|_| ResponderIdParseError::InvalidFormat(src.to_string()))?;

        Ok(Self {
            host: host.to_string(),
            port,
        })
    }
}

// This is needed for SCPNetworkState's NetworkState implementation.
impl AsRef<ResponderId> for ResponderId {
    fn as_ref(&self) -> &Self {
        self
    }
}

#[cfg(test)]
mod tests {
    use crate::ResponderId;
    use std::str::FromStr;

    #[test]
    fn new_accepts_valid_host_port() {
        let host = "hostname.com";
        let port = 65353;

        let responder_id = ResponderId::new(host, port);
        assert_eq!(responder_id.host, host);
        assert_eq!(responder_id.port, port);
    }

    #[test]
    /// Valid ports have number 0 to 65353.
    fn from_str_rejects_invalid_port_number() {
        match ResponderId::from_str("foo.com:99999") {
            Ok(_responder_id) => panic!(),
            Err(_e) => {} // This is expected.
        }
    }
}
