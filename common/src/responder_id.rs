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
use serde::{de::Error, Deserialize, Deserializer, Serialize, Serializer};

/// Potential parse errors
#[derive(Debug, Fail, Ord, PartialOrd, Eq, PartialEq, Clone)]
pub enum ResponderIdParseError {
    #[fail(display = "Failure from Utf8 for {:?}", _0)]
    FromUtf8Error(Vec<u8>),
    #[fail(display = "Invalid Format for {}", _0)]
    InvalidFormat(String),
}

/// Node unique identifier.
#[derive(Clone, Default, Debug, Eq, PartialEq, PartialOrd, Ord, Hash, Digestible)]
pub struct ResponderId {
    /// The node's host name. See https://tools.ietf.org/html/rfc1123
    pub host: String,
    /// The node's port.
    pub port: u16,
}

impl ResponderId {
    /// Create a new ResponderId.
    ///
    /// # Arguments
    /// * `host` - Node's host name
    /// * `port` - Node's port number
    pub fn new(host: &str, port: u16) -> Result<Self, ResponderIdParseError> {
        let host_port = alloc::format!("{}:{}", host, port);
        ResponderId::from_str(&host_port)
    }
}

impl Serialize for ResponderId {
    fn serialize<S>(&self, serializer: S) -> Result<<S as Serializer>::Ok, <S as Serializer>::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&alloc::format!("{}:{}", &self.host, &self.port))
    }
}

impl<'de> Deserialize<'de> for ResponderId {
    fn deserialize<D>(deserializer: D) -> Result<Self, <D as Deserializer<'de>>::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        ResponderId::from_str(&s).map_err(|e| D::Error::custom(format!("{:?}", e)))
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
        // host:port or host:port/, with named capture groups.
        let re = Regex::new(r#"(?P<host>^[^:]+):(?P<port>[0-9]{1,5})/?"#).unwrap();

        let captures = re
            .captures(src)
            .ok_or_else(|| ResponderIdParseError::InvalidFormat(src.to_string()))?;

        let host: &str = captures
            .name("host")
            .map(|host| host.as_str())
            .ok_or_else(|| ResponderIdParseError::InvalidFormat(src.to_string()))?;

        let port_str: &str = captures
            .name("port")
            .map(|port| port.as_str())
            .ok_or_else(|| ResponderIdParseError::InvalidFormat(src.to_string()))?;

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

        let responder_id = ResponderId::new(host, port).unwrap();
        assert_eq!(responder_id.host, host);
        assert_eq!(responder_id.port, port);
    }

    #[test]
    fn new_accepts_valid_ip_port() {
        let host = "0.0.0.0";
        let port = 8082;

        let responder_id = ResponderId::new(host, port).unwrap();
        assert_eq!(responder_id.host, host);
        assert_eq!(responder_id.port, port);
    }

    #[test]
    fn new_rejects_invalid_host() {
        let host = "hostname:com"; // Contains a forbidden extra colon.
        let port = 6;
        match ResponderId::new(host, port) {
            Ok(responder_id) => panic!(format!(
                "host: {}, port: {}",
                responder_id.host, responder_id.port
            )),
            Err(_) => {} // This is expected.
        }
    }

    #[test]
    /// Valid ports have number 0 to 65353.
    fn from_str_rejects_invalid_port_number() {
        assert!(ResponderId::from_str("foo.com:99999").is_err());
    }

    #[test]
    /// from_str accepts trailing slash.
    fn from_str_accepts_trailing_slash() {
        assert!(ResponderId::from_str("foo.com:23/").is_ok());
    }
}
