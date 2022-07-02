// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Type wrappers for Ethereum addresses.

use super::Error;
use serde_with::{DeserializeFromStr, SerializeDisplay};
use std::{fmt, str::FromStr};

/// Ethereum 20 byte address.
/// We currently do not store the decoded bytes since we want to maintain the
/// original capitalization (which is how Ethereum addresses represent a
/// checksum). We don't have a need for the raw bytes.
#[derive(Clone, Debug, Default, DeserializeFromStr, SerializeDisplay)]
pub struct EthAddr(pub String);

impl FromStr for EthAddr {
    type Err = Error;

    fn from_str(src: &str) -> Result<Self, Self::Err> {
        if !src.starts_with("0x") {
            return Err(Error::InvalidAddress(src.to_string()));
        }

        let bytes = hex::decode(&src[2..]).map_err(|_| Error::InvalidAddress(src.to_string()))?;
        if bytes.len() != 20 {
            return Err(Error::InvalidAddress(src.to_string()));
        }

        Ok(Self(src.to_string()))
    }
}

impl fmt::Display for EthAddr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl PartialEq for EthAddr {
    fn eq(&self, other: &Self) -> bool {
        // Ethereum addresses are case-insensitive.
        self.0.to_lowercase() == other.0.to_lowercase()
    }
}

impl Eq for EthAddr {}

/// Ethereum 32 byte transaction hash.
/// We currently do not store the decoded bytes since we have no use for them.
#[derive(Clone, Debug, Default, DeserializeFromStr, Eq, PartialEq, SerializeDisplay)]
pub struct EthTxHash(pub String);

impl FromStr for EthTxHash {
    type Err = Error;

    fn from_str(src: &str) -> Result<Self, Self::Err> {
        if !src.starts_with("0x") {
            return Err(Error::InvalidTxHash(src.to_string()));
        }

        let bytes = hex::decode(&src[2..]).map_err(|_| Error::InvalidTxHash(src.to_string()))?;
        if bytes.len() != 32 {
            return Err(Error::InvalidTxHash(src.to_string()));
        }

        Ok(Self(src.to_string()))
    }
}

impl fmt::Display for EthTxHash {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_eth_addr() {
        assert_eq!(
            EthAddr::from_str("0xA000000000000000000000000000000000001234").unwrap(),
            EthAddr("0xA000000000000000000000000000000000001234".to_string())
        );

        assert_eq!(
            EthAddr::from_str("0xABC0000000000000000000000000000000001234").unwrap(),
            EthAddr("0xabc0000000000000000000000000000000001234".to_string())
        );
    }

    #[test]
    fn invalid_eth_addr() {
        assert!(EthAddr::from_str("A000000000000000000000000000000000001234").is_err());
        assert!(EthAddr::from_str("0xz000000000000000000000000000000000001234").is_err());
        assert!(EthAddr::from_str("0xA0000000000000000000000000000000000001234").is_err());
        assert!(EthAddr::from_str("0xA00000000000000000000000000000000001234").is_err());
    }
}
