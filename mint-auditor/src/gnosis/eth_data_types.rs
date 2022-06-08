// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Type wrappers for Ethereum addresses.

use super::Error;
use serde::{Deserialize, Serialize};
use std::{fmt, str::FromStr};

/// Ethereum 20 byte address.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_eth_addr() {
        assert_eq!(
            EthAddr::from_str("0xA000000000000000000000000000000000001234").unwrap(),
            EthAddr("0xA000000000000000000000000000000000001234".to_string())
        );
    }

    #[test]
    fn invalid_eth_addr() {
        assert!(EthAddr::from_str("A000000000000000000000000000000000001234").is_err());
        assert!(EthAddr::from_str("0xz000000000000000000000000000000000001234").is_err());
    }
}
