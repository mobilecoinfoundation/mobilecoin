// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Type wrappers for Ethereum addresses.

use super::Error;
use mc_util_from_random::{CryptoRng, FromRandom, RngCore};
use serde_with::{DeserializeFromStr, SerializeDisplay};
use std::{
    fmt,
    hash::{Hash, Hasher},
    str::FromStr,
};

/// Ethereum 20 byte address.
/// We currently do not store the decoded bytes since we want to maintain the
/// original capitalization (which is how Ethereum addresses represent a
/// checksum). We don't have a need for the raw bytes.
#[derive(Clone, Debug, Default, DeserializeFromStr, Ord, PartialOrd, SerializeDisplay)]
pub struct EthAddr(pub String);

impl EthAddr {
    /// Ethereum address payload length (excludes the `0x` prefix).
    pub const LEN: usize = 20;
}

impl FromStr for EthAddr {
    type Err = Error;

    fn from_str(src: &str) -> Result<Self, Self::Err> {
        if !src.starts_with("0x") {
            return Err(Error::InvalidAddress(src.to_string()));
        }

        let bytes = hex::decode(&src[2..]).map_err(|_| Error::InvalidAddress(src.to_string()))?;
        if bytes.len() != Self::LEN {
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

impl Hash for EthAddr {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.to_lowercase().hash(state);
    }
}

/// Ethereum 32 byte transaction hash.
#[derive(
    Copy,
    Clone,
    Debug,
    Default,
    DeserializeFromStr,
    Eq,
    Hash,
    Ord,
    PartialEq,
    PartialOrd,
    SerializeDisplay,
)]
pub struct EthTxHash(pub [u8; Self::LEN]);

impl EthTxHash {
    /// The length (in bytes) of an Ethereum transaction hash.
    pub const LEN: usize = 32;
}

impl TryFrom<&[u8]> for EthTxHash {
    type Error = Error;

    fn try_from(src: &[u8]) -> Result<Self, Self::Error> {
        Ok(Self(
            src.try_into()
                .map_err(|_| Error::InvalidTxHash(hex::encode(src)))?,
        ))
    }
}

impl FromStr for EthTxHash {
    type Err = Error;

    fn from_str(src: &str) -> Result<Self, Self::Err> {
        if !src.starts_with("0x") {
            return Err(Error::InvalidTxHash(src.to_string()));
        }

        Self::try_from(
            &hex::decode(&src[2..]).map_err(|_| Error::InvalidTxHash(src.to_string()))?[..],
        )
    }
}

impl fmt::Display for EthTxHash {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "0x{}", hex::encode(&self.0))
    }
}

impl AsRef<[u8]> for EthTxHash {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl FromRandom for EthTxHash {
    fn from_random<T: RngCore + CryptoRng>(rng: &mut T) -> Self {
        Self(FromRandom::from_random(rng))
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
