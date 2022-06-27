// Copyright (c) 2018-2022 The MobileCoin Foundation

//! A validator that checks that a given key is used within a configured range
//! of indexes.

use super::{Config, KeyValidityMap};
use crate::{ParseError, ValidationError};
use mc_blockchain_types::BlockIndex;
use mc_crypto_keys::Ed25519Public;
use std::path::Path;

/// A validator that checks that a given key is used within a configured range
/// of indexes.
#[derive(Clone, Debug)]
pub struct KeyRangeValidator {
    config: KeyValidityMap,
}

impl KeyRangeValidator {
    /// Instantiate a validator with the given key validity ranges.
    pub fn new(config: KeyValidityMap) -> Self {
        Self { config }
    }

    /// Load the config from the given TOML file path.
    /// Parses a `metadata-signers.toml` as specified in [MCIP #43](https://github.com/mobilecoinfoundation/mcips/pull/43).
    pub fn load(path: impl AsRef<Path>) -> Result<Self, ParseError> {
        let config = Config::load(path)?.to_validity_map()?;
        Ok(Self { config })
    }

    /// Verifies that the given signing key is allowed at the given block index.
    pub fn validate(
        &self,
        key: &Ed25519Public,
        block_index: BlockIndex,
    ) -> Result<(), ValidationError> {
        let ranges = self.config.get(key).ok_or(ValidationError::UnknownPubKey)?;

        if ranges.iter().any(|range| range.contains(&block_index)) {
            Ok(())
        } else {
            Err(ValidationError::InvalidPubKey)
        }
    }
}
