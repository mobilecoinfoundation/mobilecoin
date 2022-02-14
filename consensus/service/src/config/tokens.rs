// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Tokens configuration.

use mc_common::HashSet;
use mc_consensus_enclave::FeeMap;
use mc_transaction_core::{tokens::Mob, Token, TokenId};
use serde::{Deserialize, Serialize};
use std::{fs, iter::FromIterator, path::Path};

/// Single token configuration.
#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq, Hash)]
pub struct TokenConfig {
    /// Token ID.
    token_id: TokenId,

    /// Minimum fee.
    minimum_fee: Option<u64>,
}

/// Tokens configuration.
#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq, Hash)]
pub struct TokensConfig {
    /// Token configurations (one for each supported token).
    tokens: Vec<TokenConfig>,
}

impl Default for TokensConfig {
    fn default() -> Self {
        Self {
            tokens: vec![TokenConfig {
                token_id: Mob::ID,
                minimum_fee: Some(Mob::MINIMUM_FEE),
            }],
        }
    }
}

impl TokensConfig {
    /// Get the tokens configuration by loading the tokens.toml/json file.
    pub fn load_from_path(path: impl AsRef<Path>) -> Result<Self, String> {
        let path = path.as_ref();

        // Read configuration file.
        let data = fs::read_to_string(path).map_err(|err| err.to_string())?;

        // Parse configuration file.
        let tokens_config: Self = match path.extension().and_then(|ext| ext.to_str()) {
            None => Err("failed figuring out file extension".to_owned()),
            Some("toml") => toml::from_str(&data).map_err(|err| format!("TOML parsing: {:?}", err)),
            Some("json") => {
                serde_json::from_str(&data).map_err(|err| format!("JSON parsing: {:?}", err))
            }
            Some(ext) => Err(format!("Unrecognized extension '{}' in path", ext)),
        }?;

        // Cannot have duplicate configuration for a single token.
        let unique_token_ids =
            HashSet::from_iter(tokens_config.tokens.iter().map(|token| token.token_id));
        if unique_token_ids.len() != tokens_config.tokens.len() {
            return Err("duplicate token configuration found".to_owned());
        }

        // Validate that we have a fee for every token that does not have a supported
        // built-in fee.
        let default_fee_map = FeeMap::default();
        for token in tokens_config.tokens.iter() {
            let has_default_fee = default_fee_map.get_fee_for_token(&token.token_id).is_some();
            if token.minimum_fee.is_none() && !has_default_fee {
                return Err(format!(
                    "missing minimum fee for token id {:?}",
                    token.token_id
                ));
            }
        }

        // Tokens configuration is valid.
        Ok(tokens_config)
    }
}
