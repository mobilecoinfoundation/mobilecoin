// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Tokens configuration.

use crate::consensus_service::ConsensusServiceError;
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

impl TokenConfig {
    /// Token ID.
    pub fn token_id(&self) -> TokenId {
        self.token_id
    }

    /// Minimum fee.
    pub fn minimum_fee_or_default(&self) -> Option<u64> {
        self.minimum_fee
            .or_else(|| FeeMap::default().get_fee_for_token(&self.token_id()))
    }
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
    pub fn load_from_path(path: impl AsRef<Path>) -> Result<Self, ConsensusServiceError> {
        let path = path.as_ref();

        // Read configuration file.
        let data = fs::read_to_string(path).map_err(|err| {
            ConsensusServiceError::Configuration(format!("error reading file: {}", err.to_string()))
        })?;

        // Parse configuration file.
        let tokens_config: Self = match path.extension().and_then(|ext| ext.to_str()) {
            None => Err(ConsensusServiceError::Configuration(
                "failed figuring out file extension".to_owned(),
            )),
            Some("toml") => toml::from_str(&data).map_err(|err| {
                ConsensusServiceError::Configuration(format!("TOML parsing: {:?}", err))
            }),
            Some("json") => serde_json::from_str(&data).map_err(|err| {
                ConsensusServiceError::Configuration(format!("JSON parsing: {:?}", err))
            }),
            Some(ext) => Err(ConsensusServiceError::Configuration(format!(
                "Unrecognized extension '{}'",
                ext
            ))),
        }?;

        tokens_config.validate()?;
        Ok(tokens_config)
    }

    /// Validate the tokens configuration.
    pub fn validate(&self) -> Result<(), ConsensusServiceError> {
        // Cannot have duplicate configuration for a single token.
        let unique_token_ids = HashSet::from_iter(self.tokens.iter().map(|token| token.token_id));
        if unique_token_ids.len() != self.tokens.len() {
            return Err(ConsensusServiceError::Configuration(
                "duplicate token configuration found".to_owned(),
            ));
        }

        // Must have MOB.
        if self.get_token_config(&Mob::ID).is_none() {
            return Err(ConsensusServiceError::Configuration(
                "MOB token configuration not found".to_owned(),
            ));
        }

        // We must have a fee for every token that does not have a built-in default fee.
        let default_fee_map = FeeMap::default();
        for token in self.tokens.iter() {
            let has_default_fee = default_fee_map.get_fee_for_token(&token.token_id).is_some();
            if token.minimum_fee.is_none() && !has_default_fee {
                return Err(ConsensusServiceError::Configuration(format!(
                    "missing minimum fee for token id {:?}",
                    token.token_id
                )));
            }
        }

        // Tokens configuration is valid.
        Ok(())
    }

    /// Get the configuration of a specific token.
    pub fn get_token_config(&self, token_id: &TokenId) -> Option<&TokenConfig> {
        self.tokens.iter().find(|token| token.token_id == *token_id)
    }

    /// Construct a FeeMap based on the configuration.
    pub fn fee_map(&self) -> Result<FeeMap, ConsensusServiceError> {
        let default_fee_map = FeeMap::default();
        FeeMap::try_from_iter(
            self.tokens
                .iter()
                .map(|token_config| {
                    Ok((
                        token_config.token_id,
                        token_config
                            .minimum_fee
                            .or_else(|| default_fee_map.get_fee_for_token(&token_config.token_id))
                            .ok_or_else(|| {
                                ConsensusServiceError::Configuration(format!(
                                    "missing minimum fee for token id {:?}",
                                    token_config.token_id
                                ))
                            })?,
                    ))
                })
                .collect::<Result<Vec<_>, ConsensusServiceError>>()?,
        )
        .map_err(|err| ConsensusServiceError::Configuration(format!("FeeMap: {}", err.to_string())))
    }
    /// Get the entire set of configured tokens.
    pub fn tokens(&self) -> &[TokenConfig] {
        &self.tokens
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_config() {
        let input_toml: &str = r#"
                tokens = []
            "#;
        let tokens: TokensConfig = toml::from_str(input_toml).expect("failed parsing toml");

        let input_json: &str = r#"{
                "tokens": []
            }"#;
        let tokens2: TokensConfig = serde_json::from_str(input_json).expect("failed parsing json");
        assert_eq!(tokens, tokens2);

        // Validation should fail since MOB is not specified.
        assert!(tokens.validate().is_err());
    }

    #[test]
    fn only_mob_config() {
        // With minimum fee.
        {
            let input_toml: &str = r#"
                tokens = [
                    { token_id = 0, minimum_fee = 123 }
                ]
            "#;
            let tokens: TokensConfig = toml::from_str(input_toml).expect("failed parsing toml");

            let input_json: &str = r#"{
                "tokens": [
                    { "token_id": 0, "minimum_fee": 123 }
                ]
            }"#;
            let tokens2: TokensConfig =
                serde_json::from_str(input_json).expect("failed parsing json");
            assert_eq!(tokens, tokens2);

            // Validation should succeed since MOB is specified and has minimum fee.
            assert!(tokens.validate().is_ok());
            assert_eq!(
                tokens.get_token_config(&Mob::ID).unwrap().minimum_fee,
                Some(123)
            );

            // A random token id does not exist.
            assert_eq!(tokens.get_token_config(&TokenId::from(42)), None);
        }

        // Without minimum fee.
        {
            let input_toml: &str = r#"
                tokens = [
                    { token_id = 0 }
                ]
            "#;
            let tokens: TokensConfig = toml::from_str(input_toml).expect("failed parsing toml");

            let input_json: &str = r#"{
                "tokens": [
                    { "token_id": 0 }
                ]
            }"#;
            let tokens2: TokensConfig =
                serde_json::from_str(input_json).expect("failed parsing json");
            assert_eq!(tokens, tokens2);

            // Validation should succeed since MOB is specified and has a default minimum
            // fee.
            assert!(tokens.validate().is_ok());
            assert_eq!(
                tokens
                    .get_token_config(&Mob::ID)
                    .unwrap()
                    .minimum_fee_or_default(),
                Some(Mob::MINIMUM_FEE)
            );
            assert_eq!(tokens.fee_map().unwrap(), FeeMap::default());

            // A random token id does not exist.
            assert_eq!(tokens.get_token_config(&TokenId::from(42)), None);
        }
    }

    #[test]
    fn mob_and_another_token() {
        let test_token = TokenId::from(6);

        // With minimum fee.
        {
            let input_toml: &str = r#"
                tokens = [
                    { token_id = 0, minimum_fee = 123 },
                    { token_id = 6, minimum_fee = 456 }
                ]
            "#;
            let tokens: TokensConfig = toml::from_str(input_toml).expect("failed parsing toml");

            let input_json: &str = r#"{
                "tokens": [
                    { "token_id": 0, "minimum_fee": 123 },
                    { "token_id": 6, "minimum_fee": 456 }
                ]
            }"#;
            let tokens2: TokensConfig =
                serde_json::from_str(input_json).expect("failed parsing json");
            assert_eq!(tokens, tokens2);

            // Validation should succeed since MOB and the secound token have minimum fee
            // configured.
            assert!(tokens.validate().is_ok());
            assert_eq!(
                tokens
                    .get_token_config(&Mob::ID)
                    .unwrap()
                    .minimum_fee_or_default(),
                Some(123)
            );
            assert_eq!(
                tokens
                    .get_token_config(&test_token)
                    .unwrap()
                    .minimum_fee_or_default(),
                Some(456)
            );

            // Fee map looks good.
            assert_eq!(
                tokens.fee_map().unwrap(),
                FeeMap::try_from_iter(vec![(Mob::ID, 123), (test_token, 456)]).unwrap(),
            );

            // A random token id does not exist.
            assert_eq!(tokens.get_token_config(&TokenId::from(42)), None);
        }

        // Without a minimum MOB fee (so we revert to the default one)
        {
            let input_toml: &str = r#"
                tokens = [
                    { token_id = 0 },
                    { token_id = 6, minimum_fee = 456 }
                ]
            "#;
            let tokens: TokensConfig = toml::from_str(input_toml).expect("failed parsing toml");

            let input_json: &str = r#"{
                "tokens": [
                    { "token_id": 0 },
                    { "token_id": 6, "minimum_fee": 456 }
                ]
            }"#;
            let tokens2: TokensConfig =
                serde_json::from_str(input_json).expect("failed parsing json");
            assert_eq!(tokens, tokens2);

            // Validation should succeed since MOB and the secound token have minimum fee
            // configured.
            assert!(tokens.validate().is_ok());
            assert_eq!(
                tokens
                    .get_token_config(&Mob::ID)
                    .unwrap()
                    .minimum_fee_or_default(),
                Some(Mob::MINIMUM_FEE)
            );
            assert_eq!(
                tokens
                    .get_token_config(&test_token)
                    .unwrap()
                    .minimum_fee_or_default(),
                Some(456)
            );

            // Fee map looks good.
            assert_eq!(
                tokens.fee_map().unwrap(),
                FeeMap::try_from_iter(vec![(Mob::ID, Mob::MINIMUM_FEE), (test_token, 456)])
                    .unwrap(),
            );

            // A random token id does not exist.
            assert_eq!(tokens.get_token_config(&TokenId::from(42)), None);
        }

        // Without a minimum fee for the second token that does not have a default fee.
        {
            let input_toml: &str = r#"
                tokens = [
                    { token_id = 0, minimum_fee = 123 },
                    { token_id = 6 }
                ]
            "#;
            let tokens: TokensConfig = toml::from_str(input_toml).expect("failed parsing toml");

            let input_json: &str = r#"{
                "tokens": [
                    { "token_id": 0, "minimum_fee": 123 },
                    { "token_id": 6 }
                ]
            }"#;
            let tokens2: TokensConfig =
                serde_json::from_str(input_json).expect("failed parsing json");
            assert_eq!(tokens, tokens2);

            // Validation should fail since the minimum fee for the second token is unknown.
            assert!(tokens.validate().is_err());

            // Getting the fee map should also fail.
            assert!(tokens.fee_map().is_err());
        }
    }
}
