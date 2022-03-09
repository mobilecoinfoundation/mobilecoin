// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Tokens configuration.

use crate::consensus_service::ConsensusServiceError;
use mc_common::{HashMap, HashSet};
use mc_consensus_enclave::FeeMap;
use mc_crypto_keys::{DistinguishedEncoding, Ed25519Public};
use mc_crypto_multisig::SignerSet;
use mc_transaction_core::{tokens::Mob, Token, TokenId};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::{fs, iter::FromIterator, path::Path};

mod pem_signer_set {
    use super::*;
    use pem::Pem;

    /// A helper struct for ser/derserializing an Ed25519 SignerSet that is PEM
    /// encoded.
    #[derive(Serialize, Deserialize)]
    struct PemSignerSet {
        signers: String,
        threshold: u32,
    }

    /// Helper method for serializing a SignerSet<Ed25519Public> into PEM.
    pub fn serialize<S: Serializer>(
        signer_set: &Option<SignerSet<Ed25519Public>>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        let pem_signer_set = signer_set.as_ref().map(|signer_set| {
            let pems = signer_set
                .signers()
                .iter()
                .map(|signer| Pem {
                    tag: String::from("PUBLIC KEY"),
                    contents: signer.to_der(),
                })
                .collect::<Vec<_>>();

            PemSignerSet {
                signers: pem::encode_many(&pems[..]),
                threshold: signer_set.threshold(),
            }
        });

        pem_signer_set.serialize(serializer)
    }

    /// Helper method for deserializing a PEM-encoded SignerSet<Ed25519Public>.
    pub fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Option<SignerSet<Ed25519Public>>, D::Error> {
        let pem_signer_set: Option<PemSignerSet> = Deserialize::deserialize(deserializer)?;
        match pem_signer_set {
            None => Ok(None),
            Some(pem_signer_set) => {
                let pems = pem::parse_many(pem_signer_set.signers.as_bytes())
                    .map_err(serde::de::Error::custom)?;

                let signers = pems
                    .iter()
                    .map(|pem| {
                        Ed25519Public::try_from_der(&pem.contents[..])
                            .map_err(serde::de::Error::custom)
                    })
                    // Return the keys.
                    .collect::<Result<_, D::Error>>()?;

                Ok(Some(SignerSet::new(signers, pem_signer_set.threshold)))
            }
        }
    }
}

/// Single token configuration.
#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
pub struct TokenConfig {
    /// Token ID.
    token_id: TokenId,

    /// Minimum fee, in the smallest denomination supported by the token (e.g.
    /// picomob for the MOB token).
    minimum_fee: Option<u64>,

    /// Allow extreme fees. Currently the limitation is only enforced for MOB
    /// (>= 1MOB, <= 0.000_000_01 MOB).
    // instructs serde to default to false without explicitly requiring this field to appear in the
    // file.
    #[serde(default)]
    allow_any_fee: bool,

    /// Master minters - if set, controls the set of keys that can sign
    /// set-minting-configuration transactions.
    /// Not supported for MOB
    #[serde(default, with = "pem_signer_set")]
    master_minters: Option<SignerSet<Ed25519Public>>,
}

impl TokenConfig {
    /// Token ID.
    pub fn token_id(&self) -> TokenId {
        self.token_id
    }

    /// Get the configured minimum fee or a default one, if available.
    /// Will return None if the minimum fee is unknown for this token id.
    pub fn minimum_fee_or_default(&self) -> Option<u64> {
        self.minimum_fee
            .or_else(|| FeeMap::default().get_fee_for_token(&self.token_id()))
    }

    /// Master minters config, when available.
    pub fn master_minters(&self) -> Option<&SignerSet<Ed25519Public>> {
        // Can never have master minters for MOB
        if self.token_id == TokenId::MOB {
            return None;
        }
        self.master_minters.as_ref()
    }

    /// Check if the token configuration is valid.
    pub fn validate(&self) -> Result<(), ConsensusServiceError> {
        // We must have a fee for every configured token.
        if self.minimum_fee_or_default().is_none() {
            return Err(ConsensusServiceError::Configuration(
                "missing minimum fee".to_string(),
            ));
        }

        // By default, we restrict MOB minimum fee to a sane value.
        if self.token_id == Mob::ID {
            let mob_fee = self.minimum_fee_or_default().unwrap(); // We are guaranteed to have a minimum fee for MOB.
            if !self.allow_any_fee && !(10_000..1_000_000_000_000u64).contains(&mob_fee) {
                return Err(ConsensusServiceError::Configuration(format!(
                    "Fee {} picoMOB is out of bounds",
                    mob_fee
                )));
            }
        } else {
            // allow_any_fee can only be used for MOB
            if self.allow_any_fee {
                return Err(ConsensusServiceError::Configuration(
                    "allow_any_fee can only be used for MOB".to_string(),
                ));
            }
        }

        // Validate minting configuration if present.
        if let Some(master_minters) = &self.master_minters {
            // MOB cannot be minted.
            if self.token_id == TokenId::MOB {
                return Err(ConsensusServiceError::Configuration(
                    "MOB cannot have minting configuration".to_string(),
                ));
            }

            // We must have at least one master minter.
            if master_minters.signers().is_empty() || master_minters.threshold() == 0 {
                return Err(ConsensusServiceError::Configuration(
                    "must have at least one signer".to_string(),
                ));
            }

            if master_minters.threshold() as usize > master_minters.signers().len() {
                return Err(ConsensusServiceError::Configuration(
                    "signer set threshold is greater than the number of signers".to_string(),
                ));
            }
        }

        // We are valid.
        Ok(())
    }
}

/// Tokens configuration.
#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
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
                allow_any_fee: false,
                master_minters: None,
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

        // Validate the configuration of each token
        for token in self.tokens.iter() {
            token.validate().map_err(|err| {
                if let ConsensusServiceError::Configuration(msg) = err {
                    ConsensusServiceError::Configuration(format!(
                        "token id {}: {}",
                        token.token_id, msg
                    ))
                } else {
                    err
                }
            })?;
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
        self.validate()?;

        FeeMap::try_from_iter(
            self.tokens
                .iter()
                .map(|token_config| {
                    Ok((
                        token_config.token_id,
                        token_config.minimum_fee_or_default().ok_or_else(|| {
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

    /// Get a map of token id -> master minters.
    pub fn token_id_to_master_minters(&self) -> Result<HashMap<TokenId, SignerSet<Ed25519Public>>, ConsensusServiceError> {
        self.validate()?;

        HashMap::from_iter(self.tokens.iter().filter_map(|token_config| {
            if let Some(master_minters) = &token_config.master_minters {
                Some((token_config.token_id, master_minters.clone()))
            } else {
                None
            }
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::convert::TryFrom;

    fn assert_validation_error(tokens: &TokensConfig, err: &str) {
        match tokens.validate() {
            Ok(_) => panic!("expected an error"),
            Err(ConsensusServiceError::Configuration(msg)) => assert_eq!(msg, err),
            Err(e) => panic!("Unexpected error: {}", e),
        }
    }

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
        assert_validation_error(&tokens, "MOB token configuration not found");
    }

    #[test]
    fn no_mob_config_with_minimum_fee() {
        let input_toml: &str = r#"
            [[tokens]]
            token_id = 1
            minimum_fee = 123000
        "#;
        let tokens: TokensConfig = toml::from_str(input_toml).expect("failed parsing toml");

        let input_json: &str = r#"{
            "tokens": [
                { "token_id": 1, "minimum_fee": 123000 }
            ]
        }"#;
        let tokens2: TokensConfig = serde_json::from_str(input_json).expect("failed parsing json");
        assert_eq!(tokens, tokens2);

        // Validation should fail since we must have the MOB token configured.
        assert_validation_error(&tokens, "MOB token configuration not found");
        assert!(tokens.fee_map().is_err());
    }

    #[test]
    fn no_mob_config_without_minimum_fee() {
        let input_toml: &str = r#"
            [[tokens]]
            token_id = 2
        "#;
        let tokens: TokensConfig = toml::from_str(input_toml).expect("failed parsing toml");

        let input_json: &str = r#"{
            "tokens": [
                { "token_id": 2 }
            ]
        }"#;
        let tokens2: TokensConfig = serde_json::from_str(input_json).expect("failed parsing json");
        assert_eq!(tokens, tokens2);

        // Validation should fail since we must have the MOB token configured.
        assert_validation_error(&tokens, "MOB token configuration not found");
        assert!(tokens.fee_map().is_err());
    }

    #[test]
    fn only_mob_config_with_minimum_fee() {
        let input_toml: &str = r#"
            [[tokens]]
            token_id = 0
            minimum_fee = 123000
        "#;
        let tokens: TokensConfig = toml::from_str(input_toml).expect("failed parsing toml");

        let input_json: &str = r#"{
            "tokens": [
                { "token_id": 0, "minimum_fee": 123000 }
            ]
        }"#;
        let tokens2: TokensConfig = serde_json::from_str(input_json).expect("failed parsing json");
        assert_eq!(tokens, tokens2);

        // Validation should succeed since MOB is specified and has minimum fee.
        assert!(tokens.validate().is_ok());
        assert_eq!(
            tokens.get_token_config(&Mob::ID).unwrap().minimum_fee,
            Some(123000)
        );

        // A random token id does not exist.
        assert_eq!(tokens.get_token_config(&TokenId::from(42)), None);
    }

    #[test]
    fn only_mob_config_without_minimum_fee() {
        let input_toml: &str = r#"
            [[tokens]]
            token_id = 0
        "#;
        let tokens: TokensConfig = toml::from_str(input_toml).expect("failed parsing toml");

        let input_json: &str = r#"{
            "tokens": [
                { "token_id": 0 }
            ]
        }"#;
        let tokens2: TokensConfig = serde_json::from_str(input_json).expect("failed parsing json");
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

    #[test]
    fn mob_and_another_token_with_minimum_fee() {
        let test_token = TokenId::from(6);

        let input_toml: &str = r#"
            [[tokens]]
            token_id = 0
            minimum_fee = 123000

            [[tokens]]
            token_id = 6
            minimum_fee = 456000
        "#;
        let tokens: TokensConfig = toml::from_str(input_toml).expect("failed parsing toml");

        let input_json: &str = r#"{
            "tokens": [
                { "token_id": 0, "minimum_fee": 123000 },
                { "token_id": 6, "minimum_fee": 456000 }
            ]
        }"#;
        let tokens2: TokensConfig = serde_json::from_str(input_json).expect("failed parsing json");
        assert_eq!(tokens, tokens2);

        // Validation should succeed since MOB and the secound token have minimum fee
        // configured.
        assert!(tokens.validate().is_ok());
        assert_eq!(
            tokens
                .get_token_config(&Mob::ID)
                .unwrap()
                .minimum_fee_or_default(),
            Some(123000)
        );
        assert_eq!(
            tokens
                .get_token_config(&test_token)
                .unwrap()
                .minimum_fee_or_default(),
            Some(456000)
        );

        // Fee map looks good.
        assert_eq!(
            tokens.fee_map().unwrap(),
            FeeMap::try_from_iter(vec![(Mob::ID, 123000), (test_token, 456000)]).unwrap(),
        );

        // A random token id does not exist.
        assert_eq!(tokens.get_token_config(&TokenId::from(42)), None);
    }

    #[test]
    fn mob_and_another_token_without_minimum_fee_reverts_to_default() {
        let test_token = TokenId::from(6);
        let input_toml: &str = r#"
            [[tokens]]
            token_id = 0

            [[tokens]]
            token_id = 6
            minimum_fee = 456000
        "#;
        let tokens: TokensConfig = toml::from_str(input_toml).expect("failed parsing toml");

        let input_json: &str = r#"{
            "tokens": [
                { "token_id": 0 },
                { "token_id": 6, "minimum_fee": 456000 }
            ]
        }"#;
        let tokens2: TokensConfig = serde_json::from_str(input_json).expect("failed parsing json");
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
            Some(456000)
        );

        // Fee map looks good.
        assert_eq!(
            tokens.fee_map().unwrap(),
            FeeMap::try_from_iter(vec![(Mob::ID, Mob::MINIMUM_FEE), (test_token, 456000)]).unwrap(),
        );

        // A random token id does not exist.
        assert_eq!(tokens.get_token_config(&TokenId::from(42)), None);
    }

    // Without a minimum fee for the second token that does not have a default fee.
    #[test]
    fn mob_and_another_token_without_minimum_fee_and_no_default() {
        let input_toml: &str = r#"
            [[tokens]]
            token_id = 0
            minimum_fee = 123000

            [[tokens]]
            token_id = 6
        "#;
        let tokens: TokensConfig = toml::from_str(input_toml).expect("failed parsing toml");

        let input_json: &str = r#"{
            "tokens": [
                { "token_id": 0, "minimum_fee": 123000 },
                { "token_id": 6 }
            ]
        }"#;
        let tokens2: TokensConfig = serde_json::from_str(input_json).expect("failed parsing json");
        assert_eq!(tokens, tokens2);

        // Validation should fail since the minimum fee for the second token is unknown.
        assert_validation_error(&tokens, "token id 6: missing minimum fee");

        // Getting the fee map should also fail.
        assert!(tokens.fee_map().is_err());
    }

    #[test]
    fn cant_use_allow_any_fee_on_non_mob_tokens() {
        let input_toml: &str = r#"
            [[tokens]]
            token_id = 0

            [[tokens]]
            token_id = 1
            minimum_fee = 123000
            allow_any_fee = true
        "#;
        let tokens: TokensConfig = toml::from_str(input_toml).expect("failed parsing toml");

        let input_json: &str = r#"{
            "tokens": [
                { "token_id": 0 },
                { "token_id": 1, "minimum_fee": 123000, "allow_any_fee": true }
            ]
        }"#;
        let tokens2: TokensConfig = serde_json::from_str(input_json).expect("failed parsing json");
        assert_eq!(tokens, tokens2);

        // Validation should fail since allow_any_fee cannot be used on non-MOB tokens.
        assert_validation_error(
            &tokens,
            "token id 1: allow_any_fee can only be used for MOB",
        );
    }

    #[test]
    fn cant_use_small_fee_on_mob_without_allow_any_fee() {
        let input_toml: &str = r#"
            [[tokens]]
            token_id = 0
            minimum_fee = 1
        "#;
        let tokens: TokensConfig = toml::from_str(input_toml).expect("failed parsing toml");

        let input_json: &str = r#"{
            "tokens": [
                { "token_id": 0, "minimum_fee": 1 }
            ]
        }"#;
        let tokens2: TokensConfig = serde_json::from_str(input_json).expect("failed parsing json");
        assert_eq!(tokens, tokens2);

        // Validation should fail since the fee is outside the allowed eange.
        assert_validation_error(&tokens, "token id 0: Fee 1 picoMOB is out of bounds");
    }

    #[test]
    fn cant_use_small_fee_on_mob_with_allow_any_fee_false() {
        let input_toml: &str = r#"
            [[tokens]]
            token_id = 0
            minimum_fee = 1
            allow_any_fee = false
        "#;
        let tokens: TokensConfig = toml::from_str(input_toml).expect("failed parsing toml");

        let input_json: &str = r#"{
            "tokens": [
                { "token_id": 0, "minimum_fee": 1, "allow_any_fee": false }
            ]
        }"#;
        let tokens2: TokensConfig = serde_json::from_str(input_json).expect("failed parsing json");
        assert_eq!(tokens, tokens2);

        // Validation should fail since the fee is outside the allowed eange.
        assert_validation_error(&tokens, "token id 0: Fee 1 picoMOB is out of bounds");
    }

    #[test]
    fn allow_any_fee_allows_small_mob_fee() {
        let input_toml: &str = r#"
            [[tokens]]
            token_id = 0
            minimum_fee = 1
            allow_any_fee = true
        "#;
        let tokens: TokensConfig = toml::from_str(input_toml).expect("failed parsing toml");

        let input_json: &str = r#"{
            "tokens": [
                { "token_id": 0, "minimum_fee": 1, "allow_any_fee": true }
            ]
        }"#;
        let tokens2: TokensConfig = serde_json::from_str(input_json).expect("failed parsing json");
        assert_eq!(tokens, tokens2);

        // Validation should succeed since allow_any_fee was true.
        assert!(tokens.validate().is_ok());
        assert_eq!(
            tokens
                .get_token_config(&Mob::ID)
                .unwrap()
                .minimum_fee_or_default(),
            Some(1)
        );
    }

    #[test]
    fn master_minters_serialize_deserialize_works() {
        let token_config = TokenConfig {
            token_id: TokenId::from(123),
            minimum_fee: Some(456),
            allow_any_fee: false,
            master_minters: Some(SignerSet::new(
                vec![
                    Ed25519Public::try_from(&[3u8; 32][..]).unwrap(),
                    Ed25519Public::try_from(&[123u8; 32][..]).unwrap(),
                ],
                1,
            )),
        };

        let bytes = mc_util_serial::serialize(&token_config).unwrap();
        let token_config2: TokenConfig = mc_util_serial::deserialize(&bytes).unwrap();

        assert_eq!(token_config, token_config2);
    }

    #[test]
    fn valid_minting_config() {
        // Keys were generated using:
        // ```sh
        // pri_pem=$(openssl genpkey -algorithm ED25519)
        // pri_der=$(echo -n "${pri_pem}" | openssl pkey -outform DER | openssl base64)
        // echo -n "${pri_pem}" | openssl pkey -pubout
        // ```

        let pem1 = pem::parse(
            r#"-----BEGIN PUBLIC KEY-----
            MCowBQYDK2VwAyEAyj6m0NRTlw/R28Q+R7vBakwybuaNFneKrvRVAYNp5WQ=
            -----END PUBLIC KEY-----"#,
        )
        .unwrap();
        let key1 = Ed25519Public::try_from_der(&pem1.contents[..]).unwrap();

        let pem2 = pem::parse(
            r#"-----BEGIN PUBLIC KEY-----
            MCowBQYDK2VwAyEAl3XVo/DeiTjHn8dYQuEtBjQrEWNQSKpfzw3X9dewSVY=
            -----END PUBLIC KEY-----"#,
        )
        .unwrap();
        let key2 = Ed25519Public::try_from_der(&pem2.contents[..]).unwrap();

        let input_toml: &str = r#"
            [[tokens]]
            token_id = 0 # Must have MOB
            
            [[tokens]]
            token_id = 1
            minimum_fee = 1
            [tokens.master_minters]
            signers = """
            -----BEGIN PUBLIC KEY-----
            MCowBQYDK2VwAyEAyj6m0NRTlw/R28Q+R7vBakwybuaNFneKrvRVAYNp5WQ=
            -----END PUBLIC KEY-----
            -----BEGIN PUBLIC KEY-----
            MCowBQYDK2VwAyEAl3XVo/DeiTjHn8dYQuEtBjQrEWNQSKpfzw3X9dewSVY=
            -----END PUBLIC KEY-----
            """
            threshold = 1
       "#;
        let tokens: TokensConfig = toml::from_str(input_toml).expect("failed parsing toml");

        let input_json: &str = r#"{
            "tokens": [
                { "token_id": 0 },
                {
                    "token_id": 1,
                    "minimum_fee": 1,
                    "master_minters": {
                        "signers": "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAyj6m0NRTlw/R28Q+R7vBakwybuaNFneKrvRVAYNp5WQ=\n-----END PUBLIC KEY-----\n-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAl3XVo/DeiTjHn8dYQuEtBjQrEWNQSKpfzw3X9dewSVY=\n-----END PUBLIC KEY-----",
                        "threshold": 1
                    }
                }
            ]
        }"#;
        let tokens2: TokensConfig = serde_json::from_str(input_json).expect("failed parsing json");
        assert_eq!(tokens, tokens2);

        // Validation should succeed since the configuration is valid.
        assert!(tokens.validate().is_ok());

        // Keys should've decoded successfully.
        assert_eq!(
            tokens
                .get_token_config(&TokenId::from(1))
                .unwrap()
                .master_minters()
                .unwrap()
                .signers()[0],
            key1
        );

        assert_eq!(
            tokens
                .get_token_config(&TokenId::from(1))
                .unwrap()
                .master_minters()
                .unwrap()
                .signers()[1],
            key2
        );
    }

    #[test]
    fn cannot_specify_minting_config_for_mob() {
        let input_toml: &str = r#"
            [[tokens]]
            token_id = 0
            
            [tokens.master_minters]
            signers = """
            -----BEGIN PUBLIC KEY-----
            MCowBQYDK2VwAyEAyj6m0NRTlw/R28Q+R7vBakwybuaNFneKrvRVAYNp5WQ=
            -----END PUBLIC KEY-----
            """
             threshold = 1
       "#;

        let tokens: TokensConfig = toml::from_str(input_toml).expect("failed parsing toml");

        assert_validation_error(&tokens, "token id 0: MOB cannot have minting configuration");
    }

    #[test]
    fn cannot_have_no_signers() {
        let input_toml: &str = r#"
            [[tokens]]
            token_id = 0 # Must have MOB
            
            [[tokens]]
            token_id = 2
            minimum_fee = 1
            [tokens.master_minters]
            signers = ""
            threshold = 1
       "#;

        let tokens: TokensConfig = toml::from_str(input_toml).expect("failed parsing toml");

        assert_validation_error(&tokens, "token id 2: must have at least one signer");
    }

    #[test]
    fn cannot_have_zero_threshold() {
        let input_toml: &str = r#"
            [[tokens]]
            token_id = 0 # Must have MOB
            [[tokens]]
            token_id = 2
            minimum_fee = 1
            [tokens.master_minters]
            signers = """
            -----BEGIN PUBLIC KEY-----
            MCowBQYDK2VwAyEAyj6m0NRTlw/R28Q+R7vBakwybuaNFneKrvRVAYNp5WQ=
            -----END PUBLIC KEY-----
            """
            threshold = 0
       "#;

        let tokens: TokensConfig = toml::from_str(input_toml).expect("failed parsing toml");

        assert_validation_error(&tokens, "token id 2: must have at least one signer");
    }

    #[test]
    fn cannot_have_duplicate_token_ids() {
        let input_toml: &str = r#"
            [[tokens]]
            token_id = 0

            [[tokens]]
            token_id = 1
            minimum_fee = 123000

            [[tokens]]
            token_id = 1
            minimum_fee = 123000
        "#;
        let tokens: TokensConfig = toml::from_str(input_toml).expect("failed parsing toml");

        // Validation should fail since we must have the MOB token configured.
        assert_validation_error(&tokens, "duplicate token configuration found");
        assert!(tokens.fee_map().is_err());
    }
}
