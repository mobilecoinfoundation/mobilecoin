// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Tokens configuration.

use crate::{
    error::Error,
    signer_identity::{SignerIdentity, SignerIdentityMap},
};
use mc_common::HashSet;
use mc_consensus_enclave_api::{GovernorsMap, GovernorsVerifier};
use mc_crypto_keys::{Ed25519Public, Ed25519Signature};
use mc_crypto_multisig::SignerSet;
use mc_transaction_core::{tokens::Mob, FeeMap, Token, TokenId};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::{fs, ops::Range, path::Path};

/// Sane values for MOB, enforced unless the allow_any_fee option is used.
pub const ACCEPTABLE_MOB_FEE_VALUES: Range<u64> = 10_000..1_000_000_000_000u64;

mod hex_signature {
    use super::*;

    /// Helper method for serializing an Ed25519Signature into a hex string.
    pub fn serialize<S: Serializer>(
        signature: &Option<Ed25519Signature>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        signature.as_ref().map(hex::encode).serialize(serializer)
    }

    /// A helper method for deserializing an Ed25519Signature from a hex string.
    pub fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Option<Ed25519Signature>, D::Error> {
        let hex_string: Option<String> = Deserialize::deserialize(deserializer)?;
        match hex_string.as_deref() {
            None | Some("") => Ok(None),
            Some(hex_string) => {
                let bytes = hex::decode(hex_string).map_err(serde::de::Error::custom)?;
                Ok(Some(
                    Ed25519Signature::try_from(&bytes[..]).map_err(serde::de::Error::custom)?,
                ))
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

    /// Signer identities - this allows the configuration to contain a human
    /// readable mapping of names to signer identities.
    #[serde(default)]
    signer_identities: SignerIdentityMap,

    /// Governors - if set, controls the set of keys that can sign
    /// minting-configuration transactions.
    /// Not supported for MOB
    #[serde(default)]
    governors: Option<SignerIdentity>,
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

    /// Governors config, when available.
    pub fn governors(&self) -> Result<Option<SignerSet<Ed25519Public>>, Error> {
        // Can never have governors for MOB
        if self.token_id == TokenId::MOB {
            return Ok(None);
        }
        self.governors
            .as_ref()
            .map(|governors| {
                governors
                    .try_into_signer_set(&self.signer_identities)
                    .map_err(|err| Error::InvalidSignerSet(self.token_id, err))
            })
            .transpose()
    }

    /// Check if the token configuration is valid.
    pub fn validate(&self) -> Result<(), Error> {
        // We must have a fee for every configured token.
        if self.minimum_fee_or_default().is_none() {
            return Err(Error::MissingMinimumFee(self.token_id));
        }

        // By default, we restrict MOB minimum fee to a sane value.
        if self.token_id == Mob::ID {
            let mob_fee = self.minimum_fee_or_default().unwrap(); // We are guaranteed to have a minimum fee for MOB.
            if !self.allow_any_fee && !ACCEPTABLE_MOB_FEE_VALUES.contains(&mob_fee) {
                return Err(Error::FeeOutOfBounds(mob_fee, self.token_id));
            }
        } else {
            // allow_any_fee can only be used for MOB
            if self.allow_any_fee {
                return Err(Error::AllowAnyFeeNotAllowed(self.token_id));
            }
        }

        // Validate minting configuration if present.
        if let Some(governors) = &self.governors {
            // MOB cannot be minted - it should not have a governors configuration.
            if self.token_id == TokenId::MOB {
                return Err(Error::MintConfigNotAllowed(self.token_id));
            }

            // We have a governors configuration, see if it can be converted to a valid
            // signer set, and abort if not.
            if let Err(err) = governors.try_into_signer_set(&self.signer_identities) {
                return Err(Error::InvalidSignerSet(self.token_id, err));
            }
        }

        // We are valid.
        Ok(())
    }
}

/// Tokens configuration.
#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
pub struct TokensConfig {
    /// Governors signature generated using the `mc-consensus-mint-client
    /// sign-governors` command.
    #[serde(default, with = "hex_signature")]
    pub governors_signature: Option<Ed25519Signature>,

    /// Token configurations (one for each supported token).
    tokens: Vec<TokenConfig>,
}

impl Default for TokensConfig {
    fn default() -> Self {
        Self {
            governors_signature: None,
            tokens: vec![TokenConfig {
                token_id: Mob::ID,
                minimum_fee: Some(Mob::MINIMUM_FEE),
                allow_any_fee: false,
                signer_identities: Default::default(),
                governors: None,
            }],
        }
    }
}

impl TokensConfig {
    /// Get the tokens configuration by loading the tokens.json file.
    pub fn load_from_path(path: impl AsRef<Path>) -> Result<Self, Error> {
        let path = path.as_ref();

        // Read configuration file.
        let data = fs::read_to_string(path)?;

        // Parse configuration file.
        let tokens_config: Self = match path.extension().and_then(|ext| ext.to_str()) {
            None => Err(Error::PathExtension),
            Some("json") => serde_json::from_str(&data).map_err(Error::from),
            Some(ext) => Err(Error::UnrecognizedExtension(ext.to_string())),
        }?;

        tokens_config.validate()?;
        Ok(tokens_config)
    }

    /// Validate the tokens configuration.
    pub fn validate(&self) -> Result<(), Error> {
        // Cannot have duplicate configuration for a single token.
        let unique_token_ids = HashSet::from_iter(self.tokens.iter().map(|token| token.token_id));
        if unique_token_ids.len() != self.tokens.len() {
            return Err(Error::DuplicateTokenConfig);
        }

        // Must have MOB.
        if self.get_token_config(&Mob::ID).is_none() {
            return Err(Error::MissingMobConfig);
        }

        // Validate the configuration of each token
        for token in self.tokens.iter() {
            token.validate()?;
        }

        // Tokens configuration is valid.
        Ok(())
    }

    /// Get the configuration of a specific token.
    pub fn get_token_config(&self, token_id: &TokenId) -> Option<&TokenConfig> {
        self.tokens.iter().find(|token| token.token_id == *token_id)
    }

    /// Construct a FeeMap based on the configuration.
    pub fn fee_map(&self) -> Result<FeeMap, Error> {
        self.validate()?;

        Ok(FeeMap::try_from_iter(
            self.tokens
                .iter()
                .map(|token_config| {
                    Ok((
                        token_config.token_id,
                        token_config
                            .minimum_fee_or_default()
                            .ok_or(Error::MissingMinimumFee(token_config.token_id))?,
                    ))
                })
                .collect::<Result<Vec<_>, Error>>()?,
        )?)
    }
    /// Get the entire set of configured tokens.
    pub fn tokens(&self) -> &[TokenConfig] {
        &self.tokens
    }

    /// Get a map of token id -> governors.
    pub fn token_id_to_governors(&self) -> Result<GovernorsMap, Error> {
        self.validate()?;

        Ok(GovernorsMap::try_from_iter(
            self.tokens
                .iter()
                .map(|token_config| {
                    token_config.governors().map(|govenors| {
                        govenors.map(|governors| (token_config.token_id(), governors))
                    })
                })
                .collect::<Result<Vec<_>, Error>>()?
                .into_iter()
                .flatten(),
        )?)
    }

    /// Verify the governors signature against a given public key
    pub fn verify_governors_signature(&self, key: &Ed25519Public) -> Result<(), Error> {
        let governors_map = self.token_id_to_governors()?;
        let signature = self
            .governors_signature
            .as_ref()
            .ok_or(Error::MissingGovernorsSignature)?;
        Ok(key.verify_governors_map(&governors_map, signature)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mc_crypto_keys::{DistinguishedEncoding, Ed25519Private};

    #[test]
    fn empty_config() {
        let input_json: &str = r#"{
            "tokens": []
        }"#;
        let tokens: TokensConfig = serde_json::from_str(input_json).expect("failed parsing json");

        // Validation should fail since MOB is not specified.
        assert!(matches!(tokens.validate(), Err(Error::MissingMobConfig)));
    }

    #[test]
    fn no_mob_config_with_minimum_fee() {
        let input_json: &str = r#"{
            "tokens": [
                { "token_id": 1, "minimum_fee": 128000 }
            ]
        }"#;
        let tokens: TokensConfig = serde_json::from_str(input_json).expect("failed parsing json");

        // Validation should fail since we must have the MOB token configured.
        assert!(matches!(tokens.validate(), Err(Error::MissingMobConfig)));
        assert!(tokens.fee_map().is_err());
    }

    #[test]
    fn no_mob_config_without_minimum_fee() {
        let input_json: &str = r#"{
            "tokens": [
                { "token_id": 2 }
            ]
        }"#;
        let tokens: TokensConfig = serde_json::from_str(input_json).expect("failed parsing json");

        // Validation should fail since we must have the MOB token configured.
        assert!(matches!(tokens.validate(), Err(Error::MissingMobConfig)));
        assert!(tokens.fee_map().is_err());
    }

    #[test]
    fn only_mob_config_with_minimum_fee() {
        let input_json: &str = r#"{
            "tokens": [
                { "token_id": 0, "minimum_fee": 128000 }
            ]
        }"#;
        let tokens: TokensConfig = serde_json::from_str(input_json).expect("failed parsing json");

        // Validation should succeed since MOB is specified and has minimum fee.
        assert!(tokens.validate().is_ok());
        assert_eq!(
            tokens.get_token_config(&Mob::ID).unwrap().minimum_fee,
            Some(128000)
        );

        // A random token id does not exist.
        assert_eq!(tokens.get_token_config(&TokenId::from(42)), None);
    }

    #[test]
    fn only_mob_config_without_minimum_fee() {
        let input_json: &str = r#"{
            "tokens": [
                { "token_id": 0 }
            ]
        }"#;
        let tokens: TokensConfig = serde_json::from_str(input_json).expect("failed parsing json");

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

        let input_json: &str = r#"{
            "tokens": [
                { "token_id": 0, "minimum_fee": 128000 },
                { "token_id": 6, "minimum_fee": 512000 }
            ]
        }"#;
        let tokens: TokensConfig = serde_json::from_str(input_json).expect("failed parsing json");

        // Validation should succeed since MOB and the secound token have minimum fee
        // configured.
        assert!(tokens.validate().is_ok());
        assert_eq!(
            tokens
                .get_token_config(&Mob::ID)
                .unwrap()
                .minimum_fee_or_default(),
            Some(128000)
        );
        assert_eq!(
            tokens
                .get_token_config(&test_token)
                .unwrap()
                .minimum_fee_or_default(),
            Some(512000)
        );

        // Fee map looks good.
        assert_eq!(
            tokens.fee_map().unwrap(),
            FeeMap::try_from_iter(vec![(Mob::ID, 128000), (test_token, 512000)]).unwrap(),
        );

        // A random token id does not exist.
        assert_eq!(tokens.get_token_config(&TokenId::from(42)), None);
    }

    #[test]
    fn mob_and_another_token_without_minimum_fee_reverts_to_default() {
        let test_token = TokenId::from(6);

        let input_json: &str = r#"{
            "tokens": [
                { "token_id": 0 },
                { "token_id": 6, "minimum_fee": 512000 }
            ]
        }"#;
        let tokens: TokensConfig = serde_json::from_str(input_json).expect("failed parsing json");

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
            Some(512000)
        );

        // Fee map looks good.
        assert_eq!(
            tokens.fee_map().unwrap(),
            FeeMap::try_from_iter(vec![(Mob::ID, Mob::MINIMUM_FEE), (test_token, 512000)]).unwrap(),
        );

        // A random token id does not exist.
        assert_eq!(tokens.get_token_config(&TokenId::from(42)), None);
    }

    // Without a minimum fee for the second token that does not have a default fee.
    #[test]
    fn mob_and_another_token_without_minimum_fee_and_no_default() {
        let input_json: &str = r#"{
            "tokens": [
                { "token_id": 0, "minimum_fee": 128000 },
                { "token_id": 6 }
            ]
        }"#;
        let tokens: TokensConfig = serde_json::from_str(input_json).expect("failed parsing json");

        // Validation should fail since the minimum fee for the second token is unknown.
        assert!(
            matches!(tokens.validate(), Err(Error::MissingMinimumFee(token_id)) if token_id == 6)
        );

        // Getting the fee map should also fail.
        assert!(tokens.fee_map().is_err());
    }

    #[test]
    fn cant_use_allow_any_fee_on_non_mob_tokens() {
        let input_json: &str = r#"{
            "tokens": [
                { "token_id": 0 },
                { "token_id": 1, "minimum_fee": 128000, "allow_any_fee": true }
            ]
        }"#;
        let tokens: TokensConfig = serde_json::from_str(input_json).expect("failed parsing json");

        // Validation should fail since allow_any_fee cannot be used on non-MOB tokens.
        assert!(
            matches!(tokens.validate(), Err(Error::AllowAnyFeeNotAllowed(token_id)) if token_id == 1)
        );
    }

    #[test]
    fn cant_use_small_fee_on_mob_without_allow_any_fee() {
        let input_json: &str = r#"{
            "tokens": [
                { "token_id": 0, "minimum_fee": 1 }
            ]
        }"#;
        let tokens: TokensConfig = serde_json::from_str(input_json).expect("failed parsing json");

        // Validation should fail since the fee is outside the allowed eange.
        assert!(
            matches!(tokens.validate(), Err(Error::FeeOutOfBounds(fee, token_id)) if fee == 1 && token_id == Mob::ID)
        );
    }

    #[test]
    fn cant_use_small_fee_on_mob_with_allow_any_fee_false() {
        let input_json: &str = r#"{
            "tokens": [
                { "token_id": 0, "minimum_fee": 1, "allow_any_fee": false }
            ]
        }"#;
        let tokens: TokensConfig = serde_json::from_str(input_json).expect("failed parsing json");

        // Validation should fail since the fee is outside the allowed range.
        assert!(
            matches!(tokens.validate(), Err(Error::FeeOutOfBounds(fee, token_id)) if fee == 1 && token_id == Mob::ID)
        );
    }

    #[test]
    fn allow_any_fee_allows_small_mob_fee() {
        let input_json: &str = r#"{
            "tokens": [
                { "token_id": 0, "minimum_fee": 1, "allow_any_fee": true }
            ]
        }"#;
        let tokens: TokensConfig = serde_json::from_str(input_json).expect("failed parsing json");

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
    fn governors_serialize_deserialize_works() {
        let input_json: &str = r#"{
            "governors_signature": "03e9e3e55724057a9e8e94dbfd1f166ea2c033aa53f5cf48942e103cde62c56655234cac2f5bffcbf9bdfb4e68ab6a2f23138accbc914e3c569838f9de058e0c",
            "tokens": [
                { "token_id": 0 },
                {
                    "token_id": 1,
                    "minimum_fee": 1,
                    "signer_identities": {
                        "signer1": {"type": "Single", "pub_key": "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAyj6m0NRTlw/R28Q+R7vBakwybuaNFneKrvRVAYNp5WQ=\n-----END PUBLIC KEY-----\n"},
                        "signer2": {"type": "Single", "pub_key": "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAl3XVo/DeiTjHn8dYQuEtBjQrEWNQSKpfzw3X9dewSVY=\n-----END PUBLIC KEY-----\n"}
                    },
                    "governors": {
                        "type": "MultiSig",
                        "threshold": 1,
                        "signers": [
                            {"type": "Identity", "name": "signer1"},
                            {"type": "Identity", "name": "signer2"}
                        ]
                    }
                }
            ]
        }"#;
        let tokens: TokensConfig = serde_json::from_str(input_json).expect("failed parsing json");

        let bytes = mc_util_serial::serialize(&tokens).unwrap();
        let tokens2 = mc_util_serial::deserialize(&bytes).unwrap();

        assert_eq!(tokens, tokens2);
    }

    #[test]
    fn valid_minting_config() {
        // Key generating using `openssl genpkey -algorithm ED25519`
        let minting_trust_root_private_key_pem = pem::parse(
            r#"-----BEGIN PRIVATE KEY-----
                MC4CAQAwBQYDK2VwBCIEIC4Z5GeRSzvx61R4ydQK/1bOGLLDGptNwsEnzaMTV9KI
                -----END PRIVATE KEY-----"#,
        )
        .unwrap();
        let minting_trust_root_private_key =
            Ed25519Private::try_from_der(&minting_trust_root_private_key_pem.contents[..]).unwrap();

        // Keys were generated using:
        // ```sh
        // pri_pem=$(openssl genpkey -algorithm ED25519)
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

        let pem3 = pem::parse(
            r#"-----BEGIN PUBLIC KEY-----
                MCowBQYDK2VwAyEAmMQUAJgqpOc0Z7NAwa+4JqAh+DCVB0TQy9zj+8xRRDc=
                -----END PUBLIC KEY-----"#,
        )
        .unwrap();
        let key3 = Ed25519Public::try_from_der(&pem3.contents[..]).unwrap();

        // Signature generated by taking the file and the admin private key above and
        // running: cargo run --bin mc-consensus-mint-client -- sign-governors
        // --tokens tokens.json --signing-key private.pem
        let input_json: &str = r#"{
            "governors_signature": "03e9e3e55724057a9e8e94dbfd1f166ea2c033aa53f5cf48942e103cde62c56655234cac2f5bffcbf9bdfb4e68ab6a2f23138accbc914e3c569838f9de058e0c",
            "tokens": [
                { "token_id": 0 },
                {
                    "token_id": 1,
                    "minimum_fee": 1,
                    "signer_identities": {
                        "signer1": {"type": "Single", "pub_key": "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAyj6m0NRTlw/R28Q+R7vBakwybuaNFneKrvRVAYNp5WQ=\n-----END PUBLIC KEY-----\n"},
                        "signer2": {"type": "Single", "pub_key": "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAl3XVo/DeiTjHn8dYQuEtBjQrEWNQSKpfzw3X9dewSVY=\n-----END PUBLIC KEY-----\n"},
                        "signer3": {"type": "Single", "pub_key": "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAmMQUAJgqpOc0Z7NAwa+4JqAh+DCVB0TQy9zj+8xRRDc=\n-----END PUBLIC KEY-----\n"}
                    },
                    "governors": {
                        "type": "MultiSig",
                        "threshold": 1,
                        "signers": [
                            {"type": "Identity", "name": "signer1"},
                            {"type": "Identity", "name": "signer2"},
                            {
                                "type": "MultiSig",
                                "threshold": 2,
                                "signers": [
                                    {"type": "Identity", "name": "signer1"},
                                    {"type": "Identity", "name": "signer2"},
                                    {"type": "Identity", "name": "signer3"}
                                ]
                            }
                        ]
                    }
                }
            ]
        }"#;
        let tokens: TokensConfig = serde_json::from_str(input_json).expect("failed parsing json");

        // Validation should succeed since the configuration is valid.
        assert!(tokens.validate().is_ok());

        // Keys should've decoded successfully.
        let governors = tokens
            .get_token_config(&TokenId::from(1))
            .unwrap()
            .governors()
            .unwrap()
            .unwrap();

        assert_eq!(
            governors,
            SignerSet::new_with_multi(
                vec![key1, key2],
                vec![SignerSet::new(vec![key1, key2, key3], 2)],
                1
            )
        );

        // The governors signature should've decoded successfully.
        tokens
            .verify_governors_signature(&Ed25519Public::from(&minting_trust_root_private_key))
            .unwrap();
    }

    #[test]
    fn cannot_specify_minting_config_for_mob() {
        let input_json: &str = r#"{
            "tokens": [
                {
                    "token_id": 0,
                    "signer_identities": {
                        "signer1": {"type": "Single", "pub_key": "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAyj6m0NRTlw/R28Q+R7vBakwybuaNFneKrvRVAYNp5WQ=\n-----END PUBLIC KEY-----\n"},
                        "signer2": {"type": "Single", "pub_key": "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAl3XVo/DeiTjHn8dYQuEtBjQrEWNQSKpfzw3X9dewSVY=\n-----END PUBLIC KEY-----\n"}
                    },
                    "governors": {
                        "type": "MultiSig",
                        "threshold": 1,
                        "signers": [
                            {"type": "Identity", "name": "signer1"},
                            {"type": "Identity", "name": "signer2"}
                        ]
                    }
                }
            ]
        }"#;
        let tokens: TokensConfig = serde_json::from_str(input_json).expect("failed parsing json");

        assert!(
            matches!(tokens.validate(), Err(Error::MintConfigNotAllowed(token_id)) if token_id == Mob::ID)
        );
    }

    #[test]
    fn cannot_have_no_signers() {
        let input_json: &str = r#"{
            "governors_signature": "03e9e3e55724057a9e8e94dbfd1f166ea2c033aa53f5cf48942e103cde62c56655234cac2f5bffcbf9bdfb4e68ab6a2f23138accbc914e3c569838f9de058e0c",
            "tokens": [
                { "token_id": 0 },
                {
                    "token_id": 2,
                    "minimum_fee": 1,
                    "signer_identities": {
                        "signer1": {"type": "Single", "pub_key": "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAyj6m0NRTlw/R28Q+R7vBakwybuaNFneKrvRVAYNp5WQ=\n-----END PUBLIC KEY-----\n"},
                        "signer2": {"type": "Single", "pub_key": "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAl3XVo/DeiTjHn8dYQuEtBjQrEWNQSKpfzw3X9dewSVY=\n-----END PUBLIC KEY-----\n"}
                    },
                    "governors": {
                        "type": "MultiSig",
                        "threshold": 1,
                        "signers": []
                    }
                }
            ]
        }"#;
        let tokens: TokensConfig = serde_json::from_str(input_json).expect("failed parsing json");

        assert!(
            matches!(tokens.validate(), Err(Error::InvalidSignerSet(token_id, _)) if token_id == 2)
        );
    }

    #[test]
    fn cannot_have_zero_threshold() {
        let input_json: &str = r#"{
            "governors_signature": "03e9e3e55724057a9e8e94dbfd1f166ea2c033aa53f5cf48942e103cde62c56655234cac2f5bffcbf9bdfb4e68ab6a2f23138accbc914e3c569838f9de058e0c",
            "tokens": [
                { "token_id": 0 },
                {
                    "token_id": 2,
                    "minimum_fee": 1,
                    "signer_identities": {
                        "signer1": {"type": "Single", "pub_key": "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAyj6m0NRTlw/R28Q+R7vBakwybuaNFneKrvRVAYNp5WQ=\n-----END PUBLIC KEY-----\n"},
                        "signer2": {"type": "Single", "pub_key": "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAl3XVo/DeiTjHn8dYQuEtBjQrEWNQSKpfzw3X9dewSVY=\n-----END PUBLIC KEY-----\n"}
                    },
                    "governors": {
                        "type": "MultiSig",
                        "threshold": 0,
                        "signers": [
                            {"type": "Identity", "name": "signer1"},
                            {"type": "Identity", "name": "signer2"}
                        ]
                    }
                }
            ]
        }"#;
        let tokens: TokensConfig = serde_json::from_str(input_json).expect("failed parsing json");

        assert!(
            matches!(tokens.validate(), Err(Error::InvalidSignerSet(token_id, _)) if token_id == 2)
        );
    }

    #[test]
    fn cannot_have_duplicate_token_ids() {
        let input_json: &str = r#"{
            "governors_signature": "03e9e3e55724057a9e8e94dbfd1f166ea2c033aa53f5cf48942e103cde62c56655234cac2f5bffcbf9bdfb4e68ab6a2f23138accbc914e3c569838f9de058e0c",
            "tokens": [
                { "token_id": 0 },
                {
                    "token_id": 1,
                    "minimum_fee": 1,
                    "signer_identities": {
                        "signer1": {"type": "Single", "pub_key": "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAyj6m0NRTlw/R28Q+R7vBakwybuaNFneKrvRVAYNp5WQ=\n-----END PUBLIC KEY-----\n"},
                        "signer2": {"type": "Single", "pub_key": "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAl3XVo/DeiTjHn8dYQuEtBjQrEWNQSKpfzw3X9dewSVY=\n-----END PUBLIC KEY-----\n"}
                    },
                    "governors": {
                        "type": "MultiSig",
                        "threshold": 1,
                        "signers": [
                            {"type": "Identity", "name": "signer1"},
                            {"type": "Identity", "name": "signer2"}
                        ]
                    }
                },
                {
                    "token_id": 1,
                    "minimum_fee": 1,
                    "signer_identities": {
                        "signer1": {"type": "Single", "pub_key": "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAyj6m0NRTlw/R28Q+R7vBakwybuaNFneKrvRVAYNp5WQ=\n-----END PUBLIC KEY-----\n"},
                        "signer2": {"type": "Single", "pub_key": "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAl3XVo/DeiTjHn8dYQuEtBjQrEWNQSKpfzw3X9dewSVY=\n-----END PUBLIC KEY-----\n"}
                    },
                    "governors": {
                        "type": "MultiSig",
                        "threshold": 1,
                        "signers": [
                            {"type": "Identity", "name": "signer1"},
                            {"type": "Identity", "name": "signer2"}
                        ]
                    }
                }
            ]
        }"#;
        let tokens: TokensConfig = serde_json::from_str(input_json).expect("failed parsing json");

        // Validation should fail since we must have the MOB token configured.
        assert!(matches!(
            tokens.validate(),
            Err(Error::DuplicateTokenConfig)
        ));
        assert!(tokens.fee_map().is_err());
    }

    #[test]
    fn verify_governors_signature_detects_incorrect_signature() {
        // Key generating using `openssl genpkey -algorithm ED25519`
        let minting_trust_root_private_key_pem = pem::parse(
            r#"-----BEGIN PRIVATE KEY-----
            MC4CAQAwBQYDK2VwBCIEIC4Z5GeRSzvx61R4ydQK/1bOGLLDGptNwsEnzaMTV9KI
            -----END PRIVATE KEY-----"#,
        )
        .unwrap();
        let minting_trust_root_private_key =
            Ed25519Private::try_from_der(&minting_trust_root_private_key_pem.contents[..]).unwrap();

        // Made invalid by changing the token id
        // A previous test verified the signature is valid.
        let input_json: &str = r#"{
            "governors_signature": "03e9e3e55724057a9e8e94dbfd1f166ea2c033aa53f5cf48942e103cde62c56655234cac2f5bffcbf9bdfb4e68ab6a2f23138accbc914e3c569838f9de058e0c",
            "tokens": [
                { "token_id": 0 },
                {
                    "token_id": 10,
                    "minimum_fee": 1,
                    "signer_identities": {
                        "signer1": {"type": "Single", "pub_key": "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAyj6m0NRTlw/R28Q+R7vBakwybuaNFneKrvRVAYNp5WQ=\n-----END PUBLIC KEY-----\n"},
                        "signer2": {"type": "Single", "pub_key": "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAl3XVo/DeiTjHn8dYQuEtBjQrEWNQSKpfzw3X9dewSVY=\n-----END PUBLIC KEY-----\n"}
                    },
                    "governors": {
                        "type": "MultiSig",
                        "threshold": 1,
                        "signers": [
                            {"type": "Identity", "name": "signer1"},
                            {"type": "Identity", "name": "signer2"}
                        ]
                    }
                }
            ]
        }"#;
        let tokens: TokensConfig = serde_json::from_str(input_json).expect("failed parsing json");

        // The governors signature should've decoded successfully.
        assert!(tokens
            .verify_governors_signature(&Ed25519Public::from(&minting_trust_root_private_key))
            .is_err());
    }
}
