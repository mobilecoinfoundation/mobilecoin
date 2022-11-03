use crate::{Error, FeeMap, GovernorsMap, GovernorsVerifier};
use alloc::{format, string::String};
use mc_common::ResponderId;
use mc_crypto_digestible::{Digestible, MerlinTranscript};
use mc_crypto_keys::{Ed25519Public, Ed25519Signature};
use mc_transaction_core::BlockVersion;
use serde::{Deserialize, Serialize};

/// Configuration for the enclave which is used to help determine which
/// transactions are valid.
///
/// (This can be contrasted with things like responder id and sealed block
/// signing key)
#[derive(Clone, Deserialize, Debug, Digestible, Eq, Hash, PartialEq, Serialize)]
pub struct BlockchainConfig {
    /// The map from tokens to their minimum fees.
    pub fee_map: FeeMap,

    /// The map from tokens to governors.
    pub governors_map: GovernorsMap,

    /// The governors signature, which is needed if GovernorsMap is
    /// not empty.
    pub governors_signature: Option<Ed25519Signature>,

    /// The block version that this enclave will be applying rules for and
    /// publishing.
    pub block_version: BlockVersion,
}

impl Default for BlockchainConfig {
    fn default() -> Self {
        Self {
            fee_map: FeeMap::default(),
            governors_map: GovernorsMap::default(),
            governors_signature: None,
            block_version: BlockVersion::MAX,
        }
    }
}

impl BlockchainConfig {
    /// Check if the blockchain config is valid.
    pub fn validate(&self, minting_trust_root_public_key: &Ed25519Public) -> Result<(), Error> {
        // Check that fee map is actually well formed
        FeeMap::is_valid_map(self.fee_map.as_ref()).map_err(Error::FeeMap)?;

        // Validate governors signature.
        if !self.governors_map.is_empty() {
            let signature = self
                .governors_signature
                .ok_or(Error::MissingGovernorsSignature)?;

            minting_trust_root_public_key
                .verify_governors_map(&self.governors_map, &signature)
                .map_err(|_| Error::InvalidGovernorsSignature)?;
        }

        Ok(())
    }
}

/// A blockchain config, together with a cache of its digest value.
/// This can be used to form responder id's in a fast and consistent way
/// based on the config.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct BlockchainConfigWithDigest {
    config: BlockchainConfig,
    cached_digest: String,
}

impl From<BlockchainConfig> for BlockchainConfigWithDigest {
    fn from(config: BlockchainConfig) -> Self {
        let digest = config.digest32::<MerlinTranscript>(b"mc-blockchain-config");
        let cached_digest = hex::encode(digest);
        Self {
            config,
            cached_digest,
        }
    }
}

impl AsRef<BlockchainConfig> for BlockchainConfigWithDigest {
    fn as_ref(&self) -> &BlockchainConfig {
        &self.config
    }
}

impl Default for BlockchainConfigWithDigest {
    fn default() -> Self {
        Self::from(BlockchainConfig::default())
    }
}

impl BlockchainConfigWithDigest {
    /// Append the config digest to an existing responder id, producing a
    /// responder id that is unique to the current fee configuration.
    pub fn responder_id(&self, responder_id: &ResponderId) -> ResponderId {
        ResponderId(format!("{}-{}", responder_id.0, self.cached_digest))
    }

    /// Get the config (non mutably)
    pub fn get_config(&self) -> &BlockchainConfig {
        &self.config
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{governors_sig::Signer, FeeMapError};
    use alloc::{string::ToString, vec};
    use mc_crypto_keys::{Ed25519Pair, Ed25519Private, Ed25519Public};
    use mc_crypto_multisig::SignerSet;
    use mc_transaction_core::{tokens::Mob, Token, TokenId};

    fn sign_governors_map(map: &GovernorsMap) -> (Option<Ed25519Signature>, Ed25519Public) {
        let keypair = Ed25519Pair::from(Ed25519Private::try_from(&[1; 32][..]).unwrap());
        (
            Some(keypair.sign_governors_map(map).unwrap()),
            keypair.public_key(),
        )
    }

    /// Different block_version/fee maps/responder ids should result in
    /// different responder ids over all
    #[test]
    fn different_fee_maps_result_in_different_responder_ids() {
        let config1: BlockchainConfigWithDigest = BlockchainConfig {
            fee_map: FeeMap::try_from_iter([(Mob::ID, 1024), (TokenId::from(2), 2048)]).unwrap(),
            governors_map: GovernorsMap::default(),
            governors_signature: None,
            block_version: BlockVersion::ZERO,
        }
        .into();
        let config2: BlockchainConfigWithDigest = BlockchainConfig {
            fee_map: FeeMap::try_from_iter([(Mob::ID, 1024), (TokenId::from(2), 384)]).unwrap(),
            governors_map: GovernorsMap::default(),
            governors_signature: None,
            block_version: BlockVersion::ZERO,
        }
        .into();
        let config3: BlockchainConfigWithDigest = BlockchainConfig {
            fee_map: FeeMap::try_from_iter([(Mob::ID, 1024), (TokenId::from(30), 384)]).unwrap(),
            governors_map: GovernorsMap::default(),
            governors_signature: None,
            block_version: BlockVersion::ZERO,
        }
        .into();

        let responder_id1 = ResponderId("1.2.3.4:5".to_string());
        let responder_id2 = ResponderId("3.1.3.3:7".to_string());

        assert_ne!(
            config1.responder_id(&responder_id1),
            config2.responder_id(&responder_id1)
        );

        assert_ne!(
            config1.responder_id(&responder_id1),
            config3.responder_id(&responder_id1)
        );

        assert_ne!(
            config2.responder_id(&responder_id1),
            config3.responder_id(&responder_id1)
        );

        assert_ne!(
            config1.responder_id(&responder_id1),
            config1.responder_id(&responder_id2)
        );

        assert_ne!(
            config2.responder_id(&responder_id1),
            config2.responder_id(&responder_id2)
        );

        let config4: BlockchainConfigWithDigest = BlockchainConfig {
            fee_map: FeeMap::try_from_iter([(Mob::ID, 256), (TokenId::from(30), 384)]).unwrap(),
            governors_map: GovernorsMap::default(),
            governors_signature: None,
            block_version: BlockVersion::ONE,
        }
        .into();

        assert_ne!(
            config3.responder_id(&responder_id1),
            config4.responder_id(&responder_id1)
        );

        assert_ne!(
            config3.responder_id(&responder_id2),
            config4.responder_id(&responder_id2)
        );
    }

    // Different governor maps result in differnet responder ids.
    #[test]
    fn different_governor_maps_result_in_different_responder_ids() {
        let config1: BlockchainConfigWithDigest = BlockchainConfig {
            fee_map: FeeMap::default(),
            governors_map: GovernorsMap::try_from_iter([(
                TokenId::from(1),
                SignerSet::new(vec![Ed25519Public::default()], vec![], 1),
            )])
            .unwrap(),
            governors_signature: None,
            block_version: BlockVersion::ONE,
        }
        .into();
        let config2: BlockchainConfigWithDigest = BlockchainConfig {
            fee_map: FeeMap::default(),
            governors_map: GovernorsMap::try_from_iter([(
                TokenId::from(2),
                SignerSet::new(vec![Ed25519Public::default()], vec![], 1),
            )])
            .unwrap(),
            governors_signature: None,
            block_version: BlockVersion::ONE,
        }
        .into();
        let config3: BlockchainConfigWithDigest = BlockchainConfig {
            fee_map: FeeMap::default(),
            governors_map: GovernorsMap::try_from_iter([(
                TokenId::from(2),
                SignerSet::new(
                    vec![Ed25519Public::default(), Ed25519Public::default()],
                    vec![],
                    1,
                ),
            )])
            .unwrap(),
            governors_signature: None,
            block_version: BlockVersion::ONE,
        }
        .into();

        let responder_id1 = ResponderId("1.2.3.4:5".to_string());
        assert_ne!(
            config1.responder_id(&responder_id1),
            config2.responder_id(&responder_id1)
        );

        assert_ne!(
            config1.responder_id(&responder_id1),
            config3.responder_id(&responder_id1)
        );

        assert_ne!(
            config2.responder_id(&responder_id1),
            config3.responder_id(&responder_id1)
        );
    }

    #[test]
    fn validate_succeeds_with_valid_config() {
        // With governors map
        let governors_map = GovernorsMap::try_from_iter([(
            TokenId::from(2),
            SignerSet::new(vec![Ed25519Public::default(), Ed25519Public::default()], 1),
        )])
        .unwrap();

        let (governors_signature, governors_public_key) = sign_governors_map(&governors_map);

        let config = BlockchainConfig {
            fee_map: FeeMap::default(),
            governors_map,
            governors_signature,
            block_version: BlockVersion::ONE,
        };

        assert_eq!(config.validate(&governors_public_key), Ok(()));

        // Without governors map
        let config = BlockchainConfig {
            fee_map: Default::default(),
            governors_map: Default::default(),
            governors_signature: None,
            block_version: BlockVersion::ONE,
        };

        assert_eq!(config.validate(&governors_public_key), Ok(()));
    }

    #[test]
    fn validate_rejects_invalid_fee_map() {
        let governors_public_key =
            Ed25519Pair::from(Ed25519Private::try_from(&[1; 32][..]).unwrap()).public_key();

        // Fee map does not contain MOB. We deserialize from JSON since that's the only
        // way we have of constructing an invalid fee map.
        let invalid_fee_map: FeeMap = serde_json::from_str(r#"{"map": {"2": 384}}"#).unwrap();

        let config = BlockchainConfig {
            fee_map: invalid_fee_map,
            governors_map: Default::default(),
            governors_signature: None,
            block_version: BlockVersion::ONE,
        };

        assert_eq!(
            config.validate(&governors_public_key),
            Err(Error::FeeMap(FeeMapError::MissingFee(Mob::ID)))
        );
    }

    #[test]
    fn validate_rejects_governors_without_signature() {
        let governors_map = GovernorsMap::try_from_iter([(
            TokenId::from(2),
            SignerSet::new(vec![Ed25519Public::default(), Ed25519Public::default()], 1),
        )])
        .unwrap();

        let (_governors_signature, governors_public_key) = sign_governors_map(&governors_map);

        let config = BlockchainConfig {
            fee_map: FeeMap::default(),
            governors_map,
            governors_signature: None,
            block_version: BlockVersion::ONE,
        };

        assert_eq!(
            config.validate(&governors_public_key),
            Err(Error::MissingGovernorsSignature)
        );
    }

    #[test]
    fn validate_rejects_invalid_governors_signature() {
        let governors_map = GovernorsMap::try_from_iter([(
            TokenId::from(2),
            SignerSet::new(vec![Ed25519Public::default(), Ed25519Public::default()], 1),
        )])
        .unwrap();

        let (governors_signature, governors_public_key) = sign_governors_map(&governors_map);

        // Invalidate the signature by using a different governors map
        let governors_map2 = GovernorsMap::try_from_iter([(
            TokenId::from(3),
            SignerSet::new(vec![Ed25519Public::default(), Ed25519Public::default()], 1),
        )])
        .unwrap();

        let config = BlockchainConfig {
            fee_map: FeeMap::default(),
            governors_map: governors_map2,
            governors_signature,
            block_version: BlockVersion::ONE,
        };

        assert_eq!(
            config.validate(&governors_public_key),
            Err(Error::InvalidGovernorsSignature)
        );
    }
}
