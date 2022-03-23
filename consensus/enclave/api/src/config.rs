use crate::{FeeMap, MasterMintersMap};
use alloc::{format, string::String};
use mc_common::ResponderId;
use mc_crypto_digestible::{Digestible, MerlinTranscript};
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

    /// The map from tokens to master minters.
    pub master_minters_map: MasterMintersMap,

    /// The block version that this enclave will be applying rules for and
    /// publishing.
    pub block_version: BlockVersion,
}

impl Default for BlockchainConfig {
    fn default() -> Self {
        Self {
            fee_map: FeeMap::default(),
            master_minters_map: MasterMintersMap::default(),
            block_version: BlockVersion::MAX,
        }
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
    use alloc::{string::ToString, vec};
    use mc_crypto_keys::Ed25519Public;
    use mc_crypto_multisig::SignerSet;
    use mc_transaction_core::{tokens::Mob, Token, TokenId};

    /// Different block_version/fee maps/responder ids should result in
    /// different responder ids over all
    #[test]
    fn different_fee_maps_result_in_different_responder_ids() {
        let config1: BlockchainConfigWithDigest = BlockchainConfig {
            fee_map: FeeMap::try_from_iter([(Mob::ID, 100), (TokenId::from(2), 2000)]).unwrap(),
            master_minters_map: MasterMintersMap::default(),
            block_version: BlockVersion::ONE,
        }
        .into();
        let config2: BlockchainConfigWithDigest = BlockchainConfig {
            fee_map: FeeMap::try_from_iter([(Mob::ID, 100), (TokenId::from(2), 300)]).unwrap(),
            master_minters_map: MasterMintersMap::default(),
            block_version: BlockVersion::ONE,
        }
        .into();
        let config3: BlockchainConfigWithDigest = BlockchainConfig {
            fee_map: FeeMap::try_from_iter([(Mob::ID, 100), (TokenId::from(30), 300)]).unwrap(),
            master_minters_map: MasterMintersMap::default(),
            block_version: BlockVersion::ONE,
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
            fee_map: FeeMap::try_from_iter([(Mob::ID, 100), (TokenId::from(30), 300)]).unwrap(),
            master_minters_map: MasterMintersMap::default(),
            block_version: BlockVersion::TWO,
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

    // Different master minter maps result in differnet responder ids.
    #[test]
    fn different_master_minter_maps_result_in_different_responder_ids() {
        let config1: BlockchainConfigWithDigest = BlockchainConfig {
            fee_map: FeeMap::default(),
            master_minters_map: MasterMintersMap::try_from_iter([(
                TokenId::from(1),
                SignerSet::new(vec![Ed25519Public::default()], 1),
            )])
            .unwrap(),
            block_version: BlockVersion::ONE,
        }
        .into();
        let config2: BlockchainConfigWithDigest = BlockchainConfig {
            fee_map: FeeMap::default(),
            master_minters_map: MasterMintersMap::try_from_iter([(
                TokenId::from(2),
                SignerSet::new(vec![Ed25519Public::default()], 1),
            )])
            .unwrap(),
            block_version: BlockVersion::ONE,
        }
        .into();
        let config3: BlockchainConfigWithDigest = BlockchainConfig {
            fee_map: FeeMap::default(),
            master_minters_map: MasterMintersMap::try_from_iter([(
                TokenId::from(2),
                SignerSet::new(vec![Ed25519Public::default(), Ed25519Public::default()], 1),
            )])
            .unwrap(),
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
}
