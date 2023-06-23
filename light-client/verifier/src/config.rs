// Copyright (c) 2018-2023 The MobileCoin Foundation

//! Light client configuration.

use crate::{LightClientVerifier, TrustedValidatorSet};
use mc_blockchain_types::{BlockID, BlockIndex};
use mc_common::{NodeID, ResponderId};
use mc_consensus_scp_types::{QuorumSet, QuorumSetMember, QuorumSetMemberWrapper};
use mc_crypto_digestible::Digestible;
use mc_crypto_keys::Ed25519Public;
use prost::Message;
use serde::{Deserialize, Serialize};
use std::{collections::BTreeSet, fmt, ops::Range};

/// A version of `[TrustedValidatorSet]` that uses a quorum set that encodes
/// node keys as base64 strings. This makes it more pleasant to use in config
/// files, as well as allowing the key format to match what consensus already
/// uses.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct TrustedValidatorSetConfig {
    pub quorum_set: QuorumSet<HexKeyNodeID>,
}

impl From<TrustedValidatorSetConfig> for TrustedValidatorSet {
    fn from(config: TrustedValidatorSetConfig) -> Self {
        Self {
            quorum_set: hex_key_node_id_from_node_id_quorum_set(config.quorum_set),
        }
    }
}

/// A version of `[TrustedValidatorSet]` that uses a quorum set that encodes
/// node keys as base64 strings. This makes it more pleasant to use in config
/// files, as well as allowing the key format to match what consensus already
/// uses.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct LightClientVerifierConfig {
    pub trusted_validator_set: TrustedValidatorSetConfig,
    pub trusted_validator_set_start_block: BlockIndex,
    pub historical_validator_sets: Vec<(Range<BlockIndex>, TrustedValidatorSetConfig)>,
    pub known_valid_block_ids: BTreeSet<BlockID>,
}

impl From<LightClientVerifierConfig> for LightClientVerifier {
    fn from(config: LightClientVerifierConfig) -> Self {
        Self {
            trusted_validator_set: config.trusted_validator_set.into(),
            trusted_validator_set_start_block: config.trusted_validator_set_start_block,
            historical_validator_sets: config
                .historical_validator_sets
                .into_iter()
                .map(|(block_range, trusted_validator_set)| {
                    (block_range, trusted_validator_set.into())
                })
                .collect(),
            known_valid_block_ids: config.known_valid_block_ids,
        }
    }
}

/// A version of `[NodeID]` that encodes the public key as a DER base64 string.
/// This is similar to how consensus-service encodes it in the `network.toml`
/// file.
#[derive(
    Clone, Deserialize, Digestible, Eq, Hash, Message, Ord, PartialEq, PartialOrd, Serialize,
)]
pub struct HexKeyNodeID {
    /// The Responder ID for this node
    #[prost(message, required, tag = 1)]
    pub responder_id: ResponderId,

    /// The public message-signing key for this node
    #[prost(message, required, tag = 2)]
    #[serde(with = "der_base64_encoding")]
    pub public_key: Ed25519Public,
}

impl From<HexKeyNodeID> for NodeID {
    fn from(src: HexKeyNodeID) -> Self {
        Self {
            responder_id: src.responder_id,
            public_key: src.public_key,
        }
    }
}

impl fmt::Display for HexKeyNodeID {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}:{}", self.responder_id, self.public_key)
    }
}

fn hex_key_node_id_from_node_id_quorum_set(src: QuorumSet<HexKeyNodeID>) -> QuorumSet<NodeID> {
    QuorumSet {
        threshold: src.threshold,
        members: src
            .members
            .into_iter()
            .map(|member| QuorumSetMemberWrapper {
                member: match member.member {
                    Some(QuorumSetMember::Node(node_id)) => {
                        Some(QuorumSetMember::Node(node_id.into()))
                    }
                    Some(QuorumSetMember::InnerSet(set)) => Some(QuorumSetMember::InnerSet(
                        hex_key_node_id_from_node_id_quorum_set(set),
                    )),
                    None => None,
                },
            })
            .collect(),
    }
}

mod der_base64_encoding {
    use base64::{engine::general_purpose::STANDARD as BASE64_ENGINE, Engine};
    use mc_crypto_keys::{DistinguishedEncoding, Ed25519Public};
    use serde::{self, Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(key: &Ed25519Public, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let der_bytes = key.to_der();
        let hex_str = BASE64_ENGINE.encode(der_bytes);
        serializer.serialize_str(&hex_str)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Ed25519Public, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let der_bytes = BASE64_ENGINE.decode(s).map_err(serde::de::Error::custom)?;
        Ed25519Public::try_from_der(&der_bytes).map_err(serde::de::Error::custom)
    }
}
