// Copyright (c) 2018-2023 The MobileCoin Foundation

//! Light client configuration.

use crate::{LightClientVerifier, TrustedValidatorSet};
use mc_blockchain_types::{BlockID, BlockIndex};
use mc_common::{NodeID, ResponderId};
use mc_crypto_digestible::Digestible;
use mc_crypto_keys::Ed25519Public;
use prost::Message;
use serde::{Deserialize, Serialize};
use serde_with::{hex::Hex, serde_as};
use std::{collections::BTreeSet, fmt, ops::Range};

/// A version of `[QuorumSetMember]` that does not use an internally-tagged
/// enum.
///
/// The only reason this is needed is because we want to be able to use
/// this configuration inside a cosmos wasm contract, and unfortunately the
/// cosmwasm runtime does not support floating point operations. It turns out
/// that serde generates some floating point code when using internally-tagged
/// enums, so we have to use a non-tagged enum instead :/
/// See https://medium.com/cosmwasm/debugging-floating-point-generation-in-rust-wasm-smart-contract-f47d833b5fba
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum QuorumSetMember {
    Node(HexKeyNodeID),
    InnerSet(QuorumSet),
}

impl From<HexKeyNodeID> for QuorumSetMember {
    fn from(src: HexKeyNodeID) -> Self {
        Self::Node(src)
    }
}

impl From<QuorumSet> for QuorumSetMember {
    fn from(src: QuorumSet) -> Self {
        Self::InnerSet(src)
    }
}

/// A version of `[QuorumSet]` that uses our non-internally-tagged-enum
/// `[QuorumSetMember]`.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct QuorumSet {
    pub threshold: u32,
    pub members: Vec<QuorumSetMember>,
}

impl From<QuorumSet> for mc_consensus_scp_types::QuorumSet<NodeID> {
    fn from(src: QuorumSet) -> mc_consensus_scp_types::QuorumSet<NodeID> {
        Self {
            threshold: src.threshold,
            members: src
                .members
                .into_iter()
                .map(|member| mc_consensus_scp_types::QuorumSetMemberWrapper {
                    member: match member {
                        QuorumSetMember::Node(node_id) => Some(
                            mc_consensus_scp_types::QuorumSetMember::Node(node_id.into()),
                        ),
                        QuorumSetMember::InnerSet(set) => Some(
                            mc_consensus_scp_types::QuorumSetMember::InnerSet(Self::from(set)),
                        ),
                    },
                })
                .collect(),
        }
    }
}

/// A version of `[TrustedValidatorSet]` that uses a quorum set that encodes
/// node keys as base64 strings.
///
/// This makes it more pleasant to use in config
/// files, as well as allowing the key format to match what consensus already
/// uses.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct TrustedValidatorSetConfig {
    pub quorum_set: QuorumSet,
}

impl From<TrustedValidatorSetConfig> for TrustedValidatorSet {
    fn from(config: TrustedValidatorSetConfig) -> Self {
        Self {
            quorum_set: config.quorum_set.into(),
        }
    }
}

/// A version of `[TrustedValidatorSet]` that uses a quorum set that encodes
/// node keys as base64 strings.
///
/// This makes it more pleasant to use in config
/// files, as well as allowing the key format to match what consensus already
/// uses.
#[serde_as]
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LightClientVerifierConfig {
    pub trusted_validator_set: TrustedValidatorSetConfig,
    pub trusted_validator_set_start_block: BlockIndex,
    pub historical_validator_sets: Vec<(Range<BlockIndex>, TrustedValidatorSetConfig)>,

    #[serde_as(as = "BTreeSet<Hex>")]
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

mod der_base64_encoding {
    use base64::{engine::general_purpose::STANDARD as BASE64_ENGINE, Engine};
    use mc_crypto_keys::{DistinguishedEncoding, Ed25519Public};
    use serde::{Deserialize, Deserializer, Serializer};

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
