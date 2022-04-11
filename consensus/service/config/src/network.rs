// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Consensus network configuration.

use crate::error::Error;
use mc_common::{HashMap, HashSet, NodeID, ResponderId};
use mc_consensus_scp::{QuorumSet, QuorumSetMember};
use mc_util_uri::{ConnectionUri, ConsensusPeerUri as PeerUri};
use serde::{Deserialize, Serialize};
use std::{fs, path::Path};

/// Consensus network configuration.
#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq, Hash)]
pub struct NetworkConfig {
    /// The set of nodes which you trust to validate transactions.
    pub quorum_set: QuorumSet<ResponderId>,

    /// List of peers we connect to.
    pub broadcast_peers: Vec<PeerUri>,

    /// List of URLs to use for transaction data.
    pub tx_source_urls: Vec<String>,

    /// Optional list of peers we are aware of.
    pub known_peers: Option<Vec<PeerUri>>,
}

impl NetworkConfig {
    /// Get the network configuration by loading the network.toml/json file.
    pub fn load_from_path(
        path: impl AsRef<Path>,
        peer_responder_id: &ResponderId,
    ) -> Result<Self, Error> {
        let path = path.as_ref();

        // Read configuration file.
        let data = fs::read_to_string(path)?;

        // Parse configuration file.
        let network: Self = match path.extension().and_then(|ext| ext.to_str()) {
            None => Err(Error::PathExtension),
            Some("toml") => toml::from_str(&data).map_err(Error::from),
            Some("json") => serde_json::from_str(&data).map_err(Error::from),
            Some(ext) => Err(Error::UnrecognizedExtension(ext.to_string())),
        }?;

        // Sanity tests:
        // - Our responder ID should not appear in `broadcast_peers` or `known_peers`.
        //   This also ensures it is not part of the quorum set.
        // - Each responder ID is unique.
        let peer_uris = network
            .broadcast_peers
            .iter()
            .chain(network.known_peers.iter().flatten());
        let mut spotted_responder_ids = HashSet::default();
        for peer_uri in peer_uris {
            let responder_id = peer_uri
                .responder_id()
                .map_err(|err| Error::UriConversion(peer_uri.to_string(), err))?;

            if peer_responder_id == &responder_id {
                return Err(Error::KnownPeersContainsSelf(responder_id));
            }

            if !spotted_responder_ids.insert(responder_id.clone()) {
                return Err(Error::DuplicateResponderId(responder_id));
            }
        }

        // Sanity test: We should have at least one source of transactions, if we have
        // any peers configured.
        if !network.broadcast_peers.is_empty() && network.tx_source_urls.is_empty() {
            return Err(Error::MissingTxSourceUrls);
        }

        // Success.
        Ok(network)
    }

    /// Construct a quorum set from the configuration.
    pub fn quorum_set(&self) -> QuorumSet {
        if !self.quorum_set.is_valid() {
            panic!("invalid quorum set: {:?}", self.quorum_set);
        }

        let mut peer_map: HashMap<ResponderId, NodeID> = self
            .broadcast_peers
            .iter()
            .cloned()
            .map(|uri| {
                (
                    uri.responder_id().unwrap_or_else(|e| {
                        panic!("unable to get responder_id for {}: {:?}", uri, e)
                    }),
                    uri.node_id()
                        .unwrap_or_else(|e| panic!("unable to get node_id for {}: {:?}", uri, e)),
                )
            })
            .collect();

        if let Some(known_peers) = self.known_peers.as_ref() {
            for uri in known_peers.iter() {
                let responder_id = uri
                    .responder_id()
                    .unwrap_or_else(|e| panic!("unable to get responder_id for {}: {:?}", uri, e));
                let node_id = uri
                    .node_id()
                    .unwrap_or_else(|e| panic!("unable to get node_id for {}: {:?}", uri, e));
                if peer_map.get(&responder_id).unwrap_or(&node_id) != &node_id {
                    panic!("node id mismatch for {}", responder_id);
                } else {
                    peer_map.insert(responder_id, node_id);
                }
            }
        }

        Self::resolve_quorum_set(&self.quorum_set, &peer_map)
    }

    /// Get the list of peers we connect and broadcast messages to.
    pub fn broadcast_peers(&self) -> Vec<PeerUri> {
        self.broadcast_peers.clone()
    }

    // Convert a QuorumSet<ResponderId> -> QuorumSet<NodeID> based on a
    // ResponderID -> NodeID map.
    fn resolve_quorum_set(
        src: &QuorumSet<ResponderId>,
        peer_map: &HashMap<ResponderId, NodeID>,
    ) -> QuorumSet<NodeID> {
        let mut new_members = Vec::with_capacity(src.members.len());
        for member in src.members.iter() {
            let new_member = match member {
                QuorumSetMember::Node(responder_id) => QuorumSetMember::Node(
                    peer_map
                        .get(responder_id)
                        .unwrap_or_else(|| {
                            panic!("Unknown responder_id {} in quorum set", responder_id)
                        })
                        .clone(),
                ),
                QuorumSetMember::InnerSet(qs_config) => {
                    QuorumSetMember::InnerSet(Self::resolve_quorum_set(qs_config, peer_map))
                }
            };
            new_members.push(new_member);
        }
        QuorumSet::new(src.threshold, new_members)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mc_consensus_scp::QuorumSetMember;
    use mc_crypto_keys::{DistinguishedEncoding, Ed25519Public};
    use std::str::FromStr;

    #[test]
    fn test_network_config_parsing() {
        // Dummy empty configuration.
        {
            let input_toml: &str = r#"
                broadcast_peers = []
                tx_source_urls = []
                quorum_set = { threshold = 2, members = [] }
            "#;
            let network: NetworkConfig = toml::from_str(input_toml).expect("failed parsing toml");

            let input_json: &str = r#"{
                "broadcast_peers": [],
                "tx_source_urls": [],
                "quorum_set": {
                    "threshold": 2,
                    "members": []
                }
            }"#;
            let network2: NetworkConfig =
                serde_json::from_str(input_json).expect("failed parsing json");
            assert_eq!(network, network2);

            assert_eq!(network.quorum_set.threshold, 2);
            assert_eq!(network.quorum_set.members.len(), 0);
            assert_eq!(network.broadcast_peers.len(), 0);
            assert!(network.known_peers.is_none());
        }

        // Real world configuration.
        {
            let input_toml: &str = r#"
                broadcast_peers = [
                    "insecure-mcp://0.0.0.0:8082?consensus-msg-key=MCowBQYDK2VwAyEA_ii3rCch5qhMbLZ2vVgpQr1iTrq1BBN2-i0mMPuAJhQ=",
                    "insecure-mcp://0.0.0.0:8083?consensus-msg-key=MCowBQYDK2VwAyEA9C-J6AUm9XnSjrGEhplQpp_jMPNwIxBovFJrJRXtoVA=",
                ]

                tx_source_urls = [
                    "file:///tmp/dump"
                ]

                known_peers = [
                    "insecure-mcp://0.0.0.0:8084?consensus-msg-key=MCowBQYDK2VwAyEAzxKNVxaVfJ4xELeA1bQ-aa-2HkcYyX2pDGcCqW9mzoo=",
                ]

                quorum_set = { threshold = 2, members = [
                    # Node 1
                    { type = "Node", args = "0.0.0.0:8082" },

                    # Node 2
                    { type = "Node", args = "0.0.0.0:8083" },

                    # InnerSet containing a single node
                    { type = "InnerSet", args = { threshold = 1, members = [
                        { type = "Node", args = "0.0.0.0:8084" },
                    ] } },
                ] }
            "#;
            let network: NetworkConfig = toml::from_str(input_toml).expect("failed parsing toml");

            let input_json: &str = r#"{
                "broadcast_peers": [
                    "insecure-mcp://0.0.0.0:8082?consensus-msg-key=MCowBQYDK2VwAyEA_ii3rCch5qhMbLZ2vVgpQr1iTrq1BBN2-i0mMPuAJhQ=",
                    "insecure-mcp://0.0.0.0:8083?consensus-msg-key=MCowBQYDK2VwAyEA9C-J6AUm9XnSjrGEhplQpp_jMPNwIxBovFJrJRXtoVA="
                ],

                "tx_source_urls": [
                    "file:///tmp/dump"
                ],

                "known_peers": [
                    "insecure-mcp://0.0.0.0:8084?consensus-msg-key=MCowBQYDK2VwAyEAzxKNVxaVfJ4xELeA1bQ-aa-2HkcYyX2pDGcCqW9mzoo="
                ],

                "quorum_set": { "threshold": 2, "members": [
                    { "type": "Node", "args": "0.0.0.0:8082" },
                    { "type": "Node", "args": "0.0.0.0:8083" },
                    { "type": "InnerSet", "args": { "threshold": 1, "members": [
                        { "type": "Node", "args": "0.0.0.0:8084" }
                    ] } }
                ] }
            }"#;
            let network2: NetworkConfig =
                serde_json::from_str(input_json).expect("failed parsing json");

            assert_eq!(network, network2);

            let quorum_set = network.quorum_set();
            assert_eq!(
                quorum_set.members[0],
                QuorumSetMember::Node(NodeID {
                    responder_id: ResponderId::from_str("0.0.0.0:8082").unwrap(),
                    public_key: Ed25519Public::try_from_der(
                        &base64::decode(
                            "MCowBQYDK2VwAyEA/ii3rCch5qhMbLZ2vVgpQr1iTrq1BBN2+i0mMPuAJhQ="
                        )
                        .unwrap()
                    )
                    .unwrap()
                })
            );
            assert_eq!(
                quorum_set.members[1],
                QuorumSetMember::Node(NodeID {
                    responder_id: ResponderId::from_str("0.0.0.0:8083").unwrap(),
                    public_key: Ed25519Public::try_from_der(
                        &base64::decode(
                            "MCowBQYDK2VwAyEA9C+J6AUm9XnSjrGEhplQpp/jMPNwIxBovFJrJRXtoVA="
                        )
                        .unwrap()
                    )
                    .unwrap()
                })
            );
            assert_eq!(
                quorum_set.members[2],
                QuorumSetMember::InnerSet(QuorumSet::new_with_node_ids(
                    1,
                    vec![NodeID {
                        responder_id: ResponderId::from_str("0.0.0.0:8084").unwrap(),
                        public_key: Ed25519Public::try_from_der(
                            &base64::decode(
                                "MCowBQYDK2VwAyEAzxKNVxaVfJ4xELeA1bQ+aa+2HkcYyX2pDGcCqW9mzoo="
                            )
                            .unwrap()
                        )
                        .unwrap()
                    }]
                ))
            );
        }
    }
}
