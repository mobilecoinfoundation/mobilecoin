// Copyright (c) 2018-2021 The MobileCoin Foundation

//! Configuration parameters for the Consensus Service application.

use mc_attest_core::ProviderId;
use mc_common::{HashMap, HashSet, NodeID, ResponderId};
use mc_consensus_scp::{QuorumSet, QuorumSetMember};
use mc_crypto_keys::{DistinguishedEncoding, Ed25519Pair, Ed25519Private};
use mc_util_uri::{
    AdminUri, ConnectionUri, ConsensusClientUri as ClientUri, ConsensusPeerUri as PeerUri,
};
use serde::{Deserialize, Serialize};
use std::{fmt::Debug, fs, path::PathBuf, str::FromStr, string::String, sync::Arc, time::Duration};
use structopt::StructOpt;

#[derive(Clone, Debug, StructOpt)]
#[structopt(
    name = "consensus_service",
    about = "The MobileCoin Consensus Service."
)]
pub struct Config {
    /// Peer Responder ID
    ///
    /// This ID needs to match the host:port remote peers use when connecting to
    /// this node. This node is uniquely identified in the network by this
    /// ID as well as the public key derived from the msg-signer-key.
    #[structopt(long)]
    pub peer_responder_id: ResponderId,

    /// The ID with which to respond to client attestation requests.
    #[structopt(long)]
    pub client_responder_id: ResponderId,

    /// The keypair with which to sign consensus messages.
    ///
    /// The value provided via config is the keypair derived from the input
    /// base64 DER-encoded private key.
    // FIXME: MC-973, get Ed25519 Pair from PEM
    #[structopt(long, parse(try_from_str=keypair_from_base64))]
    pub msg_signer_key: Arc<Ed25519Pair>,

    /// The location for the network.toml/json configuration file.
    #[structopt(long = "network", parse(from_os_str))]
    pub network_path: PathBuf,

    /// Your Intel IAS API key.
    #[structopt(long)]
    pub ias_api_key: String,

    /// The Service Provider ID (SPID) associated with your Intel IAS API Key.
    #[structopt(long)]
    pub ias_spid: ProviderId,

    /// The location on which to listen for peer traffic.
    ///
    /// The local node id is derived from the peer_listen_uri.
    #[structopt(long, default_value = "insecure-mcp://0.0.0.0:8080/")]
    pub peer_listen_uri: PeerUri,

    /// Client listening URI.
    #[structopt(long, default_value = "insecure-mc://0.0.0.0:3223/")]
    pub client_listen_uri: ClientUri,

    /// Optional admin listening URI.
    #[structopt(long)]
    pub admin_listen_uri: Option<AdminUri>,

    /// The location to write the externalized blocks for the ledger.
    #[structopt(long, parse(from_os_str))]
    pub ledger_path: PathBuf,

    /// The location from which to load the origin block.
    #[structopt(long, parse(from_os_str))]
    pub origin_block_path: Option<PathBuf>,

    /// SCP debug output.
    #[structopt(long, parse(from_os_str))]
    pub scp_debug_dump: Option<PathBuf>,

    /// Path to the sealed block signing key
    #[structopt(long, parse(from_os_str))]
    pub sealed_block_signing_key: PathBuf,

    /// Enables authenticating client requests using Authorization tokens using
    /// the provided hex-encoded 32 bytes shared secret.
    #[structopt(long, parse(try_from_str=hex::FromHex::from_hex))]
    pub client_auth_token_secret: Option<[u8; 32]>,

    /// Maximal client authentication token lifetime, in seconds (only relevant
    /// when --client-auth-token-secret is used. Defaults to 86400 - 24
    /// hours).
    #[structopt(long, default_value = "86400", parse(try_from_str=parse_duration_in_seconds))]
    pub client_auth_token_max_lifetime: Duration,

    /// Override the hard-coded minimum fee.
    #[structopt(long, env = "MC_MINIMUM_FEE")]
    pub minimum_fee: Option<u64>,

    /// Allow extreme (>= 1MOB, <= 0.000_000_01 MOB).
    #[structopt(long)]
    pub allow_any_fee: bool,
}

/// Decodes an Ed25519 private key.
///
/// # Arguments
/// * `private_key` - A DER formatted, Base64 encoded Ed25519 private key.
fn keypair_from_base64(private_key: &str) -> Result<Arc<Ed25519Pair>, String> {
    let privkey_bytes = base64::decode_config(private_key, base64::STANDARD)
        .map_err(|err| format!("Could not decode private key from base64 {:?}", err))?;

    let secret_key = Ed25519Private::try_from_der(privkey_bytes.as_slice())
        .map_err(|err| format!("Could not get Ed25519Private from der {:?}", err))?;
    Ok(Arc::new(Ed25519Pair::from(secret_key)))
}

/// Converts a string containing number of seconds to a Duration object.
fn parse_duration_in_seconds(src: &str) -> Result<Duration, std::num::ParseIntError> {
    Ok(Duration::from_secs(u64::from_str(src)?))
}

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
                        .get(&responder_id)
                        .unwrap_or_else(|| {
                            panic!("Unknown responder_id {} in quorum set", responder_id)
                        })
                        .clone(),
                ),
                QuorumSetMember::InnerSet(qs_config) => {
                    QuorumSetMember::InnerSet(Self::resolve_quorum_set(&qs_config, peer_map))
                }
            };
            new_members.push(new_member);
        }
        QuorumSet::new(src.threshold, new_members)
    }
}

impl Config {
    /// Get NodeID for this consensus validator.
    pub fn node_id(&self) -> NodeID {
        NodeID {
            responder_id: self.peer_responder_id.clone(),
            public_key: self.msg_signer_key.public_key(),
        }
    }

    /// Get the configured minimum fee.
    pub fn minimum_fee(&self) -> Result<Option<u64>, String> {
        if let Some(fee) = self.minimum_fee {
            // 1 MOB -> 10nMOB
            if !self.allow_any_fee && !(10_000..1_000_000_000_000u64).contains(&fee) {
                Err(format!("Fee {} picoMOB is out of bounds", fee))
            } else {
                Ok(Some(fee))
            }
        } else {
            Ok(None)
        }
    }

    /// Get the network configuration by loading the network.toml/json file.
    pub fn network(&self) -> NetworkConfig {
        // Read configuration file.
        let data = fs::read_to_string(&self.network_path)
            .unwrap_or_else(|err| panic!("failed reading {:?}: {:?}", self.network_path, err));

        // Parse configuration file.
        let network: NetworkConfig =
            match self.network_path.extension().and_then(|ext| ext.to_str()) {
                None => panic!(
                    "failed figuring out file extension for path {:?}",
                    self.network_path
                ),
                Some("toml") => toml::from_str(&data).unwrap_or_else(|err| {
                    panic!("failed TOML parsing {:?}: {:?}", self.network_path, err)
                }),
                Some("json") => serde_json::from_str(&data).unwrap_or_else(|err| {
                    panic!("failed JSON parsing {:?}: {:?}", self.network_path, err)
                }),
                Some(ext) => panic!(
                    "Unrecognized extension in path {:?}: {:?}",
                    self.network_path, ext
                ),
            };

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
            let responder_id = peer_uri.responder_id().unwrap_or_else(|e| {
                panic!("failed getting responder id for {:?}: {:?}", peer_uri, e)
            });

            if self.peer_responder_id == responder_id {
                panic!(
                    "Our peer responder id ({}) should not appear in broadcast_peers or known_peers!",
                    responder_id
                );
            }

            if !spotted_responder_ids.insert(responder_id.clone()) {
                panic!(
                    "Duplicate responder_id {} found in network configuration",
                    responder_id
                );
            }
        }

        // Sanity test: We should have at least one source of transactions, if we have
        // any peers configured.
        if !network.broadcast_peers.is_empty() && network.tx_source_urls.is_empty() {
            panic!("Network configuration is missing tx_source_urls");
        }

        // Success.
        network
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mc_consensus_scp::QuorumSetMember;
    use mc_crypto_keys::Ed25519Public;
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

    #[test]
    fn test_local_uris_with_pubkey() {
        let config = Config {
            peer_responder_id: ResponderId::from_str("localhost:8081").unwrap(),
            client_responder_id: ResponderId::from_str("localhost:3223").unwrap(),
            msg_signer_key: keypair_from_base64(
                "MC4CAQAwBQYDK2VwBCIEIC50QXQll2Y9qxztvmsUgcBBIxkmk7EQjxzQTa926bKo",
            )
            .unwrap(),
            network_path: PathBuf::from("network.toml"),
            ias_api_key: "".to_string(),
            ias_spid: ProviderId::from_str("22222222222222222222222222222222").unwrap(),
            peer_listen_uri: PeerUri::from_str("insecure-mcp://0.0.0.0:8081/").unwrap(),
            client_listen_uri: ClientUri::from_str("insecure-mc://0.0.0.0:3223/").unwrap(),
            admin_listen_uri: Some(AdminUri::from_str("insecure-mca://0.0.0.0:9090/").unwrap()),
            ledger_path: PathBuf::default(),
            scp_debug_dump: None,
            origin_block_path: None,
            sealed_block_signing_key: PathBuf::default(),
            client_auth_token_secret: None,
            client_auth_token_max_lifetime: Duration::from_secs(60),
            minimum_fee: None,
            allow_any_fee: false,
        };

        assert_eq!(
            config.node_id(),
            NodeID {
                responder_id: ResponderId::from_str("localhost:8081").unwrap(),
                public_key: keypair_from_base64(
                    "MC4CAQAwBQYDK2VwBCIEIC50QXQll2Y9qxztvmsUgcBBIxkmk7EQjxzQTa926bKo",
                )
                .unwrap()
                .public_key(),
            }
        );
        assert_eq!(
            config.client_responder_id,
            ResponderId::from_str("localhost:3223").unwrap(),
        );
        assert_eq!(
            config.peer_responder_id,
            ResponderId::from_str("localhost:8081").unwrap(),
        );
        assert_eq!(
            config.client_listen_uri,
            ClientUri::from_str("insecure-mc://0.0.0.0:3223/").unwrap()
        );
        assert_eq!(
            config.peer_listen_uri,
            PeerUri::from_str("insecure-mcp://0.0.0.0:8081/").unwrap()
        );
        assert_eq!(
            config.admin_listen_uri,
            Some(AdminUri::from_str("insecure-mca://0.0.0.0:9090/").unwrap())
        );
    }

    #[test]
    fn test_deployed_uris_with_pubkey() {
        let config = Config {
            peer_responder_id: ResponderId::from_str("peer1.NETWORKNAME.mobilecoin.com:443").unwrap(),
            client_responder_id: ResponderId::from_str("node1.NETWORKNAME.mobilecoin.com:443").unwrap(),
            msg_signer_key: keypair_from_base64(
                "MC4CAQAwBQYDK2VwBCIEIC50QXQll2Y9qxztvmsUgcBBIxkmk7EQjxzQTa926bKo",
            ) .unwrap(),
            network_path: PathBuf::from("network.toml"),
            ias_api_key: "".to_string(),
            ias_spid: ProviderId::from_str("22222222222222222222222222222222").unwrap(),
            peer_listen_uri: PeerUri::from_str("mcp://0.0.0.0:8443/?tls-chain=./public/attest/test_certs/selfsigned_mobilecoin.crt&tls-key=./public/attest/test_certs/selfsigned_mobilecoin.key").unwrap(),
            client_listen_uri: ClientUri::from_str("insecure-mc://0.0.0.0:3223/").unwrap(),
            admin_listen_uri: Some(AdminUri::from_str("insecure-mca://0.0.0.0:9090/").unwrap()),
            ledger_path: PathBuf::default(),
            scp_debug_dump: None,
            origin_block_path: None,
            sealed_block_signing_key: PathBuf::default(),
            client_auth_token_secret: None,
            client_auth_token_max_lifetime: Duration::from_secs(60),
            minimum_fee: None,
            allow_any_fee: false,
        };

        assert_eq!(
            config.node_id(),
            NodeID {
                responder_id: ResponderId::from_str("peer1.NETWORKNAME.mobilecoin.com:443")
                    .unwrap(),
                public_key: keypair_from_base64(
                    "MC4CAQAwBQYDK2VwBCIEIC50QXQll2Y9qxztvmsUgcBBIxkmk7EQjxzQTa926bKo",
                )
                .unwrap()
                .public_key(),
            }
        );
        assert_eq!(
            config.client_responder_id,
            ResponderId::from_str("node1.NETWORKNAME.mobilecoin.com:443").unwrap(),
        );
        assert_eq!(
            config.peer_responder_id,
            ResponderId::from_str("peer1.NETWORKNAME.mobilecoin.com:443").unwrap(),
        );
        assert_eq!(
            config.admin_listen_uri,
            Some(AdminUri::from_str("insecure-mca://0.0.0.0:9090/").unwrap())
        );
        assert_eq!(
            config.client_listen_uri,
            ClientUri::from_str("insecure-mc://0.0.0.0:3223/").unwrap()
        );
        assert_eq!(
            config.peer_listen_uri,
            PeerUri::from_str("mcp://0.0.0.0:8443/?tls-chain=./public/attest/test_certs/selfsigned_mobilecoin.crt&tls-key=./public/attest/test_certs/selfsigned_mobilecoin.key").unwrap()
        );
    }

    #[test]
    /// Should successfully decode an Ed25519 private key.
    fn test_keypair_from_base64() {
        // openssl genpkey -algorithm ed25519 -outform DER | openssl base64
        let private_key = "MC4CAQAwBQYDK2VwBCIEIFMx+OdFIVsMAXNDuOFtxrl/CiQRIblFjaf4/mQetmrq";

        assert!(keypair_from_base64(private_key).is_ok());
    }
}
