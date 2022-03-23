// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Configuration parameters for the Consensus Service application.
#![deny(missing_docs)]

mod network;
mod tokens;

use crate::config::{network::NetworkConfig, tokens::TokensConfig};
use clap::Parser;
use mc_attest_core::ProviderId;
use mc_common::{NodeID, ResponderId};
use mc_crypto_keys::{DistinguishedEncoding, Ed25519Pair, Ed25519Private};
use mc_transaction_core::BlockVersion;
use mc_util_parse::parse_duration_in_seconds;
use mc_util_uri::{AdminUri, ConsensusClientUri as ClientUri, ConsensusPeerUri as PeerUri};
use std::{fmt::Debug, path::PathBuf, str::FromStr, sync::Arc, time::Duration};

/// Configuration parameters for the Consensus Service application.
#[derive(Clone, Debug, Parser)]
#[clap(
    name = "consensus_service",
    about = "The MobileCoin Consensus Service."
)]
pub struct Config {
    /// Peer Responder ID
    ///
    /// This ID needs to match the host:port remote peers use when connecting to
    /// this node. This node is uniquely identified in the network by this
    /// ID as well as the public key derived from the msg-signer-key.
    #[clap(long, env = "MC_PEER_RESPONDER_ID")]
    pub peer_responder_id: ResponderId,

    /// The ID with which to respond to client attestation requests.
    #[clap(long, env = "MC_CLIENT_RESPONDER_ID")]
    pub client_responder_id: ResponderId,

    /// The keypair with which to sign consensus messages.
    ///
    /// The value provided via config is the keypair derived from the input
    /// base64 DER-encoded private key.
    // FIXME: MC-973, get Ed25519 Pair from PEM
    #[clap(long, parse(try_from_str = keypair_from_base64), env = "MC_MSG_SIGNER_KEY")]
    pub msg_signer_key: Arc<Ed25519Pair>,

    /// The location for the network.toml/json configuration file.
    #[clap(long = "network", parse(from_os_str), env = "MC_NETWORK")]
    pub network_path: PathBuf,

    /// Your Intel IAS API key.
    #[clap(long, env = "MC_IAS_API_KEY")]
    pub ias_api_key: String,

    /// The Service Provider ID (SPID) associated with your Intel IAS API Key.
    #[clap(long, env = "MC_IAS_SPID")]
    pub ias_spid: ProviderId,

    /// The location on which to listen for peer traffic.
    ///
    /// The local node id is derived from the peer_listen_uri.
    #[clap(
        long,
        default_value = "insecure-mcp://0.0.0.0:8080/",
        env = "MC_PEER_LISTEN_URI"
    )]
    pub peer_listen_uri: PeerUri,

    /// Client listening URI.
    #[clap(
        long,
        default_value = "insecure-mc://0.0.0.0:3223/",
        env = "MC_CLIENT_LISTEN_URI"
    )]
    pub client_listen_uri: ClientUri,

    /// Optional admin listening URI.
    #[clap(long, env = "MC_ADMIN_LISTEN_URI")]
    pub admin_listen_uri: Option<AdminUri>,

    /// The location to write the externalized blocks for the ledger.
    #[clap(long, parse(from_os_str), env = "MC_LEDGER_PATH")]
    pub ledger_path: PathBuf,

    /// The location from which to load the origin block.
    #[clap(long, parse(from_os_str), env = "MC_ORIGIN_BLOCK_PATH")]
    pub origin_block_path: Option<PathBuf>,

    /// SCP debug output.
    #[clap(long, parse(from_os_str), env = "MC_SCP_DEBUG_DUMP")]
    pub scp_debug_dump: Option<PathBuf>,

    /// Path to the sealed block signing key
    #[clap(long, parse(from_os_str), env = "MC_SEALED_BLOCK_SIGNING_KEY")]
    pub sealed_block_signing_key: PathBuf,

    /// Enables authenticating client requests using Authorization tokens using
    /// the provided hex-encoded 32 bytes shared secret.
    #[clap(long, parse(try_from_str = hex::FromHex::from_hex), env = "MC_CLIENT_AUTH_TOKEN_SECRET")]
    pub client_auth_token_secret: Option<[u8; 32]>,

    /// Maximal client authentication token lifetime, in seconds (only relevant
    /// when --client-auth-token-secret is used. Defaults to 86400 - 24
    /// hours).
    #[clap(long, default_value = "86400", parse(try_from_str = parse_duration_in_seconds), env = "MC_CLIENT_AUTH_TOKEN_MAX_LIFETIME")]
    pub client_auth_token_max_lifetime: Duration,

    /// The location for the network.toml/json configuration file.
    #[clap(long = "tokens", parse(from_os_str), env = "MC_TOKENS")]
    pub tokens_path: Option<PathBuf>,

    /// The configured block version
    #[clap(long, default_value = "1", parse(try_from_str = parse_block_version), env = "MC_BLOCK_VERSION")]
    pub block_version: BlockVersion,
}

impl Config {
    /// Get NodeID for this consensus validator.
    pub fn node_id(&self) -> NodeID {
        NodeID {
            responder_id: self.peer_responder_id.clone(),
            public_key: self.msg_signer_key.public_key(),
        }
    }

    /// Get the network configuration by loading the network.toml/json file.
    /// This will panic if the configuration is invalid.
    pub fn network(&self) -> NetworkConfig {
        NetworkConfig::load_from_path(&self.network_path, &self.peer_responder_id).unwrap_or_else(
            |_| {
                panic!(
                    "Failed loading network configuration from {:?}",
                    self.network_path,
                )
            },
        )
    }

    /// Get the tokens configuration from a file, if provided, or the default
    /// configuration.
    pub fn tokens(&self) -> TokensConfig {
        if let Some(tokens_path) = &self.tokens_path {
            TokensConfig::load_from_path(tokens_path).unwrap_or_else(|_| {
                panic!("failed loading tokens configuration from {:?}", tokens_path)
            })
        } else {
            TokensConfig::default()
        }
    }
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

/// Helper for parsing a BlockVersion
fn parse_block_version(s: &str) -> Result<BlockVersion, String> {
    // FromStr for BlockVersion uses BlockVersionError, which is not easily
    // convertible to dyn StdError, so use String (which is convertible).
    BlockVersion::from_str(s).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use mc_consensus_enclave::FeeMap;
    use mc_transaction_core::{tokens::Mob, Token};

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
            tokens_path: None,
            block_version: BlockVersion::ONE,
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

        // Empty tokens path should result with a single token being configured.
        let tokens = config.tokens();
        assert_eq!(tokens.tokens().len(), 1);
        assert_eq!(tokens.tokens()[0].token_id(), Mob::ID);
        assert_eq!(
            tokens.tokens()[0].minimum_fee_or_default(),
            Some(Mob::MINIMUM_FEE)
        );
        assert_eq!(tokens.fee_map().unwrap(), FeeMap::default());
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
            tokens_path: None,
            block_version: BlockVersion::ONE,
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
