// Copyright (c) 2018-2020 MobileCoin Inc.

//! Configuration parameters for mobilecoind

use displaydoc::Display;
use mc_attest_core::{MrSignerVerifier, Verifier, DEBUG_ENCLAVE};
use mc_common::{logger::Logger, ResponderId};
use mc_connection::{ConnectionManager, ThickClient};
use mc_consensus_scp::QuorumSet;
use mc_fog_report_connection::GrpcFogPubkeyResolver;
use mc_mobilecoind_api::MobilecoindUri;
use mc_sgx_css::Signature;
use mc_util_uri::{ConnectionUri, ConsensusClientUri};
#[cfg(feature = "ip-check")]
use reqwest::{
    blocking::Client,
    header::{HeaderMap, HeaderValue, CONTENT_TYPE},
};
use std::{convert::TryFrom, fs, path::PathBuf, str::FromStr, sync::Arc, time::Duration};
use structopt::StructOpt;

#[derive(Debug, StructOpt)]
#[structopt(name = "mobilecoind", about = "The MobileCoin client daemon.")]
pub struct Config {
    /// Path to ledger db (lmdb).
    #[structopt(long, default_value = "/tmp/ledgerdb", parse(from_os_str))]
    pub ledger_db: PathBuf,

    /// Path to existing ledger db that contains the origin block, used when initializing new ledger dbs.
    #[structopt(long)]
    pub ledger_db_bootstrap: Option<String>,

    /// Path to watcher db (lmdb).
    #[structopt(long, parse(from_os_str))]
    pub watcher_db: Option<PathBuf>,

    #[structopt(flatten)]
    pub peers_config: PeersConfig,

    /// Quorum set for ledger syncing. By default, the quorum set would include all peers.
    ///
    /// The quorum set is represented in JSON. For example:
    /// {"threshold":1,"members":[{"type":"Node","args":"node2.test.mobilecoin.com:443"},{"type":"Node","args":"node3.test.mobilecoin.com:443"}]}
    #[structopt(long, parse(try_from_str=parse_quorum_set_from_json))]
    quorum_set: Option<QuorumSet<ResponderId>>,

    /// URLs to use for transaction data.
    ///
    /// For example: https://s3-us-west-1.amazonaws.com/mobilecoin.chain/node1.test.mobilecoin.com/
    #[structopt(long = "tx-source-url", required_unless = "offline")]
    pub tx_source_urls: Option<Vec<String>>,

    /// How many seconds to wait between polling.
    #[structopt(long, default_value = "5", parse(try_from_str=parse_duration_in_seconds))]
    pub poll_interval: Duration,

    // Mobilecoind specific arguments
    /// Path to mobilecoind database used to store transactions and accounts.
    #[structopt(long, parse(from_os_str))]
    pub mobilecoind_db: Option<PathBuf>,

    /// URI to listen on and serve requests from.
    #[structopt(long)]
    pub listen_uri: Option<MobilecoindUri>,

    /// Number of worker threads to use for view key scanning.
    /// Defaults to number of logical CPU cores.
    #[structopt(long)]
    pub num_workers: Option<usize>,

    /// Offline mode.
    #[structopt(long)]
    pub offline: bool,

    /// Fog ingest enclave CSS file (needed in order to enable sending transactions to fog
    /// recipients).
    #[structopt(long, parse(try_from_str=load_css_file))]
    pub fog_ingest_enclave_css: Option<Signature>,
}

fn parse_duration_in_seconds(src: &str) -> Result<Duration, std::num::ParseIntError> {
    Ok(Duration::from_secs(u64::from_str(src)?))
}

fn parse_quorum_set_from_json(src: &str) -> Result<QuorumSet<ResponderId>, String> {
    let quorum_set: QuorumSet<ResponderId> = serde_json::from_str(src)
        .map_err(|err| format!("Error parsing quorum set {}: {:?}", src, err))?;

    if !quorum_set.is_valid() {
        return Err(format!("Invalid quorum set: {:?}", quorum_set));
    }

    Ok(quorum_set)
}

fn load_css_file(filename: &str) -> Result<Signature, String> {
    let bytes =
        fs::read(filename).map_err(|err| format!("Failed reading file '{}': {}", filename, err))?;
    let signature = Signature::try_from(&bytes[..])
        .map_err(|err| format!("Failed parsing CSS file '{}': {}", filename, err))?;
    Ok(signature)
}

#[derive(Display, Debug)]
pub enum ConfigError {
    /// Error parsing json {0}
    Json(serde_json::Error),

    /// Error handling reqwest {0}
    Reqwest(reqwest::Error),

    /// Invalid country
    InvalidCountry,

    /// Data missing in the response {0}
    DataMissing(String),
}

impl From<serde_json::Error> for ConfigError {
    fn from(e: serde_json::Error) -> Self {
        Self::Json(e)
    }
}

impl From<reqwest::Error> for ConfigError {
    fn from(e: reqwest::Error) -> Self {
        Self::Reqwest(e)
    }
}

impl Config {
    pub fn quorum_set(&self) -> QuorumSet<ResponderId> {
        // If we have an explicit quorum set, use that.
        if let Some(quorum_set) = &self.quorum_set {
            return quorum_set.clone();
        }

        // Otherwise create a quorum set that includes all of the peers we know about.
        let node_ids = self
            .peers_config
            .peers
            .clone()
            .unwrap_or_default()
            .iter()
            .map(|p| {
                p.responder_id().unwrap_or_else(|e| {
                    panic!(
                        "Could not get responder_id from uri {}: {:?}",
                        p.to_string(),
                        e
                    )
                })
            })
            .collect::<Vec<ResponderId>>();
        QuorumSet::new_with_node_ids(node_ids.len() as u32, node_ids)
    }

    pub fn get_fog_pubkey_resolver(&self, logger: Logger) -> Option<GrpcFogPubkeyResolver> {
        self.fog_ingest_enclave_css.as_ref().map(|signature| {
            let mr_signer_verifier = {
                let mut mr_signer_verifier = MrSignerVerifier::new(
                    signature.mrsigner().into(),
                    signature.product_id(),
                    signature.version(),
                );
                mr_signer_verifier.allow_hardening_advisories(&["INTEL-SA-00334"]);
                mr_signer_verifier
            };

            let report_verifier = {
                let mut verifier = Verifier::default();
                verifier.debug(DEBUG_ENCLAVE).mr_signer(mr_signer_verifier);
                verifier
            };

            let env = Arc::new(
                grpcio::EnvBuilder::new()
                    .name_prefix("FogPubkeyResolver-RPC".to_string())
                    .build(),
            );

            GrpcFogPubkeyResolver::new(&report_verifier, env, logger)
        })
    }

    /// Ensure local IP address is valid.
    ///
    /// Uses icanhazip.com for getting local IP.
    /// Uses ipinfo.io for getting details about IP address.
    ///
    /// Note, both of these services are free tier and rate-limited. A longer term solution
    /// would be to filter on the consensus server.
    #[cfg(feature = "ip-check")]
    pub fn validate_host(&self) -> Result<(), ConfigError> {
        let client = Client::builder().gzip(true).use_rustls_tls().build()?;
        let mut json_headers = HeaderMap::new();
        json_headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
        let response = client
            .get("https://icanhazip.com")
            .send()?
            .error_for_status()?;
        let local_ip_addr = response.text()?;
        let response = client
            .get(format!("https://ipinfo.io/{}/json/", local_ip_addr).as_str())
            .headers(json_headers)
            .send()?
            .error_for_status()?;
        let data = response.text()?;
        let data_json: serde_json::Value = serde_json::from_str(&data)?;
        if let Some(v) = data_json.get("country") {
            if let Some(country) = v.as_str() {
                match country {
                    "US" => Err(ConfigError::InvalidCountry),
                    _ => Ok(()),
                }
            } else {
                Err(ConfigError::DataMissing(data_json.to_string()))
            }
        } else {
            Err(ConfigError::DataMissing(data_json.to_string()))
        }
    }

    #[cfg(not(feature = "ip-check"))]
    pub fn validate_host(&self) -> Result<(), ConfigError> {
        Ok(())
    }
}

#[derive(Clone, Debug, StructOpt)]
#[structopt()]
pub struct PeersConfig {
    /// validator nodes to connect to.
    #[structopt(long = "peer", required_unless = "offline")]
    pub peers: Option<Vec<ConsensusClientUri>>,
}

impl PeersConfig {
    pub fn responder_ids(&self) -> Vec<ResponderId> {
        self.peers
            .clone()
            .unwrap_or_default()
            .iter()
            .map(|peer| {
                peer.responder_id()
                    .expect("Could not get responder_id from peer")
            })
            .collect()
    }

    pub fn create_peers(
        &self,
        verifier: Verifier,
        grpc_env: Arc<grpcio::Environment>,
        logger: Logger,
    ) -> Vec<ThickClient> {
        self.peers
            .clone()
            .unwrap_or_default()
            .iter()
            .map(|client_uri| {
                ThickClient::new(
                    client_uri.clone(),
                    verifier.clone(),
                    grpc_env.clone(),
                    logger.clone(),
                )
                .expect("Could not create thick client.")
            })
            .collect()
    }

    pub fn create_peer_manager(
        &self,
        verifier: Verifier,
        logger: &Logger,
    ) -> ConnectionManager<ThickClient> {
        let grpc_env = Arc::new(
            grpcio::EnvBuilder::new()
                .cq_count(1)
                .name_prefix("peer")
                .build(),
        );
        let peers = self.create_peers(verifier, grpc_env, logger.clone());

        ConnectionManager::new(peers, logger.clone())
    }
}
