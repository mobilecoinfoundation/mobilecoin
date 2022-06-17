// Copyright (c) 2018-2022 The MobileCoin Foundation
#![deny(missing_docs)]

//! Configuration parameters for mobilecoind

use clap::Parser;
use displaydoc::Display;
use mc_attest_verifier::{MrSignerVerifier, Verifier, DEBUG_ENCLAVE};
use mc_common::{logger::Logger, ResponderId};
use mc_connection::{ConnectionManager, HardcodedCredentialsProvider, ThickClient};
use mc_consensus_scp::QuorumSet;
use mc_fog_report_connection::GrpcFogReportConnection;
use mc_fog_report_validation::FogResolver;
use mc_mobilecoind_api::MobilecoindUri;
use mc_sgx_css::Signature;
use mc_util_parse::{load_css_file, parse_duration_in_seconds};
use mc_util_uri::{ConnectionUri, ConsensusClientUri, FogUri};
#[cfg(feature = "ip-check")]
use reqwest::{
    blocking::Client,
    header::{HeaderMap, HeaderValue, InvalidHeaderValue, AUTHORIZATION, CONTENT_TYPE},
};
use std::{path::PathBuf, sync::Arc, time::Duration};

/// Configuration parameters for mobilecoind
#[derive(Debug, Parser)]
#[clap(name = "mobilecoind", about = "The MobileCoin client daemon.")]
pub struct Config {
    /// Path to ledger db (lmdb).
    #[clap(
        long,
        default_value = "/tmp/ledgerdb",
        parse(from_os_str),
        env = "MC_LEDGER_DB"
    )]
    pub ledger_db: PathBuf,

    /// Path to existing ledger db that contains the origin block, used when
    /// initializing new ledger dbs.
    #[clap(long, env = "MC_LEDGER_DB_BOOTSTRAP")]
    pub ledger_db_bootstrap: Option<String>,

    /// Path to watcher db (lmdb).
    #[clap(long, parse(from_os_str), env = "MC_WATCHER_DB")]
    pub watcher_db: Option<PathBuf>,

    /// Peers config.
    #[clap(flatten)]
    pub peers_config: PeersConfig,

    /// Quorum set for ledger syncing. By default, the quorum set would include
    /// all peers.
    ///
    /// The quorum set is represented in JSON. For example:
    /// {"threshold":1,"members":[{"type":"Node","args":"node2.test.mobilecoin.
    /// com:443"},{"type":"Node","args":"node3.test.mobilecoin.com:443"}]}
    #[clap(long, parse(try_from_str = parse_quorum_set_from_json), env = "MC_QUORUM_SET")]
    quorum_set: Option<QuorumSet<ResponderId>>,

    /// URLs to use for transaction data.
    ///
    /// For example: https://s3-us-west-1.amazonaws.com/mobilecoin.chain/node1.test.mobilecoin.com/
    #[clap(
        long = "tx-source-url",
        required_unless_present = "offline",
        use_value_delimiter = true,
        env = "MC_TX_SOURCE_URL"
    )]
    pub tx_source_urls: Option<Vec<String>>,

    /// How many seconds to wait between polling.
    #[clap(long, default_value = "5", parse(try_from_str = parse_duration_in_seconds), env = "MC_POLL_INTERVAL")]
    pub poll_interval: Duration,

    // Mobilecoind specific arguments
    /// Path to mobilecoind database used to store transactions and accounts.
    #[clap(long, parse(from_os_str), env = "MC_MOBILECOIND_DB")]
    pub mobilecoind_db: Option<PathBuf>,

    /// URI to listen on and serve requests from.
    #[clap(long, env = "MC_LISTEN_URI")]
    pub listen_uri: Option<MobilecoindUri>,

    /// Number of worker threads to use for view key scanning.
    /// Defaults to number of logical CPU cores.
    #[clap(long, env = "MC_NUM_WORKERS")]
    pub num_workers: Option<usize>,

    /// Offline mode.
    #[clap(long, env = "MC_OFFLINE")]
    pub offline: bool,

    /// Fog ingest enclave CSS file (needed in order to enable sending
    /// transactions to fog recipients).
    #[clap(long, parse(try_from_str = load_css_file), env = "MC_FOG_INGEST_ENCLAVE_CSS")]
    pub fog_ingest_enclave_css: Option<Signature>,

    /// Automatically migrate the ledger db into the most recent version.
    #[clap(long, env = "MC_LEDGER_DB_MIGRATE")]
    pub ledger_db_migrate: bool,

    /// An authorization token for the ipinfo.io service, if available
    #[clap(long, env = "MC_IP_INFO_TOKEN", default_value = "")]
    pub ip_info_token: String,
}

fn parse_quorum_set_from_json(src: &str) -> Result<QuorumSet<ResponderId>, String> {
    let quorum_set: QuorumSet<ResponderId> = serde_json::from_str(src)
        .map_err(|err| format!("Error parsing quorum set {}: {:?}", src, err))?;

    if !quorum_set.is_valid() {
        return Err(format!("Invalid quorum set: {:?}", quorum_set));
    }

    Ok(quorum_set)
}

/// Error type.
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

    /// Invalid header: {0}
    InvalidHeader(InvalidHeaderValue),
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

impl From<InvalidHeaderValue> for ConfigError {
    fn from(e: InvalidHeaderValue) -> Self {
        Self::InvalidHeader(e)
    }
}

impl Config {
    /// Parse the quorom set.
    /// Panics on error.
    pub fn quorum_set(&self) -> QuorumSet<ResponderId> {
        // If we have an explicit quorum set, use that.
        if let Some(quorum_set) = &self.quorum_set {
            return quorum_set.clone();
        }

        // Otherwise create a quorum set that includes all of the peers we know about.
        let node_ids = self.peers_config.responder_ids();
        QuorumSet::new_with_node_ids(node_ids.len() as u32, node_ids)
    }

    /// Get the attestation verifier used to verify fog reports when sending to
    /// fog recipients
    pub fn get_fog_ingest_verifier(&self) -> Option<Verifier> {
        self.fog_ingest_enclave_css.as_ref().map(|signature| {
            let mr_signer_verifier = {
                let mut mr_signer_verifier = MrSignerVerifier::new(
                    signature.mrsigner().into(),
                    signature.product_id(),
                    signature.version(),
                );
                mr_signer_verifier
                    .allow_hardening_advisories(mc_fog_ingest_enclave_measurement::HARDENING_ADVISORIES);
                mr_signer_verifier
            };

            let mut verifier = Verifier::default();
            verifier.debug(DEBUG_ENCLAVE).mr_signer(mr_signer_verifier);
            verifier
        })
    }

    /// Get the function which creates FogResolver given a list of recipient
    /// addresses The string error should be mapped by invoker of this
    /// factory to Error::FogError
    pub fn get_fog_resolver_factory(
        &self,
        logger: Logger,
    ) -> Arc<dyn Fn(&[FogUri]) -> Result<FogResolver, String> + Send + Sync> {
        let env = Arc::new(
            grpcio::EnvBuilder::new()
                .name_prefix("FogPubkeyResolver-RPC".to_string())
                .build(),
        );

        let conn = GrpcFogReportConnection::new(env, logger);

        let verifier = self.get_fog_ingest_verifier();

        Arc::new(move |fog_uris| -> Result<FogResolver, String> {
            if fog_uris.is_empty() {
                Ok(Default::default())
            } else if let Some(verifier) = verifier.as_ref() {
                let report_responses = conn
                    .fetch_fog_reports(fog_uris.iter().cloned())
                    .map_err(|err| format!("Failed fetching fog reports: {}", err))?;
                Ok(FogResolver::new(report_responses, verifier)
                    .map_err(|err| format!("Invalid fog url: {}", err))?)
            } else {
                Err(
                    "Some recipients have fog, but no fog ingest report verifier was configured"
                        .to_string(),
                )
            }
        })
    }

    /// Ensure local IP address is valid.
    ///
    /// Uses ipinfo.io for getting details about IP address.
    ///
    /// Note, both of these services are free tier and rate-limited. A longer
    /// term solution would be to filter on the consensus server.
    #[cfg(feature = "ip-check")]
    pub fn validate_host(&self) -> Result<(), ConfigError> {
        let client = Client::builder().gzip(true).use_rustls_tls().build()?;
        let mut json_headers = HeaderMap::new();
        json_headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));

        if !self.ip_info_token.is_empty() {
            json_headers.insert(
                AUTHORIZATION,
                HeaderValue::from_str(&format!("Bearer {}", self.ip_info_token))?,
            );
        }

        let response = client
            .get("https://ipinfo.io/json/")
            .headers(json_headers)
            .send()?
            .error_for_status()?;
        let data = response.text()?;
        let data_json: serde_json::Value = serde_json::from_str(&data)?;

        let data_missing_err = Err(ConfigError::DataMissing(data_json.to_string()));
        let country: &str = match data_json["country"].as_str() {
            Some(c) => c,
            None => return data_missing_err,
        };
        let region: &str = match data_json["region"].as_str() {
            Some(r) => r,
            None => return data_missing_err,
        };

        let err = Err(ConfigError::InvalidCountry);
        match country {
            "IR" | "SY" | "CU" | "KP" => err,
            "UA" => match region {
                "Crimea" => err,
                _ => Ok(()),
            },
            _ => Ok(()),
        }
    }

    /// Ensure local IP address is valid
    ///
    /// This does nothing when ip-check is disabled.
    #[cfg(not(feature = "ip-check"))]
    pub fn validate_host(&self) -> Result<(), ConfigError> {
        Ok(())
    }
}

/// Wrapper for configuring and parsing peer URIs.
#[derive(Clone, Debug, Parser)]
pub struct PeersConfig {
    /// Validator nodes to connect to.
    /// Sample usages:
    ///     --peer mc://foo:123 --peer mc://bar:456
    ///     --peer mc://foo:123,mc://bar:456
    ///     env MC_PEER=mc://foo:123,mc://bar:456
    #[clap(
        long = "peer",
        required_unless_present = "offline",
        env = "MC_PEER",
        use_value_delimiter = true
    )]
    pub peers: Option<Vec<ConsensusClientUri>>,
}

impl PeersConfig {
    /// Parse the peer URIs as ResponderIds.
    pub fn responder_ids(&self) -> Vec<ResponderId> {
        self.peers
            .as_ref()
            .unwrap()
            .iter()
            .map(|peer| {
                peer.responder_id().unwrap_or_else(|err| {
                    panic!("Could not get responder_id from peer URI {}: {}", peer, err)
                })
            })
            .collect()
    }

    /// Instantiate a client for each of the peer URIs.
    pub fn create_peers(
        &self,
        verifier: Verifier,
        grpc_env: Arc<grpcio::Environment>,
        logger: Logger,
    ) -> Vec<ThickClient<HardcodedCredentialsProvider>> {
        self.peers
            .as_ref()
            .unwrap()
            .iter()
            .map(|client_uri| {
                ThickClient::new(
                    client_uri.clone(),
                    verifier.clone(),
                    grpc_env.clone(),
                    HardcodedCredentialsProvider::from(client_uri),
                    logger.clone(),
                )
                .expect("Could not create thick client.")
            })
            .collect()
    }

    /// Instantiate a ConnectionManager for all the peers.
    pub fn create_peer_manager(
        &self,
        verifier: Verifier,
        logger: &Logger,
    ) -> ConnectionManager<ThickClient<HardcodedCredentialsProvider>> {
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
