// Copyright (c) 2018-2021 The MobileCoin Foundation

//! Worker thread for collecting verification reports from nodes.

use crate::{config::SourceConfig, watcher_db::WatcherDB};
use grpcio::Environment;
use mc_attest_core::{VerificationReport, VerificationReportData, Verifier};
use mc_common::{
    logger::{log, Logger},
    time::SystemTimeProvider,
    HashMap,
};
use mc_connection::{
    AnyCredentialsProvider, AttestedConnection, HardcodedCredentialsProvider, ThickClient,
    TokenBasicCredentialsProvider,
};
use mc_crypto_keys::Ed25519Public;
use mc_util_grpc::TokenBasicCredentialsGenerator;
use mc_util_repr_bytes::ReprBytes;
use mc_util_uri::{ConnectionUri, ConsensusClientUri};
use std::{
    convert::TryFrom,
    marker::PhantomData,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    thread,
    time::Duration,
};
use url::Url;

/// A trait that specifies the functionality VerificationReportsCollector needs
/// in order to go from a ConsensusClientUri into a VerificationReport, and the
/// associated signer key.
pub trait NodeClient {
    /// Get a verification report for a given client.
    fn get_verification_report(
        source_config: &SourceConfig,
        env: Arc<Environment>,
        logger: Logger,
    ) -> Result<VerificationReport, String>;

    /// Get the block signer key out of a VerificationReport
    fn get_block_signer(verification_report: &VerificationReport) -> Result<Ed25519Public, String>;
}

/// An implementation of `NodeClient` that talks to a consensus node using
/// `ThickClient`.
pub struct ConsensusNodeClient;
impl NodeClient for ConsensusNodeClient {
    fn get_verification_report(
        source_config: &SourceConfig,
        env: Arc<Environment>,
        logger: Logger,
    ) -> Result<VerificationReport, String> {
        let node_url = source_config
            .consensus_client_url()
            .clone()
            .ok_or_else(|| "No consensus client url".to_owned())?;

        // Construct a credentials_provider based on our configuration.
        let credentials_provider =
            if let Some(secret) = source_config.consensus_client_auth_token_secret() {
                let username = node_url.username();
                let token_generator =
                    TokenBasicCredentialsGenerator::new(secret, SystemTimeProvider::default());
                let token_credentials_provider =
                    TokenBasicCredentialsProvider::new(username, token_generator);
                AnyCredentialsProvider::Token(token_credentials_provider)
            } else {
                AnyCredentialsProvider::Hardcoded(HardcodedCredentialsProvider::from(&node_url))
            };

        // Contact node and get a VerificationReport.
        let verifier = Verifier::default();
        let mut client = ThickClient::new(
            node_url.clone(),
            verifier,
            env,
            credentials_provider,
            logger,
        )
        .map_err(|err| {
            format!(
                "Failed constructing client to connect to {}: {}",
                node_url, err
            )
        })?;

        client
            .attest()
            .map_err(|err| format!("Failed attesting {}: {}", node_url, err))
    }

    /// Get the block signer key out of a VerificationReport
    fn get_block_signer(verification_report: &VerificationReport) -> Result<Ed25519Public, String> {
        let report_data = VerificationReportData::try_from(verification_report)
            .map_err(|err| format!("Failed constructing VerificationReportData: {}", err))?;

        let report_body = report_data
            .quote
            .report_body()
            .map_err(|err| format!("Failed getting report body: {}", err))?;

        let custom_data = report_body.report_data();
        let custom_data_bytes: &[u8] = custom_data.as_ref();

        if custom_data_bytes.len() != 64 {
            return Err(format!(
                "Unspected report data length: expected 64, got {}",
                custom_data_bytes.len()
            ));
        }

        let signer_bytes = &custom_data_bytes[32..];

        let signer_public_key = Ed25519Public::try_from(signer_bytes)
            .map_err(|err| format!("Unable to construct key: {}", err))?;

        Ok(signer_public_key)
    }
}

/// Periodically checks the verification report poll queue in the database and
/// attempts to contact nodes and get their verification report.
pub struct VerificationReportsCollector<NC: NodeClient = ConsensusNodeClient> {
    join_handle: Option<thread::JoinHandle<()>>,
    stop_requested: Arc<AtomicBool>,
    _nc: PhantomData<NC>,
}

impl<NC: NodeClient> VerificationReportsCollector<NC> {
    /// Create a new verification reports collector thread.
    pub fn new(
        watcher_db: WatcherDB,
        sources: Vec<SourceConfig>,
        poll_interval: Duration,
        logger: Logger,
    ) -> Self {
        let stop_requested = Arc::new(AtomicBool::new(false));

        let thread_stop_requested = stop_requested.clone();
        let join_handle = Some(
            thread::Builder::new()
                .name("VerificationReportsCollector".into())
                .spawn(move || {
                    let thread = VerificationReportsCollectorThread::<NC>::new(
                        watcher_db,
                        sources,
                        poll_interval,
                        logger,
                        thread_stop_requested,
                    );

                    thread.entrypoint();
                })
                .expect("Failed spawning VerificationReportsCollector thread"),
        );

        Self {
            join_handle,
            stop_requested,
            _nc: Default::default(),
        }
    }

    /// Stop the thread.
    pub fn stop(&mut self) {
        self.stop_requested.store(true, Ordering::SeqCst);
        if let Some(thread) = self.join_handle.take() {
            thread.join().expect("thread join failed");
        }
    }
}

impl<NC: NodeClient> Drop for VerificationReportsCollector<NC> {
    fn drop(&mut self) {
        self.stop();
    }
}

struct VerificationReportsCollectorThread<NC: NodeClient> {
    watcher_db: WatcherDB,
    sources: Vec<SourceConfig>,
    poll_interval: Duration,
    logger: Logger,
    stop_requested: Arc<AtomicBool>,
    grpcio_env: Arc<Environment>,
    _nc: PhantomData<NC>,
}

impl<NC: NodeClient> VerificationReportsCollectorThread<NC> {
    pub fn new(
        watcher_db: WatcherDB,
        sources: Vec<SourceConfig>,
        poll_interval: Duration,
        logger: Logger,
        stop_requested: Arc<AtomicBool>,
    ) -> Self {
        let grpcio_env = Arc::new(
            grpcio::EnvBuilder::new()
                .name_prefix("WatcherNodeGrpc")
                .build(),
        );

        Self {
            watcher_db,
            sources,
            poll_interval,
            logger,
            stop_requested,
            grpcio_env,
            _nc: Default::default(),
        }
    }

    pub fn entrypoint(self) {
        log::info!(self.logger, "VerificationReportsCollectorThread starting");
        loop {
            if self.stop_requested.load(Ordering::SeqCst) {
                log::debug!(
                    self.logger,
                    "VerificationReportsCollectorThread stop requested."
                );
                break;
            }

            // See whats currently in the queue.
            match self.watcher_db.get_verification_report_poll_queue() {
                Ok(queue) => self.process_queue(queue),
                Err(err) => {
                    log::error!(
                        self.logger,
                        "Failed getting verification report queue: {}",
                        err
                    );
                }
            };

            thread::sleep(self.poll_interval);
        }
    }

    fn process_queue(&self, queue: HashMap<Url, Vec<Ed25519Public>>) {
        for (tx_src_url, potential_signers) in queue {
            let hex_potential_signers = potential_signers
                .iter()
                .map(|signer| hex::encode(signer.to_bytes()))
                .collect::<Vec<_>>();
            log::debug!(
                self.logger,
                "Queue entry: {} -> {:?}",
                tx_src_url,
                hex_potential_signers
            );

            // See if we can get source information for this url.
            let source_config = self
                .sources
                .iter()
                .find(|source| source.tx_source_url() == tx_src_url);
            if source_config.is_none() {
                log::debug!(self.logger, "Skipping {} - not in sources", tx_src_url,);
                continue;
            }
            let source_config = source_config.unwrap();

            if source_config.consensus_client_url().is_none() {
                log::debug!(
                    self.logger,
                    "Skipping {} - no consensus_client_url configured",
                    tx_src_url,
                );
                continue;
            }
            let node_url = source_config.consensus_client_url().clone().unwrap();

            // Contact node and get a VerificationReport.
            let verification_report = match NC::get_verification_report(
                &source_config,
                self.grpcio_env.clone(),
                self.logger.clone(),
            ) {
                Ok(report) => report,
                Err(err) => {
                    log::error!(
                        self.logger,
                        "Failed getting report for {}: {}",
                        node_url,
                        err
                    );
                    return;
                }
            };

            self.process_report(
                &node_url,
                &tx_src_url,
                &potential_signers,
                &verification_report,
            );
        }
    }

    fn process_report(
        &self,
        node_url: &ConsensusClientUri,
        tx_src_url: &Url,
        potential_signers: &[Ed25519Public],
        verification_report: &VerificationReport,
    ) {
        let verification_report_block_signer = match NC::get_block_signer(verification_report) {
            Ok(key) => key,
            Err(err) => {
                log::error!(
                    self.logger,
                    "Failed extracting signer key from report by {}: {}",
                    node_url,
                    err
                );
                return;
            }
        };

        log::info!(
            self.logger,
            "Verification report from {} has block signer {}",
            node_url,
            hex::encode(verification_report_block_signer.to_bytes())
        );

        // Store the VerificationReport in the database, and also remove
        // verification_report_block_signer and potential_signers from the polling
        // queue.
        match self.watcher_db.add_verification_report(
            tx_src_url,
            &verification_report_block_signer,
            verification_report,
            potential_signers,
        ) {
            Ok(()) => {
                log::info!(
                    self.logger,
                    "Captured report for {}: block signer is {}",
                    tx_src_url,
                    hex::encode(verification_report_block_signer.to_bytes())
                );
            }
            Err(err) => {
                log::error!(
                    self.logger,
                    "Failed writing verification report to database: {} (src_url:{} verification_report_block_signer:{} potential_signers:{:?}",
                    err,
                    tx_src_url,
                    hex::encode(verification_report_block_signer.to_bytes()),
                    potential_signers.iter().map(|key| hex::encode(key.to_bytes())).collect::<Vec<_>>(),
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::watcher_db::tests::{setup_blocks, setup_watcher_db};
    use mc_attest_core::VerificationSignature;
    use mc_common::logger::{test_with_logger, Logger};
    use mc_crypto_digestible::{Digestible, MerlinTranscript};
    use mc_crypto_keys::{Ed25519Pair, Ed25519Private};
    use mc_transaction_core::BlockSignature;
    use serial_test_derive::serial;
    use std::{iter::FromIterator, str::FromStr, sync::Mutex, thread::sleep};

    // A contraption that allows us to return a specific VerificationReport for a
    // given ConsensusClientUri while also allowing the tests to control it.
    // Due to the global scope of this, mandated by the NodeClient trait, the tests
    // have to run in serial.
    lazy_static::lazy_static! {
        static ref REPORT_VERSION: Arc<Mutex<HashMap<ConsensusClientUri, u8>>> =
        Arc::new(Mutex::new(HashMap::default()));
    }

    struct TestNodeClient;
    impl TestNodeClient {
        pub fn reset() {
            let mut report_version_map = REPORT_VERSION.lock().unwrap();
            report_version_map.clear();
        }

        pub fn current_expected_report(node_url: &ConsensusClientUri) -> VerificationReport {
            let report_version_map = REPORT_VERSION.lock().unwrap();
            let report_version = report_version_map.get(&node_url).map(|v| *v).unwrap_or(1);

            VerificationReport {
                sig: VerificationSignature::from(vec![report_version; 32]),
                chain: vec![vec![report_version; 16], vec![3; 32]],
                http_body: node_url.to_string(),
            }
        }

        pub fn report_signer(verification_report: &VerificationReport) -> Ed25519Pair {
            // Convert the report into a 32 bytes hash so that we could construct a
            // consistent key from it.
            let bytes = mc_util_serial::encode(verification_report);
            let hash: [u8; 32] = bytes.digest32::<MerlinTranscript>(b"verification_report");
            let priv_key = Ed25519Private::try_from(&hash[..]).unwrap();
            Ed25519Pair::from(priv_key)
        }

        pub fn current_signer(node_url: &ConsensusClientUri) -> Ed25519Pair {
            let verification_report = Self::current_expected_report(node_url);
            Self::report_signer(&verification_report)
        }
    }
    impl NodeClient for TestNodeClient {
        fn get_verification_report(
            source_config: &SourceConfig,
            _env: Arc<Environment>,
            _logger: Logger,
        ) -> Result<VerificationReport, String> {
            Ok(Self::current_expected_report(
                &source_config.consensus_client_url().clone().unwrap(),
            ))
        }

        fn get_block_signer(
            verification_report: &VerificationReport,
        ) -> Result<Ed25519Public, String> {
            Ok(Self::report_signer(verification_report).public_key())
        }
    }

    #[test_with_logger]
    #[serial]
    fn test_background_sync_happy_flow(logger: Logger) {
        TestNodeClient::reset();

        let tx_src_url1 = Url::parse("http://www.my_url1.com").unwrap();
        let tx_src_url2 = Url::parse("http://www.my_url2.com").unwrap();
        let tx_src_url3 = Url::parse("http://www.my_url3.com").unwrap();
        let tx_src_urls = vec![
            tx_src_url1.clone(),
            tx_src_url2.clone(),
            tx_src_url3.clone(),
        ];
        let watcher_db = setup_watcher_db(&tx_src_urls, logger.clone());
        let blocks = setup_blocks();
        let filename = String::from("00/00");

        let node1_url = ConsensusClientUri::from_str("mc://node1.test.com:443/").unwrap();
        let node2_url = ConsensusClientUri::from_str("mc://node2.test.com:443/").unwrap();
        let node3_url = ConsensusClientUri::from_str("mc://node3.test.com:443/").unwrap();

        let sources = vec![
            SourceConfig::new(tx_src_url1.to_string(), Some(node1_url.clone()), None),
            SourceConfig::new(tx_src_url2.to_string(), Some(node2_url.clone()), None),
            // Node 3 is omitted on purpose to ensure it gets no data.
        ];

        let _verification_reports_collector = VerificationReportsCollector::<TestNodeClient>::new(
            watcher_db.clone(),
            sources,
            Duration::from_millis(100),
            logger,
        );

        // Get the current signers for node1, node2 and node3. They should all be
        // different and consistent.
        let signer1 = TestNodeClient::current_signer(&node1_url);
        let signer2 = TestNodeClient::current_signer(&node2_url);
        let signer3 = TestNodeClient::current_signer(&node3_url);

        assert_ne!(signer1.public_key(), signer2.public_key());
        assert_ne!(signer1.public_key(), signer3.public_key());
        assert_ne!(signer2.public_key(), signer3.public_key());

        assert_eq!(
            signer1.public_key(),
            TestNodeClient::current_signer(&node1_url).public_key()
        );
        assert_eq!(
            signer2.public_key(),
            TestNodeClient::current_signer(&node2_url).public_key()
        );
        assert_eq!(
            signer3.public_key(),
            TestNodeClient::current_signer(&node3_url).public_key()
        );

        // No data should be available for any of the signers.
        assert_eq!(
            watcher_db
                .get_verification_reports_for_signer(&signer1.public_key())
                .unwrap(),
            HashMap::default()
        );
        assert_eq!(
            watcher_db
                .get_verification_reports_for_signer(&signer2.public_key())
                .unwrap(),
            HashMap::default()
        );
        assert_eq!(
            watcher_db
                .get_verification_reports_for_signer(&signer3.public_key())
                .unwrap(),
            HashMap::default()
        );

        // Add a block signature for signer1, this should get the background thread to
        // get the VerificationReport from node1 and put it into the database.
        let signed_block_a1 =
            BlockSignature::from_block_and_keypair(&blocks[0].0, &signer1).unwrap();
        watcher_db
            .add_block_signature(&tx_src_url1, 1, signed_block_a1, filename.clone())
            .unwrap();

        let mut tries = 30;
        let expected_reports = HashMap::from_iter(vec![(
            tx_src_url1.clone(),
            vec![Some(TestNodeClient::current_expected_report(&node1_url))],
        )]);
        loop {
            let reports = watcher_db
                .get_verification_reports_for_signer(&signer1.public_key())
                .unwrap();
            if reports == expected_reports {
                break;
            }

            if tries == 0 {
                panic!("report not synced");
            }
            tries -= 1;
            sleep(Duration::from_millis(100));
        }

        // Add a block signature for signer2, while the returned report is still
        // signer1.
        let signed_block_a2 =
            BlockSignature::from_block_and_keypair(&blocks[1].0, &signer2).unwrap();
        watcher_db
            .add_block_signature(&tx_src_url1, 1, signed_block_a2, filename.clone())
            .unwrap();

        let mut tries = 30;
        let expected_reports_signer1 = HashMap::from_iter(vec![(
            tx_src_url1.clone(),
            vec![Some(TestNodeClient::current_expected_report(&node1_url))],
        )]);
        let expected_reports_signer2 = HashMap::from_iter(vec![(tx_src_url1.clone(), vec![None])]);
        loop {
            let reports_1 = watcher_db
                .get_verification_reports_for_signer(&signer1.public_key())
                .unwrap();
            let reports_2 = watcher_db
                .get_verification_reports_for_signer(&signer2.public_key())
                .unwrap();
            if reports_1 == expected_reports_signer1 && reports_2 == expected_reports_signer2 {
                break;
            }

            if tries == 0 {
                panic!("report not synced");
            }
            tries -= 1;
            sleep(Duration::from_millis(100));
        }

        // Change the report for node 1 and ensure it gets captured.
        {
            let mut report_version_map = REPORT_VERSION.lock().unwrap();
            report_version_map.insert(node1_url.clone(), 12);
        }

        let updated_signer1 = TestNodeClient::current_signer(&node1_url);
        assert_ne!(signer1.public_key(), updated_signer1.public_key());
        assert_eq!(
            signer2.public_key(),
            TestNodeClient::current_signer(&node2_url).public_key()
        );
        assert_eq!(
            signer3.public_key(),
            TestNodeClient::current_signer(&node3_url).public_key()
        );

        let signed_block_a3 =
            BlockSignature::from_block_and_keypair(&blocks[2].0, &updated_signer1).unwrap();
        watcher_db
            .add_block_signature(&tx_src_url1, 3, signed_block_a3, filename.clone())
            .unwrap();

        let mut tries = 30;
        let expected_reports_updated_signer1 = HashMap::from_iter(vec![(
            tx_src_url1.clone(),
            vec![Some(TestNodeClient::current_expected_report(&node1_url))],
        )]);
        loop {
            let signer1_reports = watcher_db
                .get_verification_reports_for_signer(&signer1.public_key())
                .unwrap();
            let updated_signer1_reports = watcher_db
                .get_verification_reports_for_signer(&updated_signer1.public_key())
                .unwrap();
            if signer1_reports == expected_reports_signer1
                && updated_signer1_reports == expected_reports_updated_signer1
            {
                break;
            }

            if tries == 0 {
                panic!("report not synced");
            }
            tries -= 1;
            sleep(Duration::from_millis(100));
        }

        // Add two more blocks, one for node2 (that we can reach) and one for node3
        // (that we can't reach)
        let signed_block_b1 =
            BlockSignature::from_block_and_keypair(&blocks[0].0, &signer2).unwrap();
        watcher_db
            .add_block_signature(&tx_src_url2, 1, signed_block_b1, filename.clone())
            .unwrap();

        let signed_block_c1 =
            BlockSignature::from_block_and_keypair(&blocks[0].0, &signer3).unwrap();
        watcher_db
            .add_block_signature(&tx_src_url3, 1, signed_block_c1, filename.clone())
            .unwrap();

        let mut tries = 30;
        let expected_reports_signer2 = HashMap::from_iter(vec![
            (tx_src_url1.clone(), vec![None]),
            (
                tx_src_url2.clone(),
                vec![Some(TestNodeClient::current_expected_report(&node2_url))],
            ),
        ]);
        let expected_reports_signer3 = HashMap::default();
        loop {
            let reports_signer2 = watcher_db
                .get_verification_reports_for_signer(&signer2.public_key())
                .unwrap();

            let reports_signer3 = watcher_db
                .get_verification_reports_for_signer(&signer3.public_key())
                .unwrap();

            if expected_reports_signer2 == reports_signer2
                && expected_reports_signer3 == reports_signer3
            {
                break;
            }

            if tries == 0 {
                panic!(
                    "report not synced: reports_signer2:{:?} reports_signer3:{:?}",
                    reports_signer2, reports_signer3
                );
            }
            tries -= 1;
            sleep(Duration::from_millis(100));
        }
    }
}
