// Copyright (c) 2018-2021 The MobileCoin Foundation

//! Worker thread for collecting verification reports from nodes.

use crate::watcher_db::WatcherDB;
use grpcio::Environment;
use mc_attest_core::{VerificationReport, VerificationReportData, Verifier, DEBUG_ENCLAVE};
use mc_common::{
    logger::{log, Logger},
    HashMap,
};
use mc_connection::{AttestedConnection, ThickClient};
use mc_crypto_keys::Ed25519Public;
use mc_util_repr_bytes::ReprBytes;
use mc_util_uri::ConsensusClientUri;
use std::{
    convert::TryFrom,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    thread,
    time::Duration,
};
use url::Url;

/// Periodically checks the verification report poll queue in the database and attempts to contact
/// nodes and get their verification report.
pub struct VerificationReportsCollector {
    join_handle: Option<thread::JoinHandle<()>>,
    stop_requested: Arc<AtomicBool>,
}

impl VerificationReportsCollector {
    /// Create a new verification reports collector thread.
    pub fn new(
        watcher_db: WatcherDB,
        tx_source_urls_to_consensus_client_urls: HashMap<String, ConsensusClientUri>,
        poll_interval: Duration,
        logger: Logger,
    ) -> Self {
        let stop_requested = Arc::new(AtomicBool::new(false));

        let thread_stop_requested = stop_requested.clone();
        let join_handle = Some(
            thread::Builder::new()
                .name("VerificationReportsCollector".into())
                .spawn(move || {
                    let thread = VerificationReportsCollectorThread::new(
                        watcher_db,
                        tx_source_urls_to_consensus_client_urls,
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
        }
    }

    /// Stop the thread.
    pub fn stop(&mut self) {
        // TODO an option to wait until the queue is empty.
        self.stop_requested.store(true, Ordering::SeqCst);
        if let Some(thread) = self.join_handle.take() {
            thread.join().expect("thread join failed");
        }
    }
}

impl Drop for VerificationReportsCollector {
    fn drop(&mut self) {
        self.stop();
    }
}

struct VerificationReportsCollectorThread {
    watcher_db: WatcherDB,
    tx_source_urls_to_consensus_client_urls: HashMap<String, ConsensusClientUri>,
    poll_interval: Duration,
    logger: Logger,
    stop_requested: Arc<AtomicBool>,
    grpcio_env: Arc<Environment>,
}

impl VerificationReportsCollectorThread {
    pub fn new(
        watcher_db: WatcherDB,
        tx_source_urls_to_consensus_client_urls: HashMap<String, ConsensusClientUri>,
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
            tx_source_urls_to_consensus_client_urls,
            poll_interval,
            logger,
            stop_requested,
            grpcio_env,
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

            // See if we can get a node url for this tx_src_url.
            let node_url = self
                .tx_source_urls_to_consensus_client_urls
                .get(tx_src_url.as_str());
            if node_url.is_none() {
                log::debug!(
                    self.logger,
                    "Skipping {} - not in tx_source_urls_to_consensus_client_urls",
                    tx_src_url,
                );
                continue;
            }
            let node_url = node_url.unwrap();

            // Contact node and get a VerificationReport.
            let mut verifier = Verifier::default();
            verifier.debug(DEBUG_ENCLAVE);

            let mut client = match ThickClient::new(
                node_url.clone(),
                verifier,
                self.grpcio_env.clone(),
                self.logger.clone(),
            ) {
                Ok(client) => client,
                Err(err) => {
                    log::error!(
                        self.logger,
                        "Failed constructing client to connect to {}: {}",
                        node_url,
                        err
                    );
                    return;
                }
            };

            // Attest in order to get a VerificationReport
            match client.attest() {
                Ok(report) => {
                    self.process_report(&node_url, &tx_src_url, &potential_signers, &report)
                }
                Err(err) => {
                    log::error!(
                        self.logger,
                        "Failed attesting to {} (for {}): {}",
                        node_url,
                        tx_src_url,
                        err
                    );
                }
            }
        }
    }

    fn process_report(
        &self,
        node_url: &ConsensusClientUri,
        tx_src_url: &Url,
        potential_signers: &[Ed25519Public],
        verification_report: &VerificationReport,
    ) {
        let report_data = match VerificationReportData::try_from(verification_report) {
            Ok(data) => data,
            Err(err) => {
                log::error!(
                    self.logger,
                    "Failed extracting report data from {}: {}",
                    node_url,
                    err
                );
                return;
            }
        };

        let report_body = match report_data.quote.report_body() {
            Ok(body) => body,
            Err(err) => {
                log::error!(
                    self.logger,
                    "Failed getting report body from {}: {}",
                    node_url,
                    err
                );
                return;
            }
        };

        let custom_data = report_body.report_data();
        let custom_data_bytes: &[u8] = custom_data.as_ref();

        let signer_bytes = &custom_data_bytes[32..];

        log::crit!(self.logger, "HEH {:?}", hex::encode(signer_bytes));
    }
}
