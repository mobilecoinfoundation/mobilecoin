// Copyright (c) 2018-2022 The MobileCoin Foundation

use displaydoc::Display;
use mc_attest_verifier::{MrEnclaveVerifier, Verifier, DEBUG_ENCLAVE};
use mc_common::logger::{log, o, Logger};
use mc_connection::{
    Error as ConnectionError, HardcodedCredentialsProvider, ProposeTxResult, RetryError,
    RetryableUserTxConnection, SyncConnection, ThickClient,
};
use mc_sgx_css::Signature;
use mc_transaction_core::tx::Tx;
use mc_util_uri::{ConnectionUri, ConsensusClientUri};
use std::{iter::empty, sync::Arc};

type ConnectionType = SyncConnection<ThickClient<HardcodedCredentialsProvider>>;

/// A TxSubmitter appropriate for usage in slam
pub struct TxSubmitter {
    conns: Vec<ConnectionType>,
}

impl TxSubmitter {
    /// Create a new TxSubmitter appropriate for slam
    ///
    /// Arguments:
    /// * uris: Consensus Client Uris (mc://) to submit to
    /// * consensus_enclave_css: Any additional MRENCLAVE's to trust
    /// * env: grpcio environment
    /// * logger
    pub fn new(
        uris: Vec<ConsensusClientUri>,
        consensus_enclave_css: Vec<Signature>,
        env: Arc<grpcio::Environment>,
        logger: &Logger,
    ) -> Result<Self, String> {
        if uris.is_empty() {
            return Err("No consensus uris".to_owned());
        }
        let conns = Self::get_connections(&uris, &consensus_enclave_css, env, logger)
            .map_err(|err| format!("consensus connection: {}", err))?;
        Ok(Self { conns })
    }

    /// Submit a Tx to the network, without retries
    ///
    /// Arguments:
    /// counter: The number of the utxo of this tx, for logging
    /// tx: The built tx to submit
    /// node_index: The node to submit to. (This will be reduced modulo num
    /// nodes)
    /// logger: Logger
    ///
    /// Returns: Current block height on success, error if submission failed
    pub fn submit_tx(
        &self,
        counter: u32,
        tx: &Tx,
        node_index: usize,
        logger: &Logger,
    ) -> Result<u64, SubmitTxError> {
        // Submit to a node in round robin fashion
        let node_index = node_index % self.conns.len();
        let conn = &self.conns[node_index];
        match conn.propose_tx(tx, empty()) {
            Ok(block_height) => Ok(block_height),
            Err(RetryError { error, .. }) => match error {
                ConnectionError::TransactionValidation(
                    ProposeTxResult::TombstoneBlockExceeded,
                    _,
                ) => {
                    log::debug!(logger, "Transaction {} tombstone block exceeded", counter);
                    Err(SubmitTxError::Rebuild)
                }
                ConnectionError::TransactionValidation(
                    ProposeTxResult::ContainsSpentKeyImage,
                    _,
                ) => {
                    log::info!(logger, "Transaction {} contains a spent key image", counter);
                    Err(SubmitTxError::Fatal)
                }
                error => {
                    log::warn!(
                        logger,
                        "Failed to submit transaction {} to node {}: {}",
                        counter,
                        conn,
                        error
                    );

                    if error.should_retry() {
                        Err(SubmitTxError::Retry)
                    } else {
                        Err(SubmitTxError::Fatal)
                    }
                }
            },
        }
    }

    /// Get thick client connections to all configured consensus nodes
    fn get_connections(
        uris: &[ConsensusClientUri],
        consensus_enclave_css: &[Signature],
        env: Arc<grpcio::Environment>,
        logger: &Logger,
    ) -> Result<Vec<ConnectionType>, ConnectionError> {
        let verifier = Self::get_consensus_verifier(consensus_enclave_css, logger);

        uris.iter()
            .map(|uri| {
                let logger = logger.new(o!("mc.cxn" => uri.addr()));
                ThickClient::new(
                    // TODO: Pass a chain id to the mobilecoind-dev-faucet?
                    String::default(),
                    uri.clone(),
                    verifier.clone(),
                    env.clone(),
                    HardcodedCredentialsProvider::from(uri),
                    logger.clone(),
                )
                .map(|inner| SyncConnection::new(inner, logger))
            })
            .collect()
    }

    /// Create a consensus enclave verifier, which allows the baked-in
    /// sigstruct, and any sigstructs produced at run-time via the
    /// MC_CONSENSUS_ENCLAVE_CSS list. This uses MRENCLAVE verification.
    fn get_consensus_verifier(consensus_enclave_css: &[Signature], logger: &Logger) -> Verifier {
        let mut verifier = Verifier::default();
        verifier.debug(DEBUG_ENCLAVE);

        let mut mr_enclave_verifier =
            MrEnclaveVerifier::from(mc_consensus_enclave_measurement::sigstruct());
        mr_enclave_verifier
            .allow_hardening_advisories(mc_consensus_enclave_measurement::HARDENING_ADVISORIES);
        verifier.mr_enclave(mr_enclave_verifier);

        for sig in consensus_enclave_css {
            let mut mr_enclave_verifier = MrEnclaveVerifier::from(sig.clone());
            mr_enclave_verifier
                .allow_hardening_advisories(mc_consensus_enclave_measurement::HARDENING_ADVISORIES);
            verifier.mr_enclave(mr_enclave_verifier);
        }

        log::debug!(logger, "Consensus Verifier: {:?}", verifier);

        verifier
    }
}

#[derive(Clone, Debug, Display)]
pub enum SubmitTxError {
    /// Tx failed but may pass if retried
    Retry,
    /// Tx failed but may pass if re-built with same inputs
    Rebuild,
    /// Tx failed irrecoverably
    Fatal,
}
