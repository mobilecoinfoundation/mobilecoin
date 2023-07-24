// Copyright (c) 2018-2022 The MobileCoin Foundation

use displaydoc::Display;
use mc_common::logger::{log, o, Logger};
use mc_connection::{
    Error as ConnectionError, HardcodedCredentialsProvider, ProposeTxResult, RetryError,
    RetryableUserTxConnection, SyncConnection, ThickClient,
};
use mc_transaction_core::tx::Tx;
use mc_util_uri::{ConnectionUri, ConsensusClientUri};
use std::{iter::empty, sync::Arc};

type ConnectionType = SyncConnection<ThickClient<HardcodedCredentialsProvider>>;

pub struct TxSubmitter {
    conns: Vec<ConnectionType>,
}

impl TxSubmitter {
    /// Create a new TxSubmitter appropriate for slam
    pub fn new(
        uris: Vec<ConsensusClientUri>,
        env: Arc<grpcio::Environment>,
        logger: &Logger,
    ) -> Result<Self, String> {
        if uris.is_empty() {
            return Err("No consensus uris".to_owned());
        }
        let conns = Self::get_connections(&uris, env, logger)
            .map_err(|err| format!("consensus connection: {err}"))?;
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
        env: Arc<grpcio::Environment>,
        logger: &Logger,
    ) -> Result<Vec<ConnectionType>, ConnectionError> {
        let identity = mc_consensus_enclave_measurement::mr_signer_identity(None);
        uris.iter()
            .map(|uri| {
                let logger = logger.new(o!("mc.cxn" => uri.addr()));
                ThickClient::new(
                    // TODO: Pass a chain id to the mobilecoind-dev-faucet?
                    String::default(),
                    uri.clone(),
                    [identity.clone()],
                    env.clone(),
                    HardcodedCredentialsProvider::from(uri),
                    logger.clone(),
                )
                .map(|inner| SyncConnection::new(inner, logger))
            })
            .collect()
    }
}

#[derive(Clone, Debug, Display)]
pub enum SubmitTxError {
    /// Tx failed but may pass if retried
    Retry,
    /// Tx failed but may pass if re-built
    Rebuild,
    /// Tx failed irrecoverably
    Fatal,
}
