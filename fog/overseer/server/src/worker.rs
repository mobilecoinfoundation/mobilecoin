// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Contains the worker thread that performs the business logic for Fog
//! Overseer.
//!
//! This is the "core" logic for Overseer.
//!
//! HTTP Client -> Overseer Rocket Server -> OverseerService -> *OverseerWorker*

use crate::error::OverseerError;
use mc_api::external;
use mc_common::logger::{log, Logger};
use mc_crypto_keys::CompressedRistrettoPublic;
use mc_fog_api::ingest_common::{IngestControllerMode, IngestSummary};
use mc_fog_ingest_client::FogIngestGrpcClient;
use mc_fog_recovery_db_iface::{IngressPublicKeyRecord, IngressPublicKeyRecordFilters, RecoveryDb};
use mc_fog_uri::FogIngestUri;
use retry::{delay::Fixed, retry_with_index, OperationResult};
use std::{
    convert::TryFrom,
    iter::Iterator,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    thread::{Builder as ThreadBuilder, JoinHandle},
    time::Duration,
};

/// Wraps a thread that is responsible for overseeing the active Fog Ingest
/// cluster.
///
/// The worker checks to see that there's always one active ingress key. If
/// there is no active key, then it promotes an idle node to active, and in the
/// case where none of the idle nodes contain the previously active ingress key,
/// it reports that key as lost.
pub struct OverseerWorker {
    /// Join handle used to wait for the thread to terminate.
    join_handle: Option<JoinHandle<()>>,

    /// If true, stops the worker thread.
    stop_requested: Arc<AtomicBool>,
}

impl OverseerWorker {
    /// Retry failed GRPC requests every 10 seconds.
    const GRPC_RETRY_SECONDS: Duration = Duration::from_millis(10000);

    pub fn new<DB: RecoveryDb + Clone + Send + Sync + 'static>(
        ingest_cluster_uris: Vec<FogIngestUri>,
        recovery_db: DB,
        logger: Logger,
        is_enabled: Arc<AtomicBool>,
    ) -> Self
    where
        OverseerError: From<DB::Error>,
    {
        let thread_is_enabled = is_enabled;
        let stop_requested = Arc::new(AtomicBool::new(false));
        let thread_stop_requested = stop_requested.clone();
        let grpcio_env = Arc::new(grpcio::EnvBuilder::new().build());
        let ingest_clients: Vec<FogIngestGrpcClient> = ingest_cluster_uris
            .iter()
            .map(|fog_ingest_uri| {
                FogIngestGrpcClient::new(
                    fog_ingest_uri.clone(),
                    Self::GRPC_RETRY_SECONDS,
                    grpcio_env.clone(),
                    logger.clone(),
                )
            })
            .collect();
        let join_handle = Some(
            ThreadBuilder::new()
                .name("OverseerWorker".to_string())
                .spawn(move || {
                    OverseerWorkerThread::start(
                        ingest_clients,
                        recovery_db,
                        thread_is_enabled,
                        thread_stop_requested,
                        logger,
                    )
                })
                .expect("Could not spawn OverseerWorkerThread"),
        );

        Self {
            join_handle,
            stop_requested,
        }
    }

    /// Stop and join the db poll thread
    pub fn stop(&mut self) -> Result<(), ()> {
        if let Some(join_handle) = self.join_handle.take() {
            self.stop_requested.store(true, Ordering::SeqCst);
            join_handle.join().map_err(|_| ())?;
        }

        Ok(())
    }
}

impl Drop for OverseerWorker {
    fn drop(&mut self) {
        let _ = self.stop();
    }
}

/// The thread that performs the Fog Overseer logic.
struct OverseerWorkerThread<DB: RecoveryDb> {
    /// The list of FogIngestClients that Overseer uses to communicate with
    /// each node in the Fog Ingest cluster that it's monitoring.
    ingest_clients: Vec<FogIngestGrpcClient>,

    /// The database that contains, among other things, info on the Fog Ingest
    /// cluster's ingress keys.
    recovery_db: DB,

    /// If this is true, the worker will not perform it's monitoring logic.
    is_enabled: Arc<AtomicBool>,

    /// If this is true, the thread will stop.
    stop_requested: Arc<AtomicBool>,

    logger: Logger,
}

/// This associates an IngestSummary with an IngestClient. This makes it easy
/// to query a given node based on its IngestSummary.
struct IngestSummaryNodeMapping {
    node_index: usize,

    ingest_summary: IngestSummary,
}

impl<DB: RecoveryDb> OverseerWorkerThread<DB>
where
    OverseerError: From<DB::Error>,
{
    /// Poll the Fog Ingest cluster every 5 seconds.
    const POLLING_FREQUENCY: Duration = Duration::from_secs(5);

    /// Try a request to Fog Ingest node this many times if you encounter an
    /// error.
    const NUMBER_OF_TRIES: usize = 3;

    pub fn start(
        ingest_clients: Vec<FogIngestGrpcClient>,
        recovery_db: DB,
        is_enabled: Arc<AtomicBool>,
        stop_requested: Arc<AtomicBool>,
        logger: Logger,
    ) {
        let thread = Self {
            ingest_clients,
            recovery_db,
            is_enabled,
            stop_requested,
            logger,
        };
        thread.run();
    }

    fn run(self) {
        loop {
            log::trace!(self.logger, "Overseer worker start of thread.");
            std::thread::sleep(Self::POLLING_FREQUENCY);

            if self.stop_requested.load(Ordering::SeqCst) {
                log::info!(self.logger, "Overseer worker thread stopping.");
                break;
            }

            if !self.is_enabled.load(Ordering::SeqCst) {
                log::trace!(self.logger, "Overseer worker is currently disabled.");
                continue;
            }

            let ingest_summary_node_mappings: Vec<IngestSummaryNodeMapping> = match self
                .retrieve_ingest_summary_node_mappings()
            {
                Ok(ingest_summary_node_mappings) => ingest_summary_node_mappings,
                Err(err) => {
                    log::error!(self.logger, "Encountered an error while retrieving ingest summaries: {}. Returning to beginning of overseer logic.", err);
                    continue;
                }
            };

            // TODO: Use these ingest summaries to send the desired metadata
            // to Prometheus: number of keys, number of active nodes, etc.
            let active_ingest_summary_node_mappings: Vec<&IngestSummaryNodeMapping> =
                ingest_summary_node_mappings
                    .iter()
                    .filter(|ingest_summary_node_mapping| {
                        ingest_summary_node_mapping.ingest_summary.mode
                            == IngestControllerMode::Active
                    })
                    .collect();

            let active_node_count = active_ingest_summary_node_mappings.len();
            match active_node_count {
                0 => {
                    log::warn!(
                        self.logger,
                        "There are currently no active nodes in the Fog Ingest cluster. Initiating automatic failover.",
                    );
                    match self.perform_automatic_failover(ingest_summary_node_mappings) {
                        Ok(_) => {
                            log::info!(self.logger, "Automatic failover completed successfully.")
                        }
                        Err(err) => {
                            log::error!(self.logger, "Automatic failover failed: {:?}", err)
                        }
                    };
                }
                1 => {
                    log::trace!(
                        self.logger,
                        "There is one active node in the Fog Ingest cluster. Active ingress key: {:?}",
                        active_ingest_summary_node_mappings[0]
                        .ingest_summary
                        .get_ingress_pubkey()
                    );
                    continue;
                }
                _ => {
                    let active_node_ingress_pubkeys: Vec<&external::CompressedRistretto> =
                        active_ingest_summary_node_mappings
                            .iter()
                            .map(|active_ingest_summary_node_mapping| {
                                active_ingest_summary_node_mapping
                                    .ingest_summary
                                    .get_ingress_pubkey()
                            })
                            .collect();
                    log::error!(
                        self.logger,
                        "There are multiple active nodes in the Fog Ingest cluster. Active ingress keys: {:?}",
                        active_node_ingress_pubkeys
                    );
                    // TODO: Set up sentry alerts and signal to ops that two
                    // keys are active at once. This is
                    // unexpected.
                }
            }
        }
    }

    /// Returns the latest round of ingest summaries for each
    /// FogIngestGrpcClient that communicates with a node that is online.
    fn retrieve_ingest_summary_node_mappings(
        &self,
    ) -> Result<Vec<IngestSummaryNodeMapping>, OverseerError> {
        let mut ingest_summary_node_mappings: Vec<IngestSummaryNodeMapping> = Vec::new();
        for (ingest_client_index, ingest_client) in self.ingest_clients.iter().enumerate() {
            match ingest_client.get_status() {
                Ok(ingest_summary) => {
                    log::trace!(
                        self.logger,
                        "Ingest summary retrieved: {:?}",
                        ingest_summary
                    );
                    ingest_summary_node_mappings.push(IngestSummaryNodeMapping {
                        node_index: ingest_client_index,
                        ingest_summary,
                    });
                }
                Err(err) => {
                    let error_message = format!(
                        "Unable to retrieve ingest summary for node ({}): {}",
                        ingest_client.get_uri(),
                        err
                    );
                    return Err(OverseerError::UnresponsiveNodeError(error_message));
                }
            }
        }

        Ok(ingest_summary_node_mappings)
    }

    /// Performs automatic failover, which means that we try to activate nodes
    /// for an outstanding ingress key, if it exists.
    ///
    /// The logic is as follows:
    ///   1. Find all of the "outstanding keys" as determined by the RecoveryDb.
    ///      These are ingress keys that Fog Ingest needs to scan blocks with
    ///      but Fog Ingest isn't currently doing that because all nodes are
    ///      idle.
    ///   2. If there are:
    ///         a) 0 outstanding keys:
    ///              No node will be activated. We now have to:
    ///                 (i)  Set new keys on an idle node.
    ///                 (ii) Activate that node.
    ///         b) 1 outsanding key:
    ///              Try to find an idle node that contains that key.
    ///                 (i)  If you find one, great! Just activate that node. If
    ///                      activation is unsuccessful, then return an error
    ///                      and return to the overseer polling logic.
    ///                 (ii) If you don't find an idle node with that key,
    ///                      then you have to report that key as lost, set
    ///                      new keys on an idle node, and activate that node.
    ///        c) > 1 outstanding key:
    ///             (i) Disable
    ///             (ii) TODO: Send an alert.
    fn perform_automatic_failover(
        &self,
        ingest_summary_node_mappings: Vec<IngestSummaryNodeMapping>,
    ) -> Result<(), OverseerError> {
        let inactive_outstanding_keys: Vec<CompressedRistrettoPublic> =
            self.get_inactive_outstanding_keys()?;

        match inactive_outstanding_keys.len() {
            0 => {
                log::info!(self.logger, "Found 0 outstanding keys.");
                let activated_node_index = self.set_new_key_on_a_node()?;
                self.activate_a_node(activated_node_index)?;
                Ok(())
            }
            1 => {
                log::info!(self.logger, "Found 1 outstanding key.");
                let inactive_outstanding_key = inactive_outstanding_keys[0];
                self.handle_one_inactive_outstanding_key(
                    inactive_outstanding_key,
                    ingest_summary_node_mappings,
                )?;
                Ok(())
            }
            _ => {
                log::error!(self.logger, "Found multiple outstanding keys {:?}. This requires manual intervention. Disabling overseer.", inactive_outstanding_keys);
                self.is_enabled.store(false, Ordering::SeqCst);
                Err(OverseerError::MultipleOutstandingKeys("Multiple outstanding keys found. This is unexpected and requires manual intervention. As such, we've disabled overseer. Take action and then enable overseer.".to_string()))
            }
        }
    }

    fn get_inactive_outstanding_keys(
        &self,
    ) -> Result<Vec<CompressedRistrettoPublic>, OverseerError> {
        // An outanding key is one that Fog Ingest is still obligated to be
        // scanning blocks with on behalf of users.
        let outstanding_keys_filters = IngressPublicKeyRecordFilters {
            // A lost key can never be outstanding because it will never again
            // be used to scan blocks.
            should_include_lost_keys: false,
            // Its possible for a retired key to be outstanding if its public
            // expiry is greater than its last scanned block, so we have to
            // include retired keys in this query.
            should_include_retired_keys: true,
            // If a key has expired- i.e. its last scanned block is greater
            // than or equal to its public expiry- then it will no longer scan
            // blocks. Therefore, we need to include unexpired keys because they
            // are still supposed to be scanned by Fog.
            should_only_include_unexpired_keys: true,
        };

        // First, find the "inactive_outstanding_keys" which are outstanding
        // keys that we've grabbed from the RecoveryDb.
        //
        // TODO: Add a config that allows us to set this start block.
        let ingress_public_key_records: Vec<IngressPublicKeyRecord> =
            self.recovery_db.get_ingress_key_records(
                /* start_block_at_least= */ 0,
                outstanding_keys_filters,
            )?;

        Ok(ingress_public_key_records
            .iter()
            .map(|record| record.key)
            .collect())
    }

    /// Performs the following logic when one inactive outstanding key is found:
    ///   1) Tries to find an idle node that contains that key.
    ///      (i)  If it's found, it activates the node that contains it. If
    ///           activation is unsuccessful, then it returns an error.
    ///      (ii) If no idle node is found that contains the key, then it
    ///           reports that key as lost, sets new keys on an idle node, and
    ///           activates that node.
    fn handle_one_inactive_outstanding_key(
        &self,
        inactive_outstanding_key: CompressedRistrettoPublic,
        ingest_summary_node_mappings: Vec<IngestSummaryNodeMapping>,
    ) -> Result<(), OverseerError> {
        log::info!(
            self.logger,
            "Trying to activate an idle node with inactive outstanding key: {:?}",
            &inactive_outstanding_key
        );
        for ingest_summary_node_mapping in &ingest_summary_node_mappings {
            let node_ingress_key = match CompressedRistrettoPublic::try_from(
                ingest_summary_node_mapping
                    .ingest_summary
                    .get_ingress_pubkey(),
            ) {
                Ok(key) => key,
                Err(_) => continue,
            };
            if inactive_outstanding_key.eq(&node_ingress_key) {
                let node = &self.ingest_clients[ingest_summary_node_mapping.node_index];
                match node.activate() {
                    Ok(_) => {
                        log::info!(
                            self.logger,
                            "Successfully activated node {}.",
                            node.get_uri()
                        );
                        return Ok(());
                    }
                    Err(err) => {
                        let error_message = format!(
                            "Tried activating node {}, but it failed: {}.",
                            node.get_uri(),
                            err
                        );
                        return Err(OverseerError::ActivateNode(error_message));
                    }
                }
            }
        }

        // We've gone through all the Fog Ingest nodes' keys,
        // and none of them matches the inactive outstanding key. We must
        // report the inactive outstanding key as lost, set new keys
        // on an idle node, and activate that node.
        self.report_lost_ingress_key(inactive_outstanding_key)?;
        let activated_node_index = self.set_new_key_on_a_node()?;
        self.activate_a_node(activated_node_index)?;

        Ok(())
    }

    /// Tries to report a lost ingress key.
    fn report_lost_ingress_key(
        &self,
        inactive_outstanding_key: CompressedRistrettoPublic,
    ) -> Result<(), OverseerError> {
        let result = retry_with_index(
            Fixed::from_millis(200).take(Self::NUMBER_OF_TRIES),
            |current_try| match self
                .recovery_db
                .report_lost_ingress_key(inactive_outstanding_key)
            {
                Ok(_) => {
                    log::info!(
                        self.logger,
                        "The following key was successfully reported as lost: {}",
                        inactive_outstanding_key
                    );
                    OperationResult::Ok(())
                }
                Err(err) => {
                    let number_of_remaining_tries = Self::NUMBER_OF_TRIES - current_try as usize;
                    let error_message = match number_of_remaining_tries {
                        0 => format!("Did not succeed in reporting lost ingress key {} within {} tries. Underlying error: {}", inactive_outstanding_key, Self::NUMBER_OF_TRIES, err),
                        _ => format!("The following key was not successfully reported as lost: {}. Will try {} more times. Underlying error: {}", inactive_outstanding_key, number_of_remaining_tries, err),
                    };
                    OperationResult::Retry(OverseerError::ReportLostKey(error_message))
                }
            },
        );

        Ok(result?)
    }

    /// Tries to set a new ingress key on a node. The node is assumed to be
    /// idle.
    fn set_new_key_on_a_node(&self) -> Result<usize, OverseerError> {
        for (i, ingest_client) in self.ingest_clients.iter().enumerate() {
            let result = retry_with_index(
                Fixed::from_millis(200).take(Self::NUMBER_OF_TRIES),
                |current_try| {
                    match ingest_client.new_keys() {
                        Ok(_) => {
                            log::info!(
                                self.logger,
                                "New keys successfully set on the ingest node at index {}.",
                                i
                            );
                            OperationResult::Ok(())
                        }
                        // TODO: We'll need to alert Ops to take manual action at this point.
                        Err(err) => {
                            let number_of_remaining_tries = Self::NUMBER_OF_TRIES - current_try as usize;
                            let error_message = match number_of_remaining_tries {
                                0 => format!("Did not succeed in setting a new key on node at index {}. Underlying error: {}", i, err),
                                _ => format!("New keys were not successfully set on the ingest node at index {}. Will try {} more times. Underlying error: {}", i, number_of_remaining_tries, err),
                            };
                            OperationResult::Retry(OverseerError::SetNewKey(error_message))
                        }
                    }
                },
            );

            if result.is_ok() {
                return Ok(i);
            }
        }

        Err(OverseerError::SetNewKey(
            "New keys were not successfully set on any of the idle nodes.".to_string(),
        ))
    }

    /// Tries to activate a node. The node is assumed to be idle.
    fn activate_a_node(&self, activated_node_index: usize) -> Result<(), OverseerError> {
        let result = retry_with_index(
            Fixed::from_millis(200).take(Self::NUMBER_OF_TRIES),
            |current_try| {
                match self.ingest_clients[activated_node_index].activate() {
                    Ok(_) => {
                        log::info!(
                            self.logger,
                            "Node at index {} successfully activated.",
                            activated_node_index
                        );
                        OperationResult::Ok(())
                    }
                    // TODO: Alert Ops to take manual action at this point.
                    Err(err) => {
                        let number_of_remaining_tries = Self::NUMBER_OF_TRIES - current_try as usize;
                        let error_message = match number_of_remaining_tries {
                            0 => format!(
                                "Did not succeed in setting a new key on node at index {}. Underlying error: {}",
                                activated_node_index,
                                err
                            ),
                            _ => format!(
                                "Node at index {} not activated. Will try {} more times. Underlying error: {}",
                                activated_node_index, number_of_remaining_tries, err
                            ),
                        };
                        OperationResult::Retry(OverseerError::ActivateNode(error_message))
                    }
                }
            },
        );

        Ok(result?)
    }
}
