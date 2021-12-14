// Copyright (c) 2018-2021 The MobileCoin Foundation

use crate::error::OverseerError;

use grpcio;
use mc_api::external;
use mc_common::logger::{log, Logger};
use mc_crypto_keys::CompressedRistrettoPublic;
use mc_fog_api::ingest_common::{IngestControllerMode, IngestSummary};
use mc_fog_ingest_client::FogIngestGrpcClient;
use mc_fog_recovery_db_iface::{IngressPublicKeyRecord, IngressPublicKeyRecordFilters, RecoveryDb};
use mc_fog_uri::FogIngestUri;
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

// Wraps a thread that is responsible for overseeing the active Fog Ingest
// cluster. The worker is checking to see that there's always one active
// ingress key. If there is no active key, then it promotes an idle node to
// active, and in the case where none of the idle nodes contain the previously
// active ingress key it reports that key as lost.
pub struct OverseerWorker {
    /// Join handle used to wait for the thread to terminate.
    join_handle: Option<JoinHandle<()>>,

    /// Stop request trigger, used to signal the thread to stop.
    stop_requested: Arc<AtomicBool>,
}

impl OverseerWorker {
    /// Retry failed GRPC requests every 10 seconds.
    const GRPC_RETRY_SECONDS: Duration = Duration::from_millis(10000);

    pub fn new<DB: RecoveryDb + Clone + Send + Sync + 'static>(
        ingest_cluster_uris: Vec<FogIngestUri>,
        recovery_db: DB,
        logger: Logger,
        stop_requested: Arc<AtomicBool>,
    ) -> Self
    where
        OverseerError: From<DB::Error>,
    {
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
                .name("OverseerWorker".to_owned())
                .spawn(move || {
                    OverseerWorkerThread::start(
                        ingest_clients,
                        recovery_db,
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
    /// Each ingest client talks to a specific Fog Ingest node.
    ingest_clients: Vec<FogIngestGrpcClient>,

    recovery_db: DB,

    stop_requested: Arc<AtomicBool>,

    logger: Logger,
}

/// This associates an IngestSummary with an IngestClient. This makes it easy
/// to query a given node based on it's IngestSummary.
struct IngestSummaryNodeMapping {
    node_index: usize,

    ingest_summary: IngestSummary,
}

impl<DB: RecoveryDb> OverseerWorkerThread<DB>
where
    OverseerError: From<DB::Error>,
{
    /// Poll the Fog Ingest cluter every 5 seconds.
    const POLLING_FREQUENCY: Duration = Duration::from_secs(5);

    /// Try a request to Fog Ingest node this many times if you encounter an
    /// error.
    const NUMBER_OF_RETRIES: u8 = 3;

    pub fn start(
        ingest_clients: Vec<FogIngestGrpcClient>,
        recovery_db: DB,
        stop_requested: Arc<AtomicBool>,
        logger: Logger,
    ) {
        let thread = Self {
            ingest_clients,
            recovery_db,
            stop_requested,
            logger,
        };
        thread.run();
    }

    fn run(self) {
        while !self.stop_requested.load(Ordering::SeqCst) {
            log::info!(self.logger, "Overser worker start of thread.");
            std::thread::sleep(Self::POLLING_FREQUENCY);

            let ingest_summary_node_mappings: Vec<IngestSummaryNodeMapping> =
                self.retrieve_ingest_summary_node_mappings();
            let active_ingest_summary_node_mappings: Vec<&IngestSummaryNodeMapping> =
                ingest_summary_node_mappings
                    .iter()
                    .filter(|ingest_summary_node_mapping| {
                        ingest_summary_node_mapping.ingest_summary.mode
                            == IngestControllerMode::Active
                    })
                    .collect();

            // TODO: Send these somewhere like Prometheus... ?

            let active_node_count = active_ingest_summary_node_mappings.len();
            if active_node_count == 1 {
                log::trace!(
                    self.logger,
                    "There is one active node in the Fog Ingest cluster. Active ingress key: {:?}",
                    active_ingest_summary_node_mappings[0]
                        .ingest_summary
                        .get_ingress_pubkey()
                );
                continue;
            } else if active_node_count > 1 {
                let active_node_ingress_pubkeys: Vec<&external::CompressedRistretto> =
                    active_ingest_summary_node_mappings
                        .iter()
                        .map(|active_ingest_summary_node_mapping| {
                            active_ingest_summary_node_mapping
                                .ingest_summary
                                .get_ingress_pubkey()
                        })
                        .collect();
                log::warn!(
                    self.logger,
                    "There are multiple active nodes in the Fog Ingest cluster. Active ingress keys: {:?}",
                    active_node_ingress_pubkeys
                );
                // TODO: Signal to ops that two keys are active at once. This is
                // unexpected.
            } else {
                log::error!(
                    self.logger,
                    "There are currently no active nodes in the Fog Ingest cluster. Initiating automatic failover.",
                );
                match self.perform_automatic_failover(ingest_summary_node_mappings) {
                    Ok(_) => {
                        log::info!(self.logger, "Automatic failover completed successfully.")
                    }
                    Err(err) => log::error!(self.logger, "Automatic failover failed: {:?}", err),
                };
            }
        }
    }

    /// Returns the latest round of ingest summaries for each
    /// FogIngestGrpcClient that communicates with a node that is online.
    fn retrieve_ingest_summary_node_mappings(&self) -> Vec<IngestSummaryNodeMapping> {
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
                Err(_) => {
                    log::warn!(
                        self.logger,
                        "Unable to retrieve ingest summary for node: {}",
                        ingest_client.get_uri()
                    );
                }
            }
        }

        ingest_summary_node_mappings
    }

    /// Performs automatic failover, which means that we try to activate nodes
    /// for an outstanding ingress key, if it exists.
    ///
    /// The logic is as follows:
    ///   1. Find all of the "outstanding keys" as determined by the RecoveryDb.
    ///      These are ingress keys that Fog Ingest needs scan blocks with
    ///      (and the issue is that Fog Ingest isn't currently doing that
    ///      because all nodes are idle).
    ///   2. If there are:
    ///         a) 0 outstanding keys:
    ///              No node will be activated. We now have to:
    ///                 (i)  Set new keys on an idle node.
    ///                 (ii) Activate that node.
    ///         b) 1 oustanding key:
    ///              Try to find an idle node that contains that key.
    ///                 (i)  If you find one, great! Just activate that node. If
    ///                      activation is unsuccessful, then return an error
    ///                      and return to the overseer polling logic.
    ///                 (ii) If you don't find an idle node with that key,
    ///                      then you have to report that key as lost.
    ///        c) > 1 outstanding key:
    ///             Disarm and send an alert (todo).
    fn perform_automatic_failover(
        &self,
        ingest_summary_node_mappings: Vec<IngestSummaryNodeMapping>,
    ) -> Result<(), OverseerError> {
        let inactive_outstanding_keys: Vec<CompressedRistrettoPublic> =
            self.get_inactive_outstanding_keys()?;

        match inactive_outstanding_keys.len() {
            0 => log::info!(self.logger, "Found 0 outstanding keys."),
            1 => log::info!(self.logger, "Found 1 outstanding key."),
            _ => {
                log::error!(self.logger, "Found multiple outstanding keys. This requires manual intervention. Disarming.");
                self.stop_requested.store(true, Ordering::SeqCst);
                return Err(OverseerError::MultipleOutstandingKeys("Multiple outstanding keys found. This is unexpected and requires manual intervention. As such, we've disarmed overseer. Take action and then rearm.".to_string()));
            }
        }

        if let Some(inactive_outstanding_key) = inactive_outstanding_keys.get(0) {
            match self.try_to_activate_node_for_inactive_outstanding_key(
                &inactive_outstanding_key,
                &ingest_summary_node_mappings,
            ) {
                Ok(_) => {
                    log::info!(
                        self.logger,
                        "A node was activated, so there is no need to report the key as lost."
                    );
                    return Ok(());
                }
                Err(err) => log::error!(
                    self.logger,
                    "There was an issue activating a node for the outstanding key: {:?}",
                    err
                ),
            }
        }

        // If there's an outstanding key, we need to report it as lost.
        if let Some(inactive_outstanding_key) = inactive_outstanding_keys.get(0) {
            self.report_lost_ingress_key(*inactive_outstanding_key)?;
        }

        // Regardless of whether or not there's an outstanding key, we need
        // to set new keys on a node and then activate it.
        let activated_node_index = self.set_new_key_on_a_node()?;
        self.activate_a_node(activated_node_index)?;

        Ok(())
    }

    fn get_inactive_outstanding_keys(
        &self,
    ) -> Result<Vec<CompressedRistrettoPublic>, OverseerError> {
        // An outanding key is one that Fog Ingest is still obligated to be
        // scanning blocks with on behalf of users.
        let outstanding_keys_filters = IngressPublicKeyRecordFilters {
            // A lost key is not outstanding because it will never again be used
            // to scan blocks.
            should_include_lost_keys: false,
            // A retired key can be outstanding if public expiry is greater than
            // its last scanned block.
            should_include_retired_keys: true,
            // If a key has expired- i.e. its last scanned block is greater
            // than or equal to its public expiry- then it will no longer scan
            // blocks. Therefore, we need to include unexpired keys because they
            // are still supposed to be scanned by Fog.
            should_only_include_unexpired_keys: true,
        };

        // First, find the "inactive_outstanding_keys" which are outstanding keys
        // that we've grabbed from the RecoveryDb.
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

    /// Tries to activate a node with the given inactive outstanding key.
    ///
    /// returns true if a node was successfully activated.
    fn try_to_activate_node_for_inactive_outstanding_key(
        &self,
        inactive_outstanding_key: &CompressedRistrettoPublic,
        ingest_summary_node_mappings: &Vec<IngestSummaryNodeMapping>,
    ) -> Result<(), OverseerError> {
        log::debug!(
            self.logger,
            "Trying to activate an idle node with inactive outstanding key: {:?}",
            &inactive_outstanding_key
        );
        for ingest_summary_node_mapping in ingest_summary_node_mappings {
            let node_ingress_key = match CompressedRistrettoPublic::try_from(
                ingest_summary_node_mapping
                    .ingest_summary
                    .get_ingress_pubkey(),
            ) {
                Ok(key) => key,
                Err(_) => continue,
            };
            if inactive_outstanding_key.eq(&node_ingress_key) {
                // We have to keep trying to activate this node with the
                // matching ingress key until it becomes active.
                //
                // This prevents the secenario in which the active node is
                // bounced, and then we end up here and we're trying to
                // activate an idle node. If we give up after a few
                // unsuccessful tries, then we'd report the previously
                // active key as lost. But then the previously active server
                // could be restarted by Kubernetes, have this lost key, and
                // restart in the active state. This would be bad because
                // we don't want a server to be active with a lost key.
                //
                // Since we always expect the node to come back in some
                // time, we should just keep trying here.
                //
                // TODO: Add alerting if this is taking too long.
                loop {
                    log::info!(
                        self.logger,
                        "Trying to activate node at index {}",
                        ingest_summary_node_mapping.node_index
                    );
                    match self.ingest_clients[ingest_summary_node_mapping.node_index].activate() {
                        Ok(_) => {
                            log::info!(self.logger, "Successfully activated ingest client.");
                            return Ok(());
                        }
                        Err(_) => {
                            // TODO: See if we can make an id field for ingest client. This
                            // will allow us to better identify ingest clients.
                            log::warn!(self.logger, "Could not activate idle ingest client.");
                        }
                    }
                }
            }
        }

        return Err(OverseerError::ActivateNode("Could not activate a node because no node has an ingress key that matches the outstanding key.".to_string()));
    }

    fn report_lost_ingress_key(
        &self,
        inactive_outstanding_key: CompressedRistrettoPublic,
    ) -> Result<(), OverseerError> {
        for try_count in 0..Self::NUMBER_OF_RETRIES {
            match self
                .recovery_db
                .report_lost_ingress_key(inactive_outstanding_key)
            {
                Ok(_) => {
                    log::info!(
                        self.logger,
                        "The following key  was successfully reported as lost: {}",
                        inactive_outstanding_key
                    );
                    OperationResult::Ok(success_message)
                }
                Err(_) => {
                    let number_of_remaining_tries = Self::NUMBER_OF_RETRIES - try_count - 1;
                    log::info!(self.logger, "The following key  was not successfully reported as lost: {}. Will try {} more times", inactive_outstanding_key, number_of_remaining_tries);
                }
            }
        }

        // TODO: Add alerting that says we need to manually report these keys
        // as lost.
        Err(OverseerError::ReportLostKey(format!(
            "Could not successfully report this key {:?} as lost",
            inactive_outstanding_key
        )))
    }

    fn set_new_key_on_a_node(&self) -> Result<usize, OverseerError> {
        for (i, ingest_client) in self.ingest_clients.iter().enumerate() {
            for try_count in 0..Self::NUMBER_OF_RETRIES {
                match ingest_client.new_keys() {
                    Ok(_) => {
                        log::info!(
                            self.logger,
                            "New keys successfully set on the ingest node at index {}.",
                            i
                        );
                        return Ok(i);
                    }
                    // TODO: We'll need to alert Ops to take manual action at this point.
                    Err(_) => {
                        let number_of_remaining_tries = Self::NUMBER_OF_RETRIES - try_count - 1;
                        log::error!(self.logger, "New keys were not successfully set on the ingest node at index {}. Will try {} more times.", i, number_of_remaining_tries);
                    }
                }
            }
        }

        Err(OverseerError::SetNewKey(
            "Could not successfully set a new key on any ingest node.".to_string(),
        ))
    }

    fn activate_a_node(&self, activated_node_index: usize) -> Result<(), OverseerError> {
        for try_count in 0..Self::NUMBER_OF_RETRIES {
            match self.ingest_clients[activated_node_index].activate() {
                Ok(_) => {
                    log::info!(
                        self.logger,
                        "Node at index {} successfully activated.",
                        activated_node_index
                    );
                    return Ok(());
                }
                // TODO: Alert Ops to take manual action at this point.
                Err(_) => {
                    let number_of_remaining_tries = Self::NUMBER_OF_RETRIES - try_count - 1;
                    log::error!(
                        self.logger,
                        "Node at index {} not activated. Will try {} more times.",
                        activated_node_index,
                        number_of_remaining_tries
                    );
                }
            }
        }
        // TODO: Add alerting that says we need to manually activate this
        // node.
        //
        Err(OverseerError::ActivateNode(
            "Could not activate any nodes.".to_string(),
        ))
    }
}
