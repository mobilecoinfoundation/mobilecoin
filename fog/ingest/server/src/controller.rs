// Copyright (c) 2018-2021 The MobileCoin Foundation

use crate::{
    connection::PeerConnection,
    connection_error::Error as ConnectionError,
    connection_traits::IngestConnection,
    controller_state::{IngestControllerState, StateChangeError},
    counters,
    error::{IngestServiceError as Error, PeerBackupError, RestoreStateError, SetPeersError},
    server::IngestServerConfig,
    SeqDisplay,
};
use mc_attest_enclave_api::{EnclaveMessage, PeerAuthRequest, PeerAuthResponse, PeerSession};
use mc_attest_net::RaClient;
use mc_common::{
    logger::{log, Logger},
    ResponderId,
};
use mc_connection::Connection;
use mc_crypto_keys::{CompressedRistrettoPublic, RistrettoPublic};
use mc_fog_api::{
    ingest_common::{IngestControllerMode, IngestStateFile, IngestSummary},
    report_parse::try_extract_unvalidated_ingress_pubkey_from_fog_report,
};
use mc_fog_ingest_enclave::{Error as EnclaveError, IngestEnclave, IngestSgxEnclave};
use mc_fog_recovery_db_iface::{IngressPublicKeyStatus, RecoveryDb, ReportData, ReportDb};
use mc_fog_types::{common::BlockRange, ingest::TxsForIngest};
use mc_fog_uri::IngestPeerUri;
use mc_sgx_report_cache_api::ReportableEnclave;
use mc_sgx_report_cache_untrusted::{Error as ReportCacheError, ReportCache};
use mc_transaction_core::{Block, BlockContents, BlockIndex};
use mc_util_uri::ConnectionUri;
use std::{
    collections::{BTreeMap, BTreeSet},
    convert::TryFrom,
    io::ErrorKind,
    sync::{Arc, Mutex, MutexGuard},
};

/// The ingest controller sits under the grpc / networking layer, and implements
/// functions corresponding to high-level actions like "process_next_block,
/// rotate_keys". The name "controller" is suggested by GRASP guidelines:
/// https://en.wikipedia.org/wiki/GRASP_(object-oriented_design)
///
/// The ingest controller API is thread-safe and an Arc to this can be shared
/// with GRPC services. There is also an ingest worker, which periodically calls
/// "process_next_block". There should only be one thread doing that.
///
/// In consensus service, there is a roughly analogous object ByzantineLedger,
/// which also has a worker thread, and owns its worker thread. In this case, we
/// can't quite do that because the worker thread would need a shared reference
/// to the controller, but the controller cannot obtain `Arc<Self>` in order to
/// construct the worker (AFAIK).
///
/// So the idea here is instead that the IngestController owns no threads, the
/// IngestWorker is external to it, and all the grpcio threads are also external
/// to it, and talk to Arc<IngestController> to accomplish their tasks.
pub struct IngestController<
    R: RaClient + Send + Sync + 'static,
    DB: RecoveryDb + ReportDb + Clone + Send + Sync + 'static,
> where
    Error: From<<DB as RecoveryDb>::Error>,
{
    /// The config object for the server
    config: IngestServerConfig,
    /// State controlling the operation of the server
    controller_state: Arc<Mutex<IngestControllerState>>,
    /// The enclave supporting the server's operation
    enclave: IngestSgxEnclave,
    /// The recovery db that we write rng records and txout records to
    recovery_db: DB,
    /// The cache for reports from this enclave
    report_cache: Arc<Mutex<ReportCache<IngestSgxEnclave, R>>>,
    /// grpc environment (thread pool) for grpc connections to our peers
    /// Note: we only make synchronous grpc calls in igp connection object,
    /// and this env isn't used to recieve any connections,
    /// so I believe we don't actually use any of these threads.
    grpc_env: Arc<grpcio::Environment>,
    /// The last sealed key. We don't bother asking the enclave for the sealed
    /// key again unless the private key changes.
    last_sealed_key: Arc<Mutex<Option<(Vec<u8>, CompressedRistrettoPublic)>>>,
    /// Logger object
    logger: Logger,
}

impl<
        R: RaClient + Send + Sync + 'static,
        DB: RecoveryDb + ReportDb + Clone + Send + Sync + 'static,
    > IngestController<R, DB>
where
    Error: From<<DB as RecoveryDb>::Error>,
{
    /// Create a new ingest controller
    pub fn new(config: IngestServerConfig, ra_client: R, recovery_db: DB, logger: Logger) -> Self {
        let controller_state = Arc::new(Mutex::new(IngestControllerState::new(
            &config,
            logger.clone(),
        )));

        // Load the statefile if there is one:
        let state_file_data: Option<IngestStateFile> =
            config.state_file.as_ref().and_then(|file| {
                match file.read() {
                    Ok(state_data) => Some(state_data),
                    Err(io_error) => {
                        match io_error.kind() {
                            ErrorKind::NotFound => {
                                log::info!(logger, "State file {:?} did not exist", file);
                                None
                            }
                            _ => {
                                // TODO: Should we delete the file, to avoid a crash loop?
                                // We could move it to a backup location or something, like, `.1`,
                                // `.2`, etc. up to some maximum.
                                panic!("Could not read state file ({:?}): {}", file, io_error);
                            }
                        }
                    }
                }
            });

        let cached_key: Option<Vec<u8>> = state_file_data
            .as_ref()
            .map(|x| x.sealed_ingress_key.clone());

        // Initialize the enclave
        let enclave = IngestSgxEnclave::new(
            config.enclave_path.clone(),
            &config.local_node_id,
            &cached_key,
            config.omap_capacity,
        );

        // Initialize report cache
        let report_cache = Arc::new(Mutex::new(ReportCache::new(
            enclave.clone(),
            ra_client,
            config.ias_spid,
            &counters::ENCLAVE_REPORT_TIMESTAMP,
            logger.clone(),
        )));

        // Build grpc env for initiating peer connections
        let grpc_env = Arc::new(
            grpcio::EnvBuilder::new()
                .name_prefix("Ingest-Peer-Clients".to_string())
                .build(),
        );

        // Make controller object
        let result = Self {
            config: config.clone(),
            controller_state,
            enclave,
            recovery_db,
            report_cache,
            grpc_env,
            last_sealed_key: Arc::new(Mutex::new(None)),
            logger,
        };

        // Attempt to restore state from state file if provided
        // NotFound is not an error, but otherwise it is an error.
        if let Some(ref file_data) = state_file_data {
            let summary = file_data.get_summary();
            result
                .restore_state_from_summary(summary)
                .unwrap_or_else(|err| {
                    panic!(
                        "Could not restore state from state file ({:?}), {:?}: {}",
                        config.state_file, summary, err
                    )
                });
        }

        result.write_state_file();

        log::info!(
            result.logger,
            "Ingest Controller starting in state: {}",
            result.get_state()
        );

        result
    }

    /// Forward peer_accept function from ingest enclave api
    pub fn peer_accept(
        &self,
        req: PeerAuthRequest,
    ) -> Result<(PeerAuthResponse, PeerSession), EnclaveError> {
        self.enclave.peer_accept(req)
    }

    /// Forward get_ingress_private_key function from ingest enclave api
    pub fn get_ingress_private_key(
        &self,
        session: PeerSession,
    ) -> Result<(EnclaveMessage<PeerSession>, CompressedRistrettoPublic), EnclaveError> {
        self.enclave.get_ingress_private_key(session)
    }

    /// Forward set_ingress_private_key from ingest enclave api,
    /// but with checks for idle state, and updates to sealed backups
    pub fn set_ingress_private_key(&self, msg: EnclaveMessage<PeerSession>) -> Result<(), Error> {
        // Lock our state for this entire call
        let mut state = self.get_state();
        if !state.is_idle() {
            return Err(Error::ServerNotIdle);
        }

        // TODO: We could make enclave.set_ingress_private_key return a bool
        // which tells us if the key changed, and that would be simpler.
        // But it's an enclave upgrade if we do that, and we're developing this in
        // a patch release branch.
        let old_ingress_pubkey: CompressedRistrettoPublic = self
            .enclave
            .get_ingress_pubkey()
            .expect("Failed to get ingress pubkey")
            .into();

        self.enclave.set_ingress_private_key(msg)?;

        let new_ingress_pubkey: CompressedRistrettoPublic = self
            .enclave
            .get_ingress_pubkey()
            .expect("Failed to get ingress pubkey")
            .into();

        if old_ingress_pubkey != new_ingress_pubkey {
            // Seal the new private keys we ended up with to disk
            *self.last_sealed_key.lock().unwrap() = None;
            self.write_state_file_inner(&mut state);

            // Don't hold the lock while we make network calls to IAS
            drop(state);

            // Refresh report cache
            log::debug!(
                self.logger,
                "Refreshing enclave report cache after private key change"
            );
            if let Err(err) = self.update_enclave_report_cache() {
                log::error!(
                    self.logger,
                    "Failed to update enclave report cache after changing ingress private key: {}",
                    err
                );
            }
        }

        Ok(())
    }

    /// Make completely new keys in the enclave, wiping out all previous ingress
    /// and egress private keys. This is similar to reinitializing the
    /// enclave. This also frees the ingest invocation id if any.
    /// This also updates the state file, and the sealed key file.
    ///
    /// This is only possible if the server is idling
    pub fn new_keys(&self) -> Result<IngestSummary, Error> {
        let mut state = self.get_state();
        self.new_keys_inner(&mut state)?;
        Ok(self.get_ingest_summary_inner(&mut state))
    }

    // Does work of new_keys but takes MutexGuard for controller_state as argument
    fn new_keys_inner(&self, state: &mut MutexGuard<IngestControllerState>) -> Result<(), Error> {
        if !state.is_idle() {
            return Err(Error::ServerNotIdle);
        }

        // Retire our ingest invocation
        self.decommission_ingest_invocation_id(state);

        // Change the keys
        self.enclave.new_keys()?;

        // Write sealed key file
        *self.last_sealed_key.lock().unwrap() = None;
        self.write_state_file_inner(state);

        // Update report cache (since ingress key changed)
        log::debug!(
            self.logger,
            "Refreshing enclave report cache after new private key"
        );
        if let Err(err) = self.update_enclave_report_cache() {
            log::error!(
                self.logger,
                "Failed to update enclave report cache after choosing new keys: {}",
                err
            );
        }

        Ok(())
    }

    // Similar to new_keys_inner, but only wipes out the egress key and rng states,
    // not the ingress key.
    fn new_egress_key(&self, state: &mut MutexGuard<IngestControllerState>) -> Result<(), Error> {
        if !state.is_idle() {
            return Err(Error::ServerNotIdle);
        }

        // Retire our ingest invocation
        self.decommission_ingest_invocation_id(state);

        // Change the egress key
        self.enclave.new_egress_key()?;

        // Write sealed key file
        *self.last_sealed_key.lock().unwrap() = None;
        self.write_state_file_inner(state);

        Ok(())
    }

    // Helper which decommissions our ingest invocation id in the database and
    // updates our state
    fn decommission_ingest_invocation_id(&self, state: &mut MutexGuard<IngestControllerState>) {
        // Retire our ingest invocation
        if let Some(iid) = state.get_ingest_invocation_id() {
            if let Err(err) = self.recovery_db.decommission_ingest_invocation(&iid) {
                log::error!(
                    self.logger,
                    "Could not decommission our ingest invocation id, it will be leaked: {}",
                    err
                );
            }
            state.set_ingest_invocation_id(&None);
        }
    }

    /// Process the next block through ingest enclave, and write all resulting
    /// ETxOutRecord's to recovery db Then increment the next_block_index.
    ///
    /// Additionally, if we are active, try to publish a fog report.
    /// If we cannot, because the ingress key is retired and there is no more
    /// work to do with it, set ourselves to the idle state and early
    /// return.
    ///
    /// This function must maintain an invariant around the ingest invocation
    /// id:
    /// * The first time we publish data using an invocation id, the egress key
    ///   in the enclave must be fresh, so that all the RNGs will be at the
    ///   initial position, which is what clients expect.
    /// * If we have an invocation id before we enter this loop, we must
    ///   decommission it if we can't make progress, because if we run block
    ///   data through the enclave, but then don't manage to publish it to the
    ///   database, there will be gaps in the RNG sequences (some of the entries
    ///   won't make it to database), and the client's won't be able to perform
    ///   balance checks successfully then.
    pub fn process_next_block(
        &self,
        block: &Block,
        block_contents: &BlockContents,
        timestamp: u64,
    ) {
        let _process_next_block_timer = counters::PROCESS_NEXT_BLOCK_TIME.start_timer();

        let ingress_pubkey: CompressedRistrettoPublic = self
            .enclave
            .get_ingress_pubkey()
            .expect("Failed to get ingress pubkey")
            .into();

        let initial_kex_rng_pubkey = self
            .enclave
            .get_kex_rng_pubkey()
            .expect("Failed to get kex rng pubkey");

        // Scope for mutex: Get invocation id, confirm next_block_index
        let mut iid = {
            let mut state = self.get_state();
            assert_eq!(
                block.index,
                state.get_next_block_index(),
                "We were asked to process the wrong block"
            );

            log::debug!(
                self.logger,
                "Now ingesting block #{:?} (id = {:?})",
                block.index,
                block.id,
            );

            // Publish fresh report on every block, if we are in the active state.
            // This also returns an ingress key state which indicates if publishing was
            // successful, it may fail if the key is retired. Then we can check
            // if we are still needed to be active.
            if state.is_active() {
                log::trace!(self.logger, "publish report");
                match self.publish_report(&ingress_pubkey, &mut state) {
                    Ok(ingress_key_status) => {
                        // If our key is retired, and the index we want to scan is past expiry,
                        // early return. Note, we don't even NEED to scan
                        // when block.index == pubkey_expiry, because the
                        // semantic of pubkey expiry is that it bounds the tombstone block, and a
                        // transaction cannot land in its tombstone block.
                        // But scanning the tombstone block as well may help
                        // deal with off-by-one errors somewhere else, and doesn't really hurt.
                        if ingress_key_status.retired
                            && block.index > ingress_key_status.pubkey_expiry
                        {
                            log::warn!(self.logger, "When preparing to process block index {}, we discovered that our ingress key is expired: {:?}. Switching to idle and nuking keys.", block.index, ingress_key_status);
                            state.set_idle();
                            self.new_egress_key(&mut state)
                                .expect("Failure to rotate egress key can't be recovered from");
                            return;
                        }
                    }
                    Err(err) => {
                        // Failing to publish a report is not fatal, because we attempt to publish
                        // on every block, and even if it only succeeds half
                        // the time, it wont make much difference in the pubkey
                        // expiry window.
                        log::error!(
                            self.logger,
                            "Could not publish ingest report at block index {}: {}",
                            block.index,
                            err
                        );
                    }
                }
            }

            // FIXME FOG-390, this should be atomic with the add-block-data operation,
            // so that the invocation id is not created if we don't actually publish the
            // block data
            let mut iid = state.get_ingest_invocation_id();

            if iid.is_none() {
                log::debug!(self.logger, "Now creating ingest invocation id");
                iid = Some(
                    self.recovery_db
                        .new_ingest_invocation(
                            None,
                            &ingress_pubkey,
                            &initial_kex_rng_pubkey,
                            block.index,
                        )
                        .expect("Failed recording new ingest invocation and kex rng pubkey"),
                );
                state.set_ingest_invocation_id(&iid);
            }

            iid
        };

        // TxsForIngest expects global_txo_index to be the index of the first TxOut in
        // the block handed to it.
        assert!(block.cumulative_txo_count >= block_contents.outputs.len() as u64);
        let mut global_txo_index = block.cumulative_txo_count - block_contents.outputs.len() as u64;
        let initial_global_txo_index = global_txo_index;

        // tx_rows are records containing tx outs, encrypted for the users.
        // there is typically (and at most) one tx row per tx out that comes in.
        let mut tx_rows = Vec::with_capacity(block_contents.outputs.len());
        for chunk in block_contents.outputs.chunks(self.config.max_transactions) {
            log::trace!(self.logger, "Chunk of {}", chunk.len());

            let txs_chunk = TxsForIngest {
                block_index: block.index,
                global_txo_index,
                redacted_txs: chunk.to_vec(),
                timestamp,
            };

            log::trace!(self.logger, "into enclave");
            let ingest_txs_timer = counters::INGEST_TXS_TIME.start_timer();
            let (new_tx_rows, maybe_kex_rng_pubkey) = match self.enclave.ingest_txs(txs_chunk) {
                Ok(pair) => pair,
                Err(err) => {
                    log::error!(self.logger, "Failed ingesting txs: {}", err);
                    return;
                }
            };
            drop(ingest_txs_timer);
            log::trace!(self.logger, "out enclave");

            // Don't commit the results immediately, try to commit the whole
            // block transactionally
            tx_rows.extend(new_tx_rows);
            global_txo_index += chunk.len() as u64;

            // If the enclave emitted a new rng pubkey, we need to decommission
            // the old one and put the new one in the database.
            // This should happen only rarely, when ingest hashmap overflows
            // FIXME: FOG-390: We should queue these up and make these additions
            // atomic in the add-block-data operation, so that none of them happen,
            // and the clients never see them, unless we manage to publish a block
            if let Some(new_kex_rng_pubkey) = maybe_kex_rng_pubkey {
                let mut retry_seconds = 1;
                let new_iid = loop {
                    match self.recovery_db.new_ingest_invocation(
                        Some(iid.expect("no ingest_invocation_id")),
                        &ingress_pubkey,
                        &new_kex_rng_pubkey,
                        block.index,
                    ) {
                        Ok(new_iid) => {
                            break new_iid;
                        }
                        Err(err) => {
                            log::crit!(self.logger, "Could not rotate kex rng pubkey in recovery database! Retrying...: {}", err);
                            std::thread::sleep(std::time::Duration::from_secs(retry_seconds));
                            retry_seconds = std::cmp::min(retry_seconds + 1, 30);
                        }
                    };
                };
                iid = Some(new_iid);
                self.get_state().set_ingest_invocation_id(&iid);
            }

            log::debug!(
                self.logger,
                "Ingesting block #{:?}: {}/{} txs ingested",
                block.index,
                global_txo_index - initial_global_txo_index,
                block_contents.outputs.len()
            );
        }

        log::info!(self.logger, "add_block_data");

        // Commit all the new data to the database,
        // and set num_blocks_processed to block.index + 1
        //
        // Failure to commit the data is not recoverable without decommissioning our
        // ingest invocation, since there is no way to roll back the RNG's in
        // the enclave, and the users won't find their transactions if we skip
        // an RNG output. But decommissioning the ingest invocation is costly
        // and we don't want to do it if retries will work. As such, we try
        // indefinitely until we succeed with a linear backoff time capped at 30
        // seconds (chosen arbitrarily), or until we definitely fail (postgres
        // constraint violation). A constraint violation indicates that a
        // different ingest server with the same ingress public key
        // as this server has already published data for this block.
        let mut retry_seconds = 1;
        loop {
            let db_metrics_timer = counters::DB_ADD_BLOCK_DATA_TIME.start_timer();
            match self.recovery_db.add_block_data(
                // It's okay to .expect here since this code should not run if we did not get an
                // ingest invocation id.
                iid.as_ref().expect("no ingest invocation id"),
                &block,
                timestamp,
                &tx_rows,
            ) {
                Ok(add_blocks_result) => {
                    log::trace!(self.logger, "state update");
                    let mut state = self.get_state();

                    if add_blocks_result.block_already_scanned_with_this_key {
                        // We lost the race to publish this block
                        log::info!(self.logger, "Another active server did work for block {}, we should become idle and back off", block.index);
                        state.set_idle();
                        // we need to nuke our egress key state and reset all rng's, since we
                        // scanned something that didn't get published
                        // new_egress_key also makes sure our rng is decommissioned
                        self.new_egress_key(&mut state).expect("Failure to rotate egress key after we can't publish data isn't recoverable, the RNGs would have gaps that the clients can't deal with");
                    } else {
                        // We won the race to publish this block
                        log::info!(
                            self.logger,
                            "Succeeded writing block {} to the database, invocation id {:?} ingress key {:?}",
                            block.index,
                            iid,
                            ingress_pubkey
                        );
                        log::trace!(self.logger, "increment_next_block_index");
                        state.increment_next_block_index();
                    }

                    log::debug!(self.logger, "Controller state: {}", state);
                    break;
                }
                Err(err) => {
                    log::crit!(self.logger, "add_block_data failed while attempting to add {} rows for block #{}: {}. Retrying in {} seconds", tx_rows.len(), block.index, err, retry_seconds);
                    std::thread::sleep(std::time::Duration::from_secs(retry_seconds));
                    retry_seconds = std::cmp::min(retry_seconds + 1, 30);
                    let _ = db_metrics_timer.stop_and_discard();
                }
            }
        }

        log::info!(&self.logger, "Finished ingesting block #{:?}", block.index);
        counters::LAST_PROCESSED_BLOCK_INDEX.set(block.index as i64);
        counters::BLOCKS_PROCESSED_COUNT.inc();

        self.write_state_file();
    }

    /// Attempt to put this server safely in the active mode
    ///
    /// - Check peers, if any is active or retiring, abort
    /// - If any peer doesn't have our ingress keys, send it our ingress keys
    /// - If any peer doesn't have our peers, set its peers
    /// - Check database if any blocks have been scanned using this ingress
    ///   pubkey, if so start after them.
    /// - Determine an appropriate start block to start scanning. If key already
    ///   exists, do last-scanned-block + 1. If not, start at the latest known
    ///   value of num_blocks.
    /// - Enter the active state
    ///
    /// Arguments:
    /// * ledger_num_blocks: The latest known value of ledger_db.num_blocks()
    ///
    /// Returns:
    /// * A status report of the ingest server after this operation, or an error
    pub fn activate(&self, ledger_num_blocks: u64) -> Result<IngestSummary, Error> {
        log::info!(self.logger, "activate");
        let mut state = self.get_state();
        if state.is_active() {
            log::info!(self.logger, "We are already active! Early return");
            return Ok(self.get_ingest_summary_inner(&mut state));
        }

        // A valid report cache is required to initiate an outgoing attested connection.
        // Activating doesn't happen very often so this should be okay.
        log::debug!(self.logger, "Refreshing enclave report cache on activate");
        self.update_enclave_report_cache()?;

        let peers = state.get_peers();

        // Open connections to all peers
        let mut peer_connections: Vec<_> = peers
            .iter()
            .filter_map(|peer| {
                if peer
                    .responder_id()
                    .expect("Could not get responder id from peer URI")
                    == self.config.local_node_id
                {
                    None
                } else {
                    log::info!(self.logger, "activate: connect to peer {}", peer);
                    Some(PeerConnection::<IngestSgxEnclave>::new(
                        self.enclave.clone(),
                        self.config.local_node_id.clone(),
                        peer.clone(),
                        self.grpc_env.clone(),
                        self.logger.clone(),
                    ))
                }
            })
            .collect();

        // First, check that no other servers are active before doing anything.
        let mut summaries = Vec::new();
        for conn in peer_connections.iter_mut() {
            match conn.get_status() {
                Ok(summary) => {
                    match summary.mode {
                        IngestControllerMode::Active => {
                            let uri = conn.uri();
                            log::error!(
                                self.logger,
                                "Could not activate: peer {} is already active",
                                uri
                            );
                            return Err(PeerBackupError::AnotherActivePeer(uri).into());
                        }
                        IngestControllerMode::Idle => {}
                    };
                    summaries.push(summary);
                }
                Err(err) => {
                    log::error!(
                        self.logger,
                        "Could not activate: peer {} was unreachable: {}",
                        conn.uri(),
                        err
                    );
                    return Err(PeerBackupError::from(err).into());
                }
            }
        }

        // Now, check if any backups need their keys or peer list updated.
        let our_pubkey = CompressedRistrettoPublic::from(
            &self
                .enclave
                .get_ingress_pubkey()
                .expect("Could not get pubkey from our enclave"),
        );
        for (conn, summary) in peer_connections.iter_mut().zip(summaries.iter()) {
            log::info!(self.logger, "activate: check on peer {}", conn.uri());
            // Allow updates to our peers but don't log if they don't match initially
            self.confirm_backup(
                conn,
                Some(summary),
                Some(&our_pubkey),
                Some(&peers),
                true,
                false,
            )?;
        }

        // At this point all peers are configured correctly as backups
        // We need to figure out what the start block should be
        let start_block =
            if let Some(status) = self.recovery_db.get_ingress_key_status(&our_pubkey)? {
                log::info!(
                    self.logger,
                    "When activating, our key already existed: {:?}",
                    status
                );
                // If this key already exists, get the block that was last scanned with it and
                // add one. If no block was scanned with it yet, start scanning
                // whereever it was supposed to start
                self.recovery_db
                    .get_last_scanned_block_index(&our_pubkey)?
                    .map(|val| val + 1)
                    .unwrap_or(status.start_block)
            } else {
                log::info!(self.logger, "When activating, we seem to have a new key");
                // This key doesn't exist yet, so we want to start at the "latest" known block.
                // We take the max of what the caller passed us, which is
                // ledger_db.num_blocks(), and whatever is in recovery_db, in
                // case our ledger_db is behind Note: we add one to recovery_db
                // result because that is an index, but num_blocks is a block_count
                let start_block = core::cmp::max(
                    ledger_num_blocks,
                    self.recovery_db
                        .get_highest_known_block_index()?
                        .map(|x| x + 1)
                        .unwrap_or(0),
                );
                if !self.recovery_db.new_ingress_key(&our_pubkey, start_block)? {
                    return Err(PeerBackupError::CreatingNewIngressKey.into());
                };

                start_block
            };
        // This unwrap is okay because we are idle right now.
        state
            .set_next_block_index(start_block)
            .expect("state change error is not expected");

        // Publish a report, to ensure that a report is available even if
        // no blocks come after we activate. This is needed because in some tests,
        // the only transactions sent are fog transactions, so there can't be
        // a block unless this key is published before the next block comes.
        let key_status = self.publish_report(&our_pubkey, &mut state)?;

        // If our key is retired, and the index we want to scan is past expiry, early
        // return. Note, we don't even NEED to scan when block.index ==
        // pubkey_expiry, because the semantic of pubkey expiry is that it
        // bounds the tombstone block, and a transaction cannot land in its
        // tombstone block. But scanning the tombstone block as well
        // may help deal with off-by-one errors somewhere else, and doesn't really hurt.
        if key_status.retired && start_block > key_status.pubkey_expiry {
            log::warn!(self.logger, "When activating, we found out our key has already been retired and there is no remaining work to do. Activation is canceled: our start_block = {}, key_status = {:?}", start_block, key_status);
            return Err(Error::KeyAlreadyRetired(our_pubkey));
        }

        state.set_active();
        drop(state);
        log::info!(
            self.logger,
            "activate: success. start block is {}",
            start_block
        );
        self.write_state_file();
        Ok(self.get_ingest_summary())
    }

    /// Attempt to mark our ingress public key as retired in the database.
    /// This will eventually cause the whole cluster to become idle.
    pub fn retire(&self) -> Result<IngestSummary, Error> {
        log::info!(self.logger, "retire");

        let ingress_pubkey = CompressedRistrettoPublic::from(
            &self
                .enclave
                .get_ingress_pubkey()
                .expect("Failed to get ingress pubkey"),
        );
        self.recovery_db.retire_ingress_key(&ingress_pubkey, true)?;

        Ok(self.get_ingest_summary())
    }

    /// Attempt to mark our ingress public key as not retired in the database.
    /// The use case for this is:
    /// 1. We are trying to do ingest enclave upgrade
    /// 2. We retire the old cluster and activate the new cluster
    /// 3. Something goes wrong and the new cluster goes up in flames
    /// 4. We want to unretire the old cluster key so that the old cluster
    /// starts publishing fog reports    again and continues life as usual,
    /// and then continue debugging the new cluster and try again later.
    pub fn unretire(&self) -> Result<IngestSummary, Error> {
        log::info!(self.logger, "unretire");

        let ingress_pubkey = CompressedRistrettoPublic::from(
            &self
                .enclave
                .get_ingress_pubkey()
                .expect("Failed to get ingress pubkey"),
        );
        self.recovery_db
            .retire_ingress_key(&ingress_pubkey, false)?;

        Ok(self.get_ingest_summary())
    }

    /// Attempt to sync ingress keys from a remote server, which may be idle or
    /// active. We can only do this while we are idle.
    pub fn sync_keys_from_remote(&self, remote: &IngestPeerUri) -> Result<IngestSummary, Error> {
        // A valid report cache is required to initiate an outgoing attested connection.
        log::debug!(
            self.logger,
            "Refreshing enclave report cache before attesting to remote"
        );
        self.update_enclave_report_cache()?;

        // Lock the state for the duration of this call
        let mut state = self.get_state();
        if !state.is_idle() {
            return Err(Error::ServerNotIdle);
        }

        log::info!(self.logger, "Syncing from Remote URI: {}", remote);

        let mut connection = PeerConnection::<IngestSgxEnclave>::new(
            self.enclave.clone(),
            self.config.local_node_id.clone(),
            remote.clone(),
            self.grpc_env.clone(),
            self.logger.clone(),
        );

        log::info!(self.logger, "Asking remote for private key");
        let msg = connection.get_ingress_private_key()?;

        log::info!(self.logger, "Setting new private key on local enclave");
        let (pubkey, _) = self.enclave.set_ingress_private_key(msg.into())?;
        log::info!(self.logger, "Key successfully set in enclave: {}", pubkey);

        *self.last_sealed_key.lock().unwrap() = None;
        self.write_state_file_inner(&mut state);
        let result = self.get_ingest_summary_inner(&mut state);

        // Don't hold the state mutex while we are talking to IAS
        drop(state);

        // Update our report cache since we changed the private key
        log::debug!(
            self.logger,
            "Refreshing enclave report cache after remote private key fetch"
        );
        self.update_enclave_report_cache()?;

        Ok(result)
    }

    /// Set the pubkey expiry window
    pub fn set_pubkey_expiry_window(
        &self,
        new_pubkey_expiry_window: u64,
    ) -> Result<(), StateChangeError> {
        self.get_state()
            .set_pubkey_expiry_window(new_pubkey_expiry_window)
    }

    /// Set the list of peers
    ///
    /// * Arguments:
    /// - peers: A list of ingest peer uris
    ///
    /// * Returns:
    /// - An error if any of the peer uris doesn't have a valid responder id.
    pub fn set_peers(&self, peers: Vec<IngestPeerUri>) -> Result<(), SetPeersError> {
        self.set_peers_inner(peers, &mut self.get_state())
    }

    // Does work of set_peers but takes mutex guard for controller state as argument
    fn set_peers_inner(
        &self,
        peers: Vec<IngestPeerUri>,
        state: &mut MutexGuard<IngestControllerState>,
    ) -> Result<(), SetPeersError> {
        // Enforce the invariant that uris in peers list all have valid responder id
        let new_peers_by_responder_id = peers
            .iter()
            .map(
                |uri| -> Result<(ResponderId, IngestPeerUri), SetPeersError> {
                    Ok((uri.responder_id()?, uri.clone()))
                },
            )
            .collect::<Result<BTreeMap<ResponderId, IngestPeerUri>, SetPeersError>>()?;
        // Our own responder id should correspond to one of the peers
        if new_peers_by_responder_id
            .get(&self.config.local_node_id)
            .is_none()
        {
            return Err(SetPeersError::MissingOurResponderId(
                self.config.local_node_id.clone(),
                new_peers_by_responder_id,
            ));
        }
        let new_peers = new_peers_by_responder_id
            .values()
            .cloned()
            .collect::<BTreeSet<IngestPeerUri>>();
        state.set_peers(new_peers);
        Ok(())
    }

    /// Get the next block index, and whether we are idle, atomically together.
    ///
    /// This can be used by the worker thread to figure out if it should provide
    /// the next block and which block.
    pub fn get_next_block_index(&self) -> (BlockIndex, bool) {
        let state = self.get_state();
        (state.get_next_block_index(), state.is_idle())
    }

    /// Check if the controller is idle
    ///
    /// This thin pass-through exists to reduce the need for other components
    /// to talk directly to the controller state
    pub fn is_idle(&self) -> bool {
        self.get_state().is_idle()
    }

    /// Get the IngestSummary object
    pub fn get_ingest_summary(&self) -> IngestSummary {
        self.get_ingest_summary_inner(&mut self.get_state())
    }

    // Helper for get_ingest_summary that takes an existing lock on our state
    fn get_ingest_summary_inner(
        &self,
        state: &mut MutexGuard<IngestControllerState>,
    ) -> IngestSummary {
        let mut result = state.get_ingest_summary();
        let ingress_pubkey = CompressedRistrettoPublic::from(
            &self
                .enclave
                .get_ingress_pubkey()
                .expect("failed to get pubkey"),
        );
        let kex_rng_pubkey = self
            .enclave
            .get_kex_rng_pubkey()
            .expect("Failed to get kex rng pubkey");
        result.set_ingress_pubkey((&ingress_pubkey).into());
        result.set_egress_pubkey(kex_rng_pubkey.public_key);
        result.kex_rng_version = kex_rng_pubkey.version;
        result
    }

    /// Restore controller state from IngestSummary state data
    /// This may be done if a state file is found when starting the server
    ///
    /// Restoring into an active or retiring state is ONLY permitted if
    /// the ingress pubkey in the summary matches what's in our enclave,
    /// AND if no peers are active or retiring, AND the key is backed up
    ///
    /// Egress key can never be restored, it leads to replay attacks, and so the
    /// enclave forbids it Because of this, ingest invocation id can't be
    /// restored either.
    fn restore_state_from_summary(
        &self,
        state_data: &IngestSummary,
    ) -> Result<(), RestoreStateError> {
        let mut state = self.get_state();

        if !state.is_idle() {
            return Err(RestoreStateError::ServerNotIdle);
        }

        // Try to parse the peers list from the state_data
        let new_peers = state_data.get_sorted_peers()?;

        let ingress_pubkey = CompressedRistrettoPublic::from(&self.enclave.get_ingress_pubkey()?);
        if state_data.mode != IngestControllerMode::Idle {
            let state_data_ingress_pubkey =
                CompressedRistrettoPublic::try_from(state_data.get_ingress_pubkey())?;
            if state_data_ingress_pubkey != ingress_pubkey {
                return Err(RestoreStateError::IngressKeyMismatch(
                    ingress_pubkey,
                    state_data_ingress_pubkey,
                ));
            }

            // Check peers from STORED data to be in the correct backup state
            for peer_uri in new_peers.iter() {
                if peer_uri
                    .responder_id()
                    .map_err(|err| RestoreStateError::SetPeers(err.into()))?
                    == self.config.local_node_id
                {
                    continue;
                }

                let mut conn = PeerConnection::<IngestSgxEnclave>::new(
                    self.enclave.clone(),
                    self.config.local_node_id.clone(),
                    peer_uri.clone(),
                    self.grpc_env.clone(),
                    self.logger.clone(),
                );

                // Check that the peer from summary is configured from a backup as expected,
                // without logging or reconfiguring it if it isn't, we just give up.
                self.confirm_backup(
                    &mut conn,
                    None,
                    Some(&ingress_pubkey),
                    Some(&new_peers),
                    false,
                    false,
                )?;
            }
        }

        // Either we're restoring to idle state, or we're restoring to an active state
        // but all backups exist correctly, so we can make state changes now.
        self.set_peers_inner(new_peers.into_iter().collect(), &mut state)?;
        state
            .set_pubkey_expiry_window(state_data.pubkey_expiry_window)
            .expect("Modification should have been allowed, this is a logic error");
        state
            .set_next_block_index(state_data.next_block_index)
            .expect("Modification should have been allowed, this is a logic error");

        match state_data.mode {
            IngestControllerMode::Idle => {}
            IngestControllerMode::Active => {
                state.set_active();
            }
        };

        Ok(())
    }

    /// Record a lost ingress key into the database
    pub fn report_lost_ingress_key(
        &self,
        lost_ingress_key: CompressedRistrettoPublic,
    ) -> Result<(), <DB as RecoveryDb>::Error> {
        self.recovery_db.report_lost_ingress_key(lost_ingress_key)
    }

    /// Gets all the known missed block ranges.
    pub fn get_missed_block_ranges(&self) -> Result<Vec<BlockRange>, <DB as RecoveryDb>::Error> {
        self.recovery_db.get_missed_block_ranges()
    }

    /// Get the public key of the enclave
    ///
    /// This thin pass-through exists to reduce the need for other components
    /// to talk directly to the enclave
    pub fn get_enclave_pubkey(&self) -> Result<RistrettoPublic, EnclaveError> {
        self.enclave.get_ingress_pubkey()
    }

    // Helper which causes the enclave report cache to be updated
    // This is needed before attestation with a peer can occur
    pub fn update_enclave_report_cache(&self) -> Result<(), ReportCacheError> {
        self.report_cache
            .lock()
            .expect("mutex poisoned")
            .update_enclave_report_cache()?;
        Ok(())
    }

    // Helper which eases syntax around getting a lock on the state
    fn get_state(&self) -> MutexGuard<IngestControllerState> {
        self.controller_state.lock().expect("mutex poisoned")
    }

    // Helper which causes the enclave verification report to be published
    //
    // The pubkey_expiry will be computed as state.next_block_index +
    // state.pubkey_expiry_window
    //
    // Arguments:
    // * ingress_public_key: The key this report is attesting to the validity of
    // * state: A mutex guard locking this server's Ingest Controller State
    //
    // Returns:
    // * Err on a database or report-cache error
    // * Ok(status) If the database operation succeeded. If status.retired is false,
    //   we published a report, and possibly updated pubkey_expiry for this key If
    //   status.retired is true, we did NOT publish a report, In this case, the
    //   caller can inspect status.pubkey_expiry, which will not change anymore, to
    //   determine if there is still useful work to do with this ingress key.
    fn publish_report(
        &self,
        ingress_public_key: &CompressedRistrettoPublic,
        state: &mut MutexGuard<IngestControllerState>,
    ) -> Result<IngressPublicKeyStatus, Error> {
        // Get a report and check that it makes sense with what we think is happening
        let report = {
            let report = self.enclave.get_ias_report()?;
            // Check that key in report data matches ingress_public_key.
            // If not, then there is some kind of race.
            let found_key = try_extract_unvalidated_ingress_pubkey_from_fog_report(&report)?;
            if &found_key == ingress_public_key {
                report
            } else {
                // Hmm, let's try refreshing the enclave cache
                log::debug!(
                    self.logger,
                    "Refreshing enclave report cache after mismatch detected"
                );
                self.update_enclave_report_cache()?;

                let report = self.enclave.get_ias_report()?;
                let found_key = try_extract_unvalidated_ingress_pubkey_from_fog_report(&report)?;
                if &found_key == ingress_public_key {
                    report
                } else {
                    // This means that the caller is wrong about what the
                    // current ingress public key is, and we don't have anything we can publish.
                    //
                    // Note: If we publish a report containing a key that doesn't actually match
                    // what we are scanning for, that is likely catastrophic -- it's not clear that
                    // `report_lost_key` will work, because the key we thought we were scanning
                    // with, and recording in the database that we were scanning
                    // with, doesn't match what we actually scanned with. And if
                    // we don't know when that started happening, then it's not
                    // clear what range of blocks we need to tell the users to download.
                    //
                    // So if we can't fix the mismatch, then logging an error, refusing to publish
                    // report, and trying again later seems like the best
                    // approach. If this doesn't resolve itself, then eng needs
                    // to root-cause it, and ops likely should just, assume that this is
                    // some cache or something getting in a bad state, nuke the server and activate
                    // a backup that has the right key.
                    log::error!(self.logger, "Report doesn't contain the expected public key even after report refresh: {:?} != {:?}", found_key, ingress_public_key);
                    return Err(Error::PublishReport);
                }
            }
        };

        let report_data = ReportData {
            ingest_invocation_id: state.get_ingest_invocation_id(),
            report,
            pubkey_expiry: state.get_next_block_index() + state.get_pubkey_expiry_window(),
        };
        let report_id = self.config.fog_report_id.as_ref();

        self.recovery_db
            .set_report(ingress_public_key, report_id, &report_data)
            .map(|x| {
                counters::LAST_PUBLISHED_PUBKEY_EXPIRY.set(report_data.pubkey_expiry as i64);
                x
            })
            .map_err(|err| {
                log::error!(
                    self.logger,
                    "Could not publish report and check on ingress key status: {}",
                    err
                );
                // Note: At this revision, we don't have generic constraints for converting
                // ReportDB error to IngestServiceError but the caller won't do
                // much but log this error eventually so...
                Error::PublishReport
            })
    }

    // Helper which writes out the state file. This should be done after processing
    // a block, or when the state is actively changed.
    // This is a no-op if there is no state file configured.
    fn write_state_file(&self) {
        self.write_state_file_inner(&mut self.get_state())
    }

    // Helper for write_state_file which takes an already existing lock on the state
    // mutex
    fn write_state_file_inner(&self, state: &mut MutexGuard<IngestControllerState>) {
        // This ensures that if the server goes down, we know at what block it stopped
        // and we know where to start up if we start up again.
        if let Some(state_file) = self.config.state_file.as_ref() {
            let (summary, sealed_key) = loop {
                let summary = self.get_ingest_summary_inner(state);

                let ingress_pubkey =
                    CompressedRistrettoPublic::try_from(summary.get_ingress_pubkey())
                        .expect("could not interpret ingress pubkey");
                let mut last_sealed = self.last_sealed_key.lock().expect("mutex poisoned");

                {
                    let (bytes, pubkey) = last_sealed.get_or_insert_with(|| {
                        self.enclave
                            .get_sealed_ingress_private_key()
                            .expect("Could not get sealed private key from enclave")
                    });
                    if pubkey == &ingress_pubkey {
                        break (summary, bytes.clone());
                    }
                }

                // This may mean that summary is stale, so we should retry
                log::info!(self.logger, "sealed key didn't match summary we just computed, this is likely a race. retrying");
                *last_sealed = None;
            };

            let mut state_file_data = IngestStateFile::new();
            state_file_data.set_summary(summary);
            state_file_data.set_sealed_ingress_key(sealed_key);

            log::info!(self.logger, "Writing state file to {:?}", state_file_data);
            state_file
                .write(&state_file_data)
                .expect("Failed writing state file, this is fatal");
        }
    }

    // Helper which checks if we are active, then checks up on our peers, sending
    // them our data again if something is wrong and they are not acting
    // correctly as a backup. This is meant to be called periodically by a
    // background thread
    pub fn peer_checkup(&self) {
        mc_common::trace_time!(self.logger, "IngestController.peer_checkup");
        let peers = {
            let state = self.get_state();

            // If we are idle then we don't need to checkup on a peer
            if state.is_idle() {
                return;
            }

            state.get_peers()
        };

        // If there are no peers, then we don't need to checkup on them
        if peers.is_empty() {
            return;
        }

        for peer_uri in peers {
            // Our own uri is in the peers list, because that simplifies checking if peers
            // have matching lists. But we should skip when we reach ourself.
            match peer_uri.responder_id() {
                Err(err) => {
                    log::error!(
                        self.logger,
                        "Our peer uri: {} did not have a valid responder id: {}",
                        peer_uri,
                        err
                    );
                    continue;
                }
                Ok(responder_id) => {
                    if responder_id == self.config.local_node_id {
                        continue;
                    }
                }
            }

            log::debug!(self.logger, "Checking on peer: {}", peer_uri);
            // Build a peer connection
            let mut conn = PeerConnection::<IngestSgxEnclave>::new(
                self.enclave.clone(),
                self.config.local_node_id.clone(),
                peer_uri.clone(),
                self.grpc_env.clone(),
                self.logger.clone(),
            );

            // Confirm that the peer is backing us up correctly, and log if it isn't in that
            // state, since it is expected to be. This call will update the peer
            // if it is in the wrong state.
            match self.confirm_backup(&mut conn, None, None, None, true, true) {
                Ok(()) => {
                    log::debug!(self.logger, "Peer backup {} was confirmed", peer_uri);
                }
                Err(
                    err @ PeerBackupError::Connection(ConnectionError::UnexpectedKeyInEnclave(_)),
                ) => {
                    // This error is informational / debug and not warn
                    // because it may happen in a race when our server goes from retiring to idle in
                    // the other thread. Because, that thread wants to wipe out
                    // the old keys when they are no longer needed.
                    // The appropriate thing to do here is back off and wait for next cycle to
                    // attempt any more backups.
                    log::info!(self.logger, "Peer checkups stopped: Our key changed while checking up on peer backup: {}", err);
                    return;
                }
                Err(err) => {
                    log::warn!(
                        self.logger,
                        "Could not ensure backup with peer {}: {}",
                        peer_uri,
                        err
                    );
                }
            };
        }
    }

    /// Helper function which takes a connection to a peer which should be an
    /// idle backup, checks if this is the case, and if desired, updates the
    /// peer to make it correctly a backup.
    ///
    /// Arguments:
    /// - conn: The already-formed peer connection
    /// - cached_summary: A summary that we have earlier obtained from this
    ///   peer, if available
    /// - cached_our_pubkey: The earlier result of self.enclave.get_pubkey(), if
    ///   available
    /// - cached_our_peers: The earlier result of
    ///   self.controller_state.get_peers(), if available
    /// - update_if_wrong: Whether to update the peer's ingress keys or peer
    ///   list if it is wrong. If false we just return an error. If the peer is
    ///   not idle then we only return an error and don't attempt to update it.
    /// - log_if_wrong: Whether to log if the peer's ingress keys or peer list
    ///   is wrong. If it has not been configured as a backup yet, then it is
    ///   expected to be wrong before we update it, and then we shouldn't log.
    ///
    /// Returns:
    /// - Ok if the peer is idle and backing up our data correctly, or we
    ///   updated it to be in that state.
    /// - Err if the peer is not now a correctly configured backup.
    fn confirm_backup(
        &self,
        conn: &mut PeerConnection<IngestSgxEnclave>,
        cached_summary: Option<&IngestSummary>,
        cached_our_pubkey: Option<&CompressedRistrettoPublic>,
        cached_our_peers: Option<&BTreeSet<IngestPeerUri>>,
        update_if_wrong: bool,
        log_if_wrong: bool,
    ) -> Result<(), PeerBackupError> {
        mc_common::trace_time!(self.logger, "IngestController.confirm_backup");

        let summary = match cached_summary {
            Some(summary) => summary.clone(),
            None => conn.get_status()?,
        };

        match summary.mode {
            IngestControllerMode::Active => {
                if log_if_wrong {
                    log::error!(
                        self.logger,
                        "Peer {} is unexpectedly active! Expected to be an idle backup",
                        conn.uri()
                    );
                }
                return Err(PeerBackupError::AnotherActivePeer(conn.uri()));
            }
            IngestControllerMode::Idle => {}
        };

        let our_pubkey = cached_our_pubkey.cloned().unwrap_or_else(|| {
            self.enclave
                .get_ingress_pubkey()
                .expect("Could not get our pubkey from enclave")
                .into()
        });
        let our_peers = cached_our_peers
            .cloned()
            .unwrap_or_else(|| self.get_state().get_peers());

        let peer_pubkey = CompressedRistrettoPublic::try_from(summary.get_ingress_pubkey())?;
        if peer_pubkey != our_pubkey {
            if log_if_wrong {
                log::warn!(
                    self.logger,
                    "Our peer {} was not backing up our ingress key as expected! Ours: {}, Theirs: {}",
                    conn.uri(),
                    our_pubkey,
                    peer_pubkey
                );
            }

            if update_if_wrong {
                match conn.set_ingress_private_key(&our_pubkey) {
                    Ok(summary) => {
                        let peer_pubkey =
                            CompressedRistrettoPublic::try_from(summary.get_ingress_pubkey())?;
                        if peer_pubkey != our_pubkey {
                            let uri = conn.uri();
                            log::error!(self.logger, "Tried to send our ingress key to peer {}, but despite successful status the key is still wrong! Expected: {}, Found: {}", uri, our_pubkey, peer_pubkey);
                            return Err(PeerBackupError::FailedRemoteKeyBackup(uri));
                        }
                    }
                    Err(err @ ConnectionError::UnexpectedKeyInEnclave(_)) => {
                        log::info!(self.logger, "While sending our key to a peer, the key in our enclave changed: had {}, encountered {}. Backing off and not sending", our_pubkey, err);
                        return Err(err.into());
                    }
                    Err(err) => {
                        log::error!(
                            self.logger,
                            "Could not send our ingress key to peer {}: {}",
                            conn.uri(),
                            err
                        );
                        return Err(err.into());
                    }
                };
            }
        }

        let sorted_remote_peers = summary.get_sorted_peers()?;
        if our_peers != sorted_remote_peers {
            if log_if_wrong {
                log::warn!(
                    self.logger,
                    "Our peer {} did not have the same peer list as us, as we expected! Ours: {}, Theirs: {}",
                    conn.uri(),
                    SeqDisplay(our_peers.iter()),
                    SeqDisplay(sorted_remote_peers.iter())
                );
            }

            if update_if_wrong {
                match conn.set_peers(our_peers.clone()) {
                    Ok(new_summary) => {
                        let new_sorted_remote_peers = new_summary.get_sorted_peers()?;
                        if new_sorted_remote_peers != our_peers {
                            let uri = conn.uri();
                            log::error!(self.logger, "Tried to send our peer list to peer {}, but despite successful status the peer list is still wrong! Expected: {}, Found: {}", uri,
                                SeqDisplay(our_peers.iter()),
                                SeqDisplay(new_sorted_remote_peers.iter()),
                            );
                            return Err(PeerBackupError::FailedRemoteSetPeers(uri));
                        }
                    }
                    Err(err) => {
                        log::error!(
                            self.logger,
                            "Could not send our peer list to peer {}: {}",
                            conn.uri(),
                            err
                        );
                        return Err(err.into());
                    }
                };
            }
        }

        Ok(())
    }
}
