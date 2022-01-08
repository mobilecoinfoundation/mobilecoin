// Copyright (c) 2018-2022 The MobileCoin Foundation

use crate::{error::OverseerError, worker::OverseerWorker};
use mc_common::logger::{log, Logger};
use mc_fog_recovery_db_iface::RecoveryDb;
use mc_fog_uri::FogIngestUri;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};

// Implements core logic for the Fog Overseer HTTP server.
pub struct OverseerService<DB: RecoveryDb + Clone + Send + Sync + 'static>
where
    OverseerError: From<DB::Error>,
{
    ingest_cluster_uris: Vec<FogIngestUri>,
    logger: Logger,
    overseer_worker: Option<OverseerWorker>,
    recovery_db: DB,
    stop_requested: Arc<AtomicBool>,
}

impl<DB: RecoveryDb + Clone + Send + Sync + 'static> OverseerService<DB>
where
    OverseerError: From<DB::Error>,
{
    pub fn new(ingest_cluster_uris: Vec<FogIngestUri>, recovery_db: DB, logger: Logger) -> Self {
        Self {
            ingest_cluster_uris,
            logger,
            overseer_worker: None,
            recovery_db,
            stop_requested: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Starts the Fog Overseer worker thread.
    pub fn start(&mut self) -> Result<(), OverseerError> {
        let ret = self.start_helper();
        if let Err(ref err) = ret {
            log::error!(self.logger, "Stopping ingest server due to {:?}", err);
            self.stop()?;
        }
        ret
    }

    fn start_helper(&mut self) -> Result<(), OverseerError> {
        assert!(self.overseer_worker.is_none());
        log::info!(self.logger, "Starting overseer worker");

        self.overseer_worker = Some(OverseerWorker::new(
            self.ingest_cluster_uris.clone(),
            self.recovery_db.clone(),
            self.logger.clone(),
            self.stop_requested.clone(),
        ));

        Ok(())
    }

    pub fn stop(&mut self) -> Result<(), OverseerError> {
        // This blocks on teardown of overseer_worker
        self.overseer_worker = None;

        Ok(())
    }

    pub fn arm(&self) -> Result<String, String> {
        log::trace!(self.logger, "Arming overseer worker");
        self.stop_requested.store(true, Ordering::SeqCst);
        Ok(String::from("Fog Overseer was successfully armed."))
    }

    pub fn disarm(&self) -> Result<String, String> {
        log::trace!(self.logger, "Disarming overseer worker");
        self.stop_requested.store(false, Ordering::SeqCst);
        Ok(String::from("Fog Overseer was successfully disarmed."))
    }
}
