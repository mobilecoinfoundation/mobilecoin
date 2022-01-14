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
    is_enabled: Arc<AtomicBool>,
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
            is_enabled: Arc::new(AtomicBool::new(true)),
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
            self.is_enabled.clone(),
            self.stop_requested.clone(),
        ));

        Ok(())
    }

    pub fn stop(&mut self) -> Result<(), OverseerError> {
        // This blocks on teardown of overseer_worker
        self.overseer_worker = None;

        Ok(())
    }

    pub fn enable(&self) -> Result<String, String> {
        log::info!(self.logger, "Enabling overseer worker");
        self.is_enabled.store(true, Ordering::SeqCst);
        Ok(String::from("Fog Overseer was successfully enabled."))
    }

    pub fn disable(&self) -> Result<String, String> {
        log::info!(self.logger, "Disabling overseer worker");
        self.is_enabled.store(false, Ordering::SeqCst);
        Ok(String::from("Fog Overseer was successfully disabled."))
    }

    pub fn get_status(&self) -> Result<String, String> {
        let is_enabled : bool = self.is_enabled.load(Ordering::SeqCst);
        let response_message = match is_enabled {
            true => "Fog Overseer is enabled.",
            false => "Fog Overseer is disabled.",
        };

        Ok(String::from(response_message))
    }
}
