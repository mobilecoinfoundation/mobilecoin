// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Implements the service logic for the Fog Overseer.
//!
//! This is encapsulated by Fog Oveseer Server, and it in turn encapsulates the
//! OverseerWorker, which contains the overseer busines logic.
//!
//! HTTP Client -> Overseer Rocket Server -> *OverseerService* -> OverseerWorker

use crate::{error::OverseerError, responses::GetIngestSummariesResponse, worker::OverseerWorker};
use mc_common::logger::{log, Logger};
use mc_fog_ingest_client::FogIngestGrpcClient;
use mc_fog_recovery_db_iface::RecoveryDb;
use mc_fog_types::ingest_common::IngestSummary;
use mc_fog_uri::FogIngestUri;
use prometheus::{self, Encoder};
use std::{
    collections::HashMap,
    convert::TryFrom,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::Duration,
};

/// Implements core logic for the Fog Overseer HTTP server.
pub struct OverseerService<DB: RecoveryDb + Clone + Send + Sync + 'static>
where
    OverseerError: From<DB::Error>,
{
    ingest_clients: Arc<Vec<FogIngestGrpcClient>>,
    logger: Logger,
    overseer_worker: Option<OverseerWorker>,
    recovery_db: DB,
    is_enabled: Arc<AtomicBool>,
}

impl<DB: RecoveryDb + Clone + Send + Sync + 'static> OverseerService<DB>
where
    OverseerError: From<DB::Error>,
{
    /// Retry failed GRPC requests every 10 seconds.
    const GRPC_RETRY_SECONDS: Duration = Duration::from_millis(10000);

    /// Insantiate the service with the given URIs and DB.
    pub fn new(ingest_cluster_uris: Vec<FogIngestUri>, recovery_db: DB, logger: Logger) -> Self {
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
        Self {
            ingest_clients: Arc::new(ingest_clients),
            logger,
            overseer_worker: None,
            recovery_db,
            is_enabled: Arc::new(AtomicBool::new(false)),
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
            self.ingest_clients.clone(),
            self.recovery_db.clone(),
            self.logger.clone(),
            self.is_enabled.clone(),
        ));

        Ok(())
    }

    /// Stop the service.
    /// This blocks on teardown of overseer_worker
    pub fn stop(&mut self) -> Result<(), OverseerError> {
        self.overseer_worker = None;

        Ok(())
    }

    /// Enable Overseer worker.
    pub fn enable(&self) -> Result<String, String> {
        log::info!(self.logger, "Enabling overseer worker");
        let was_enabled = self.is_enabled.swap(true, Ordering::SeqCst);
        let response_message = match was_enabled {
            true => "Fog Overseer was already enabled",
            false => "Fog Overseer was successfully enabled",
        };

        Ok(response_message.to_string())
    }

    /// Disable Overseer worker.
    pub fn disable(&self) -> Result<String, String> {
        log::info!(self.logger, "Disabling overseer worker");
        let was_enabled = self.is_enabled.swap(false, Ordering::SeqCst);
        let response_message = match was_enabled {
            true => "Fog Overseer was successfully disabled",
            false => "Fog Overseer was already disabled",
        };

        Ok(response_message.to_string())
    }

    /// Get the status for Overseer.
    pub fn get_status(&self) -> Result<String, String> {
        let is_enabled: bool = self.is_enabled.load(Ordering::SeqCst);
        let response_message = match is_enabled {
            true => "Fog Overseer is enabled.",
            false => "Fog Overseer is disabled.",
        };

        Ok(response_message.to_string())
    }

    /// Get metrics to publish.
    pub fn get_metrics(&self) -> Result<String, String> {
        log::trace!(self.logger, "Getting prometheus metrics");
        let metric_families = prometheus::gather();
        let encoder = prometheus::TextEncoder::new();
        let mut buffer = vec![];
        encoder.encode(&metric_families, &mut buffer).unwrap();

        String::from_utf8(buffer)
            .map_err(|err| format!("Get prometheus metrics from_utf8 failed: {}", err))
    }

    /// Try and fetch summaries from all ingest clients.
    pub fn get_ingest_summaries(&self) -> Result<GetIngestSummariesResponse, String> {
        let ingest_summaries: HashMap<FogIngestUri, Result<IngestSummary, String>> = self
            .ingest_clients
            .iter()
            .map(|ingest_client| {
                let uri = ingest_client.get_uri();
                let result = match ingest_client.get_status() {
                    Ok(proto_ingest_summary) => {
                        log::trace!(
                            self.logger,
                            "Got ingest summary for node with URI '{}': {:?}",
                            uri,
                            proto_ingest_summary
                        );
                        IngestSummary::try_from(&proto_ingest_summary).map_err(|err| {
                            format!(
                                "Could not parse ingest summary for node with URI '{}': {}",
                                uri, err
                            )
                        })
                    }

                    Err(err) => {
                        let error_message = format!(
                            "Unable to retrieve ingest summary for node with URI '{}': {}",
                            uri, err
                        );
                        log::trace!(self.logger, "{}", error_message);
                        Err(error_message)
                    }
                };

                (uri.clone(), result)
            })
            .collect();

        Ok(GetIngestSummariesResponse { ingest_summaries })
    }
}

impl<DB: RecoveryDb + Clone + Send + Sync + 'static> Drop for OverseerService<DB>
where
    OverseerError: From<DB::Error>,
{
    fn drop(&mut self) {
        let _ = self.disable();
        let _ = self.stop();
    }
}
