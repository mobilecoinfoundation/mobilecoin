// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Implement the ingest grpc API

use crate::{
    controller::IngestController,
    error::{IngestServiceError as Error, PeerBackupError},
    SVC_COUNTERS,
};
use grpcio::{RpcContext, RpcStatus, UnarySink};
use mc_api::external;
use mc_common::logger::Logger;
use mc_crypto_keys::CompressedRistrettoPublic;
use mc_fog_api::{
    account_ingest::*,
    fog_common::BlockRange,
    ingest_common::{IngestSummary, SetPeersRequest},
};
use mc_fog_block_provider::BlockProvider;
use mc_fog_ingest_enclave_api::Error as EnclaveError;
use mc_fog_recovery_db_iface::{RecoveryDb, ReportDb};
use mc_fog_uri::IngestPeerUri;
use mc_util_grpc::{
    rpc_database_err, rpc_internal_error, rpc_invalid_arg_error, rpc_logger, rpc_permissions_error,
    rpc_precondition_error, rpc_unavailable_error, send_result,
};
use std::{str::FromStr, sync::Arc};

/// Implements the ingest grpc api
#[derive(Clone)]
pub struct IngestService<DB: RecoveryDb + ReportDb + Clone + Send + Sync + 'static>
where
    Error: From<<DB as RecoveryDb>::Error>,
{
    controller: Arc<IngestController<DB>>,
    block_provider: Box<dyn BlockProvider>,
    logger: Logger,
}

impl<DB: RecoveryDb + ReportDb + Clone + Send + Sync + 'static> IngestService<DB>
where
    Error: From<<DB as RecoveryDb>::Error>,
{
    /// Creates a new ingest node (but does not create sockets and start it
    /// etc.)
    pub fn new(
        controller: Arc<IngestController<DB>>,
        block_provider: Box<dyn BlockProvider>,
        logger: Logger,
    ) -> Self {
        Self {
            controller,
            block_provider,
            logger,
        }
    }

    /// Logic of proto api
    pub fn get_status_impl(&mut self) -> Result<IngestSummary, RpcStatus> {
        Ok(self.controller.get_ingest_summary())
    }

    /// Logic of proto api
    pub fn new_keys_impl(&mut self, logger: &Logger) -> Result<IngestSummary, RpcStatus> {
        self.controller.new_keys().map_err(|err| match err {
            Error::ServerNotIdle => rpc_precondition_error("new_keys", err, logger),
            _ => rpc_internal_error("new_keys", err, logger),
        })?;

        Ok(self.controller.get_ingest_summary())
    }

    /// Logic of proto api
    pub fn set_pubkey_expiry_window_impl(
        &mut self,
        request: SetPubkeyExpiryWindowRequest,
        logger: &Logger,
    ) -> Result<IngestSummary, RpcStatus> {
        self.controller
            .set_pubkey_expiry_window(request.pubkey_expiry_window)
            .map_err(|err| rpc_precondition_error("set_pubkey_expiry_window", err, logger))?;

        Ok(self.controller.get_ingest_summary())
    }

    /// Logic of proto api
    pub fn set_peers_impl(
        &mut self,
        request: SetPeersRequest,
        logger: &Logger,
    ) -> Result<IngestSummary, RpcStatus> {
        let peers = request
            .ingest_peer_uris
            .iter()
            .map(|x| IngestPeerUri::from_str(x))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|err| rpc_invalid_arg_error("invalid peer uri", err, logger))?;

        self.controller
            .set_peers(peers)
            .map_err(|err| rpc_invalid_arg_error("invalid peer uri", err, logger))?;

        Ok(self.controller.get_ingest_summary())
    }

    /// Logic of proto api
    pub fn activate_impl(&mut self, _: (), logger: &Logger) -> Result<IngestSummary, RpcStatus> {
        self.controller
            .activate(
                self.block_provider
                    .num_blocks()
                    .map_err(|err| rpc_database_err(err, logger))?,
            )
            .map_err(|err| match err {
                // These are conditions under which it is incorrect for us to try to activate
                Error::ServerNotIdle | Error::Backup(PeerBackupError::AnotherActivePeer(_)) => {
                    rpc_precondition_error("activate", err, logger)
                }
                // Return UNAVAILABLE if there is a connection issue, or a retriable error
                Error::Connection(_)
                | Error::Backup(PeerBackupError::Connection(_))
                | Error::Backup(PeerBackupError::CreatingNewIngressKey) => {
                    rpc_unavailable_error("activate", err, logger)
                }
                // Return PERMISSION_DENIED if there is an attestation error
                Error::Enclave(EnclaveError::Attest(_)) => {
                    rpc_permissions_error("activate", err, logger)
                }
                // return INTERNAL_ERROR for other errors
                _ => rpc_internal_error("activate", err, logger),
            })?;

        Ok(self.controller.get_ingest_summary())
    }

    /// Logic of proto api
    pub fn retire_impl(&mut self, _: (), logger: &Logger) -> Result<IngestSummary, RpcStatus> {
        self.controller
            .retire()
            .map_err(|err| rpc_database_err(err, logger))
    }

    /// Logic of proto api
    pub fn unretire_impl(&mut self, _: (), logger: &Logger) -> Result<IngestSummary, RpcStatus> {
        self.controller
            .unretire()
            .map_err(|err| rpc_database_err(err, logger))
    }

    /// Report a lost ingress key
    pub fn report_lost_ingress_key_impl(
        &mut self,
        request: ReportLostIngressKeyRequest,
        logger: &Logger,
    ) -> Result<(), RpcStatus> {
        let key: CompressedRistrettoPublic = (&request.key.unwrap_or_default())
            .try_into()
            .map_err(|err| rpc_invalid_arg_error("lost_ingress_key", err, logger))?;

        self.controller
            .report_lost_ingress_key(key)
            .map_err(|err| rpc_database_err(err, logger))?;

        Ok(())
    }

    /// Gets all the known missed block ranges
    pub fn get_missed_block_ranges_impl(
        &mut self,
        logger: &Logger,
    ) -> Result<GetMissedBlockRangesResponse, RpcStatus> {
        let ranges = self
            .controller
            .get_missed_block_ranges()
            .map_err(|err| rpc_database_err(err, logger))?;

        Ok(GetMissedBlockRangesResponse {
            missed_block_ranges: ranges
                .iter()
                .map(|range| BlockRange {
                    start_block: range.start_block,
                    end_block: range.end_block,
                })
                .collect(),
        })
    }

    /// Retrieves a private key from a remote encalve and then sets it as the
    /// current enclave's private key.
    pub fn sync_keys_from_remote_impl(
        &mut self,
        request: SyncKeysFromRemoteRequest,
        logger: &Logger,
    ) -> Result<IngestSummary, RpcStatus> {
        let peer_uri = IngestPeerUri::from_str(&request.peer_uri)
            .map_err(|err| rpc_invalid_arg_error("invalid peer uri", err, logger))?;

        self.controller
            .sync_keys_from_remote(&peer_uri)
            .map_err(|err| match err {
                Error::ServerNotIdle => {
                    rpc_precondition_error("sync_keys_from_remote", err, logger)
                }
                Error::Connection(_) => rpc_unavailable_error("sync_keys_from_remote", err, logger),
                Error::Enclave(EnclaveError::Attest(_)) => {
                    rpc_permissions_error("sync_keys_from_remote", err, logger)
                }
                _ => rpc_internal_error("sync_keys_from_remote", err, logger),
            })
    }

    /// Retrieves the ingress public keys and filters according to the request's
    /// parameters.
    pub fn get_ingress_key_records_impl(
        &self,
        request: GetIngressKeyRecordsRequest,
        logger: &Logger,
    ) -> Result<GetIngressKeyRecordsResponse, RpcStatus> {
        let ingress_key_records = self
            .controller
            .get_ingress_key_records(
                request.start_block_at_least,
                request.should_include_lost_keys,
                request.should_include_retired_keys,
                request.should_only_include_unexpired_keys,
            )
            .map_err(|err| rpc_precondition_error("get_ingress_key_records", err, logger))?;

        Ok(GetIngressKeyRecordsResponse {
            records: ingress_key_records
                .iter()
                .map(|record| IngressPublicKeyRecord {
                    ingress_public_key: Some(external::CompressedRistretto::from(&record.key)),
                    start_block: record.status.start_block,
                    pubkey_expiry: record.status.pubkey_expiry,
                    retired: record.status.retired,
                    lost: record.status.lost,
                    last_scanned_block: record.last_scanned_block.unwrap_or_default(),
                })
                .collect(),
        })
    }
}

impl<DB: RecoveryDb + ReportDb + Clone + Send + Sync + 'static>
    mc_fog_api::account_ingest::AccountIngestApi for IngestService<DB>
where
    Error: From<<DB as RecoveryDb>::Error>,
{
    fn get_status(&mut self, ctx: RpcContext, _request: (), sink: UnarySink<IngestSummary>) {
        let _timer = SVC_COUNTERS.req(&ctx);
        mc_common::logger::scoped_global_logger(&rpc_logger(&ctx, &self.logger), |logger| {
            send_result(ctx, sink, self.get_status_impl(), logger)
        })
    }

    fn new_keys(&mut self, ctx: RpcContext, _request: (), sink: UnarySink<IngestSummary>) {
        let _timer = SVC_COUNTERS.req(&ctx);
        mc_common::logger::scoped_global_logger(&rpc_logger(&ctx, &self.logger), |logger| {
            send_result(ctx, sink, self.new_keys_impl(logger), logger)
        })
    }

    fn set_pubkey_expiry_window(
        &mut self,
        ctx: RpcContext,
        request: SetPubkeyExpiryWindowRequest,
        sink: UnarySink<IngestSummary>,
    ) {
        let _timer = SVC_COUNTERS.req(&ctx);
        mc_common::logger::scoped_global_logger(&rpc_logger(&ctx, &self.logger), |logger| {
            send_result(
                ctx,
                sink,
                self.set_pubkey_expiry_window_impl(request, logger),
                logger,
            )
        })
    }

    fn set_peers(
        &mut self,
        ctx: RpcContext,
        request: SetPeersRequest,
        sink: UnarySink<IngestSummary>,
    ) {
        let _timer = SVC_COUNTERS.req(&ctx);
        mc_common::logger::scoped_global_logger(&rpc_logger(&ctx, &self.logger), |logger| {
            send_result(ctx, sink, self.set_peers_impl(request, logger), logger)
        })
    }

    fn activate(&mut self, ctx: RpcContext, request: (), sink: UnarySink<IngestSummary>) {
        let _timer = SVC_COUNTERS.req(&ctx);
        mc_common::logger::scoped_global_logger(&rpc_logger(&ctx, &self.logger), |logger| {
            send_result(ctx, sink, self.activate_impl(request, logger), logger)
        })
    }

    fn retire(&mut self, ctx: RpcContext, request: (), sink: UnarySink<IngestSummary>) {
        let _timer = SVC_COUNTERS.req(&ctx);
        mc_common::logger::scoped_global_logger(&rpc_logger(&ctx, &self.logger), |logger| {
            send_result(ctx, sink, self.retire_impl(request, logger), logger)
        })
    }

    fn unretire(&mut self, ctx: RpcContext, request: (), sink: UnarySink<IngestSummary>) {
        let _timer = SVC_COUNTERS.req(&ctx);
        mc_common::logger::scoped_global_logger(&rpc_logger(&ctx, &self.logger), |logger| {
            send_result(ctx, sink, self.unretire_impl(request, logger), logger)
        })
    }

    fn report_lost_ingress_key(
        &mut self,
        ctx: RpcContext,
        request: ReportLostIngressKeyRequest,
        sink: UnarySink<()>,
    ) {
        let _timer = SVC_COUNTERS.req(&ctx);
        mc_common::logger::scoped_global_logger(&rpc_logger(&ctx, &self.logger), |logger| {
            send_result(
                ctx,
                sink,
                self.report_lost_ingress_key_impl(request, logger),
                logger,
            )
        })
    }

    fn get_missed_block_ranges(
        &mut self,
        ctx: RpcContext,
        _request: (),
        sink: UnarySink<GetMissedBlockRangesResponse>,
    ) {
        let _timer = SVC_COUNTERS.req(&ctx);
        mc_common::logger::scoped_global_logger(&rpc_logger(&ctx, &self.logger), |logger| {
            send_result(ctx, sink, self.get_missed_block_ranges_impl(logger), logger)
        })
    }

    fn sync_keys_from_remote(
        &mut self,
        ctx: RpcContext,
        request: SyncKeysFromRemoteRequest,
        sink: UnarySink<IngestSummary>,
    ) {
        let _timer = SVC_COUNTERS.req(&ctx);
        mc_common::logger::scoped_global_logger(&rpc_logger(&ctx, &self.logger), |logger| {
            send_result(
                ctx,
                sink,
                self.sync_keys_from_remote_impl(request, logger),
                logger,
            )
        })
    }

    fn get_ingress_key_records(
        &mut self,
        ctx: RpcContext,
        request: GetIngressKeyRecordsRequest,
        sink: UnarySink<GetIngressKeyRecordsResponse>,
    ) {
        let _timer = SVC_COUNTERS.req(&ctx);
        mc_common::logger::scoped_global_logger(&rpc_logger(&ctx, &self.logger), |logger| {
            send_result(
                ctx,
                sink,
                self.get_ingress_key_records_impl(request, logger),
                logger,
            )
        })
    }
}
