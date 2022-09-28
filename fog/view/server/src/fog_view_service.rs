// Copyright (c) 2018-2022 The MobileCoin Foundation

use crate::{
    config::{ClientListenUri, MobileAcctViewConfig},
    server::DbPollSharedState,
    sharding_strategy::ShardingStrategy,
};
use grpcio::{RpcContext, RpcStatus, RpcStatusCode, UnarySink};
use mc_attest_api::attest;
use mc_common::logger::{log, Logger};
use mc_fog_api::{
    view::{
        MultiViewStoreQueryRequest, MultiViewStoreQueryResponse, MultiViewStoreQueryResponseStatus,
    },
    view_grpc::{FogViewApi, FogViewStoreApi},
};
use mc_fog_recovery_db_iface::RecoveryDb;
use mc_fog_types::view::QueryRequestAAD;
use mc_fog_uri::{ConnectionUri, FogViewStoreUri};
use mc_fog_view_enclave::{Error as ViewEnclaveError, ViewEnclaveProxy};
use mc_fog_view_enclave_api::UntrustedQueryResponse;
use mc_util_grpc::{
    check_request_chain_id, rpc_internal_error, rpc_invalid_arg_error, rpc_logger,
    rpc_permissions_error, send_result, Authenticator,
};
use mc_util_metrics::SVC_COUNTERS;
use mc_util_telemetry::{tracer, BoxedTracer, Tracer};
use std::sync::{Arc, Mutex};

#[derive(Clone)]
pub struct FogViewService<E, DB, SS>
where
    E: ViewEnclaveProxy,
    DB: RecoveryDb + Send + Sync,
    SS: ShardingStrategy,
{
    /// Server Config
    config: MobileAcctViewConfig,

    /// Enclave providing access to the Recovery DB
    enclave: E,

    /// Recovery DB.
    db: Arc<DB>,

    /// Shared state from db polling thread.
    db_poll_shared_state: Arc<Mutex<DbPollSharedState>>,

    /// GRPC request authenticator.
    authenticator: Arc<dyn Authenticator + Send + Sync>,

    /// The ClientListenUri for this FogViewService.
    client_listen_uri: ClientListenUri,

    /// Slog logger object
    logger: Logger,

    /// Dictates what blocks to process.
    sharding_strategy: SS,
}

impl<E, DB, SS> FogViewService<E, DB, SS>
where
    E: ViewEnclaveProxy,
    DB: RecoveryDb + Send + Sync,
    SS: ShardingStrategy,
{
    /// Creates a new fog-view-service node (but does not create sockets and
    /// start it etc.)
    pub fn new(
        config: MobileAcctViewConfig,
        enclave: E,
        db: Arc<DB>,
        db_poll_shared_state: Arc<Mutex<DbPollSharedState>>,
        authenticator: Arc<dyn Authenticator + Send + Sync>,
        client_listen_uri: ClientListenUri,
        sharding_strategy: SS,
        logger: Logger,
    ) -> Self {
        Self {
            config,
            enclave,
            db,
            db_poll_shared_state,
            authenticator,
            client_listen_uri,
            sharding_strategy,
            logger,
        }
    }

    fn auth_impl(
        &mut self,
        mut request: attest::AuthMessage,
        logger: &Logger,
    ) -> Result<attest::AuthMessage, RpcStatus> {
        // TODO: Use the prost message directly, once available
        match self.enclave.client_accept(request.take_data().into()) {
            Ok((response, _)) => {
                let mut result = attest::AuthMessage::new();
                result.set_data(response.into());
                Ok(result)
            }
            Err(client_error) => {
                // This is debug because there's no requirement on the remote party to trigger
                // it.
                log::debug!(
                    logger,
                    "ViewEnclaveApi::client_accept failed: {}",
                    client_error
                );
                let rpc_permissions_error = rpc_permissions_error(
                    "client_auth",
                    format!("Permission denied: {}", client_error),
                    logger,
                );
                Err(rpc_permissions_error)
            }
        }
    }

    pub fn create_untrusted_query_response(
        &mut self,
        aad: &[u8],
        tracer: &BoxedTracer,
    ) -> Result<UntrustedQueryResponse, RpcStatus> {
        // Attempt and deserialize the untrusted portion of this request.
        let query_request_aad: QueryRequestAAD = mc_util_serial::decode(aad).map_err(|err| {
            RpcStatus::with_message(
                RpcStatusCode::INVALID_ARGUMENT,
                format!("AAD deserialization error: {}", err),
            )
        })?;

        let (user_events, next_start_from_user_event_id) =
            tracer.in_span("search_user_events", |_cx| {
                self.db
                    .search_user_events(query_request_aad.start_from_user_event_id)
                    .map_err(|e| rpc_internal_error("search_user_events", e, &self.logger))
            })?;

        let (
            highest_processed_block_count,
            highest_processed_block_signature_timestamp,
            last_known_block_count,
            last_known_block_cumulative_txo_count,
        ) = tracer.in_span("get_shared_state", |_cx_| {
            let shared_state = self.db_poll_shared_state.lock().expect("mutex poisoned");
            (
                shared_state.highest_processed_block_count,
                shared_state.highest_processed_block_signature_timestamp,
                shared_state.last_known_block_count,
                shared_state.last_known_block_cumulative_txo_count,
            )
        });

        let untrusted_query_response = UntrustedQueryResponse {
            user_events,
            next_start_from_user_event_id,
            highest_processed_block_count,
            highest_processed_block_signature_timestamp,
            last_known_block_count,
            last_known_block_cumulative_txo_count,
        };

        Ok(untrusted_query_response)
    }

    /// Unwrap and forward to enclave
    pub fn query_impl(&mut self, request: attest::Message) -> Result<attest::Message, RpcStatus> {
        log::trace!(self.logger, "Getting encrypted request");
        let tracer = tracer!();

        tracer.in_span("query_impl", |_cx| {
            let untrusted_query_response =
                self.create_untrusted_query_response(request.get_aad(), &tracer)?;
            let result_blob = tracer.in_span("enclave_query", |_cx| {
                self.enclave
                    .query(request.into(), untrusted_query_response)
                    .map_err(|e| self.enclave_err_to_rpc_status("enclave request", e))
            })?;

            let mut resp = attest::Message::new();
            resp.set_data(result_blob);
            Ok(resp)
        })
    }

    /// Unwrap and forward to enclave
    pub fn query_nonce_impl(
        &mut self,
        request: attest::NonceMessage,
    ) -> Result<attest::NonceMessage, RpcStatus> {
        log::trace!(self.logger, "Getting encrypted request");
        let tracer = tracer!();

        tracer.in_span("query_impl", |_cx| {
            // TODO: Create query_nonce enclave method that does what query currently does
            // but for NonceMessage. It should produce data and a nonce that is
            // then set on the nonce_message.
            let _untrusted_query_response =
                self.create_untrusted_query_response(request.get_aad(), &tracer)?;
            let data = vec![0; 0];
            let nonce = 0;

            let mut nonce_message = attest::NonceMessage::new();
            nonce_message.set_data(data);
            nonce_message.set_nonce(nonce);
            Ok(nonce_message)
        })
    }

    fn process_queries(
        &mut self,
        fog_view_store_uri: FogViewStoreUri,
        queries: Vec<attest::NonceMessage>,
    ) -> MultiViewStoreQueryResponse {
        let mut response = MultiViewStoreQueryResponse::new();
        response.set_fog_view_store_uri(fog_view_store_uri.url().to_string());
        for query in queries.into_iter() {
            let result = self.query_nonce_impl(query);
            // Only one of the query messages in an MVSQR is intended for this store
            if let Ok(attested_message) = result {
                {
                    let shared_state = self.db_poll_shared_state.lock().expect("mutex poisoned");
                    if !self
                        .sharding_strategy
                        .is_ready_to_serve_tx_outs(shared_state.processed_block_count.into())
                    {
                        response.set_status(MultiViewStoreQueryResponseStatus::NOT_READY);
                    } else {
                        response.set_query_response(attested_message);
                        response.set_status(MultiViewStoreQueryResponseStatus::SUCCESS);
                    }
                }
                return response;
            }
        }

        response.set_status(MultiViewStoreQueryResponseStatus::AUTHENTICATION_ERROR);
        response
    }

    // Helper function that is common
    fn enclave_err_to_rpc_status(&self, context: &str, src: ViewEnclaveError) -> RpcStatus {
        // Treat prost-decode error as an invalid arg,
        // treat attest error as permission denied,
        // everything else is an internal error
        match src {
            ViewEnclaveError::ProstDecode => {
                rpc_invalid_arg_error(context, "Prost decode failed", &self.logger)
            }
            ViewEnclaveError::AttestEnclave(err) => {
                rpc_permissions_error(context, err, &self.logger)
            }
            other => rpc_internal_error(context, format!("{}", &other), &self.logger),
        }
    }
}

// Implement grpc trait
impl<E, DB, SS> FogViewApi for FogViewService<E, DB, SS>
where
    E: ViewEnclaveProxy,
    DB: RecoveryDb + Send + Sync,
    SS: ShardingStrategy,
{
    fn auth(
        &mut self,
        ctx: RpcContext,
        request: attest::AuthMessage,
        sink: UnarySink<attest::AuthMessage>,
    ) {
        let _timer = SVC_COUNTERS.req(&ctx);
        mc_common::logger::scoped_global_logger(&rpc_logger(&ctx, &self.logger), |logger| {
            if let Err(err) = check_request_chain_id(&self.config.chain_id, &ctx) {
                return send_result(ctx, sink, Err(err), logger);
            }

            if let Err(err) = self.authenticator.authenticate_rpc(&ctx) {
                return send_result(ctx, sink, err.into(), logger);
            }

            send_result(ctx, sink, self.auth_impl(request, logger), logger);
        })
    }

    fn query(
        &mut self,
        ctx: RpcContext,
        request: attest::Message,
        sink: UnarySink<attest::Message>,
    ) {
        let _timer = SVC_COUNTERS.req(&ctx);
        mc_common::logger::scoped_global_logger(&rpc_logger(&ctx, &self.logger), |logger| {
            if let Err(err) = check_request_chain_id(&self.config.chain_id, &ctx) {
                return send_result(ctx, sink, Err(err), logger);
            }

            if let Err(err) = self.authenticator.authenticate_rpc(&ctx) {
                return send_result(ctx, sink, err.into(), logger);
            }

            send_result(ctx, sink, self.query_impl(request), logger)
        })
    }
}

/// Implement the FogViewStoreService gRPC trait.
impl<E, DB, SS> FogViewStoreApi for FogViewService<E, DB, SS>
where
    E: ViewEnclaveProxy,
    DB: RecoveryDb + Send + Sync,
    SS: ShardingStrategy,
{
    fn auth(
        &mut self,
        ctx: RpcContext,
        request: attest::AuthMessage,
        sink: UnarySink<attest::AuthMessage>,
    ) {
        let _timer = SVC_COUNTERS.req(&ctx);
        mc_common::logger::scoped_global_logger(&rpc_logger(&ctx, &self.logger), |logger| {
            if let Err(err) = self.authenticator.authenticate_rpc(&ctx) {
                return send_result(ctx, sink, err.into(), logger);
            }

            send_result(ctx, sink, self.auth_impl(request, logger), logger);
        })
    }

    /// Fulfills the query if the MultiViewStoreQueryRequest contains an
    /// encrypted Query for the store. If it doesn't, then it responds with
    /// an grpc error that contains the store's hostname.
    fn multi_view_store_query(
        &mut self,
        ctx: RpcContext,
        request: MultiViewStoreQueryRequest,
        sink: UnarySink<MultiViewStoreQueryResponse>,
    ) {
        mc_common::logger::scoped_global_logger(&rpc_logger(&ctx, &self.logger), |logger| {
            if let Err(err) = self.authenticator.authenticate_rpc(&ctx) {
                return send_result(ctx, sink, err.into(), logger);
            }
            if let ClientListenUri::Store(fog_view_store_uri) = self.client_listen_uri.clone() {
                let response = self.process_queries(fog_view_store_uri, request.queries.into_vec());
                send_result(ctx, sink, Ok(response), logger)
            } else {
                let rpc_permissions_error = rpc_permissions_error(
                    "multi_view_store_query",
                    "Permission denied: the multi_view_store_query is not accessible to clients"
                        .to_string(),
                    logger,
                );
                send_result(ctx, sink, Err(rpc_permissions_error), logger)
            }
        });
    }
}
