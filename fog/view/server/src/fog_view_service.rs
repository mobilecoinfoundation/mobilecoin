// Copyright (c) 2018-2021 The MobileCoin Foundation

use crate::server::DbPollSharedState;
use grpcio::{RpcContext, RpcStatus, RpcStatusCode, UnarySink};
use mc_attest_api::attest;
use mc_common::logger::{log, Logger};
use mc_fog_api::view_grpc::FogViewApi;
use mc_fog_recovery_db_iface::RecoveryDb;
use mc_fog_types::view::QueryRequestAAD;
use mc_fog_view_enclave::{Error as ViewEnclaveError, ViewEnclaveProxy};
use mc_fog_view_enclave_api::UntrustedQueryResponse;
use mc_util_grpc::{
    rpc_internal_error, rpc_invalid_arg_error, rpc_logger, rpc_permissions_error, send_result,
    Authenticator,
};
use mc_util_metrics::SVC_COUNTERS;
use std::sync::{Arc, Mutex};

#[derive(Clone)]
pub struct FogViewService<E: ViewEnclaveProxy, DB: RecoveryDb + Send + Sync> {
    /// Enclave providing access to the Recovery DB
    enclave: E,

    /// Recovery DB.
    db: Arc<DB>,

    /// Shared state from db polling thread.
    db_poll_shared_state: Arc<Mutex<DbPollSharedState>>,

    /// GRPC request authenticator.
    authenticator: Arc<dyn Authenticator + Send + Sync>,

    /// Slog logger object
    logger: Logger,
}

impl<E: ViewEnclaveProxy, DB: RecoveryDb + Send + Sync> FogViewService<E, DB> {
    /// Creates a new fog-view-service node (but does not create sockets and
    /// start it etc.)
    pub fn new(
        enclave: E,
        db: Arc<DB>,
        db_poll_shared_state: Arc<Mutex<DbPollSharedState>>,
        authenticator: Arc<dyn Authenticator + Send + Sync>,
        logger: Logger,
    ) -> Self {
        Self {
            enclave,
            db,
            db_poll_shared_state,
            authenticator,
            logger,
        }
    }

    /// Unwrap and forward to enclave
    pub fn query_impl(&mut self, request: attest::Message) -> Result<attest::Message, RpcStatus> {
        log::trace!(self.logger, "Getting encrypted request");

        // Attempt and deserialize the untrusted portion of this request.
        let query_request_aad: QueryRequestAAD = mc_util_serial::decode(request.get_aad())
            .map_err(|err| {
                RpcStatus::with_message(
                    RpcStatusCode::INVALID_ARGUMENT,
                    format!("AAD deserialization error: {}", err),
                )
            })?;

        let (user_events, next_start_from_user_event_id) = self
            .db
            .search_user_events(query_request_aad.start_from_user_event_id)
            .map_err(|e| rpc_internal_error("search_user_events", e, &self.logger))?;

        let (
            highest_processed_block_count,
            highest_processed_block_signature_timestamp,
            last_known_block_count,
            last_known_block_cumulative_txo_count,
        ) = {
            let shared_state = self.db_poll_shared_state.lock().expect("mutex poisoned");
            (
                shared_state.highest_processed_block_count,
                shared_state.highest_processed_block_signature_timestamp,
                shared_state.last_known_block_count,
                shared_state.last_known_block_cumulative_txo_count,
            )
        };

        let untrusted_query_response = UntrustedQueryResponse {
            user_events,
            next_start_from_user_event_id,
            highest_processed_block_count,
            highest_processed_block_signature_timestamp,
            last_known_block_count,
            last_known_block_cumulative_txo_count,
        };

        let result_blob = self
            .enclave
            .query(request.into(), untrusted_query_response)
            .map_err(|e| self.enclave_err_to_rpc_status("enclave request", e))?;

        let mut resp = attest::Message::new();
        resp.set_data(result_blob);
        Ok(resp)
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
impl<E: ViewEnclaveProxy, DB: RecoveryDb + Send + Sync> FogViewApi for FogViewService<E, DB> {
    fn auth(
        &mut self,
        ctx: RpcContext,
        mut request: attest::AuthMessage,
        sink: UnarySink<attest::AuthMessage>,
    ) {
        let _timer = SVC_COUNTERS.req(&ctx);
        mc_common::logger::scoped_global_logger(&rpc_logger(&ctx, &self.logger), |logger| {
            if let Err(err) = self.authenticator.authenticate_rpc(&ctx) {
                return send_result(ctx, sink, err.into(), &logger);
            }

            // TODO: Use the prost message directly, once available
            match self.enclave.client_accept(request.take_data().into()) {
                Ok((response, _)) => {
                    let mut result = attest::AuthMessage::new();
                    result.set_data(response.into());
                    send_result(ctx, sink, Ok(result), &logger);
                }
                Err(client_error) => {
                    // This is debug because there's no requirement on the remote party to trigger
                    // it.
                    log::debug!(
                        logger,
                        "ViewEnclaveApi::client_accept failed: {}",
                        client_error
                    );
                    send_result(
                        ctx,
                        sink,
                        Err(rpc_permissions_error(
                            "client_auth",
                            format!("Permission denied: {}", client_error),
                            &logger,
                        )),
                        &logger,
                    );
                }
            }
        });
    }

    fn query(
        &mut self,
        ctx: RpcContext,
        request: attest::Message,
        sink: UnarySink<attest::Message>,
    ) {
        let _timer = SVC_COUNTERS.req(&ctx);
        mc_common::logger::scoped_global_logger(&rpc_logger(&ctx, &self.logger), |logger| {
            if let Err(err) = self.authenticator.authenticate_rpc(&ctx) {
                return send_result(ctx, sink, err.into(), &logger);
            }

            send_result(ctx, sink, self.query_impl(request), &logger)
        })
    }
}
