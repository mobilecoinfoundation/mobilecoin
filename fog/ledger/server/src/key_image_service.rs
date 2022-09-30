// Copyright (c) 2018-2022 The MobileCoin Foundation
use crate::{server::DbPollSharedState, config::KeyImageClientListenUri};
use grpcio::{RpcContext, RpcStatus, UnarySink};
use mc_attest_api::{
    attest,
    attest::{AuthMessage, Message},
};
use mc_blockchain_types::MAX_BLOCK_VERSION;
use mc_common::logger::{log, Logger};
use mc_fog_api::{
    ledger::{MultiKeyImageStoreRequest, MultiKeyImageStoreResponse, MultiKeyImageStoreResponseStatus},
    ledger_grpc::{FogKeyImageApi, KeyImageStoreApi},
};
use mc_fog_ledger_enclave::LedgerEnclaveProxy;
use mc_fog_ledger_enclave_api::{Error as EnclaveError, UntrustedKeyImageQueryResponse};
use mc_fog_uri::{KeyImageStoreUri, ConnectionUri};
use mc_ledger_db::Ledger;
use mc_util_grpc::{
    rpc_internal_error, rpc_invalid_arg_error, rpc_logger, rpc_permissions_error, send_result,
    Authenticator,
};
use mc_util_metrics::SVC_COUNTERS;
use mc_watcher::watcher_db::WatcherDB;
use std::sync::{Arc, Mutex};

#[derive(Clone)]
pub struct KeyImageService<L: Ledger + Clone, E: LedgerEnclaveProxy> {
    /// The ClientListenUri for this FogViewService.
    client_listen_uri: KeyImageClientListenUri,
    ledger: L,
    watcher: WatcherDB,
    enclave: E,
    authenticator: Arc<dyn Authenticator + Send + Sync>,
    logger: Logger,
    /// Shared state from db polling thread.
    db_poll_shared_state: Arc<Mutex<DbPollSharedState>>,
}

impl<L: Ledger + Clone, E: LedgerEnclaveProxy> KeyImageService<L, E> {
    pub fn new(
        client_listen_uri: KeyImageClientListenUri,
        ledger: L,
        watcher: WatcherDB,
        enclave: E,
        db_poll_shared_state: Arc<Mutex<DbPollSharedState>>,
        authenticator: Arc<dyn Authenticator + Send + Sync>,
        logger: Logger,
    ) -> Self {
        Self {
            client_listen_uri,
            ledger,
            watcher,
            enclave,
            authenticator,
            logger,
            db_poll_shared_state,
        }
    }

    pub fn get_watcher(&mut self) -> WatcherDB {
        self.watcher.clone()
    }

    pub fn get_ledger(&mut self) -> L {
        self.ledger.clone()
    }

    pub fn get_db_poll_shared_state(&mut self) -> Arc<Mutex<DbPollSharedState>> {
        self.db_poll_shared_state.clone()
    }

    pub fn auth_impl(&mut self,
        mut req: AuthMessage,
        logger: &Logger) 
            -> Result<attest::AuthMessage, RpcStatus> { 
        // TODO: Use the prost message directly, once available
        match self.enclave.client_accept(req.take_data().into()) {
            Ok((response, _)) => {
                let mut result = attest::AuthMessage::new();
                result.set_data(response.into());
                Ok(result)
            }
            Err(client_error) => {
                // There's no requirement on the remote party to trigger this, so it's debug.
                log::debug!(
                    logger,
                    "KeyImageStoreApi::client_accept failed: {}",
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

    /// Unwrap and forward to enclave
    // self.enclave.check_key_images should take both an AttestMessage and an
    // UntrustedKeyImageQueryResponse object that contains any data that is
    // needed that isn't in the ORAM. This might be like "num_blocks" and similar
    // stuff. self.enclave.check_key_images should return an AttestMessage that
    // we send back to the user.
    fn check_key_images_auth(
        &mut self,
        request: attest::Message,
    ) -> Result<attest::Message, RpcStatus> {
        log::trace!(self.logger, "Getting encrypted request");

        let (
            highest_processed_block_count,
            last_known_block_cumulative_txo_count,
            latest_block_version,
        ) = {
            let shared_state = self.db_poll_shared_state.lock().expect("mutex poisoned");
            (
                shared_state.highest_processed_block_count,
                shared_state.last_known_block_cumulative_txo_count,
                shared_state.latest_block_version,
            )
        };

        let untrusted_query_response = UntrustedKeyImageQueryResponse {
            highest_processed_block_count,
            last_known_block_cumulative_txo_count,
            latest_block_version,
            max_block_version: latest_block_version.max(*MAX_BLOCK_VERSION),
        };

        let result_blob = self
            .enclave
            .check_key_images(request.into(), untrusted_query_response)
            .map_err(|e| self.enclave_err_to_rpc_status("enclave request", e))?;

        let mut resp = attest::Message::new();
        resp.set_data(result_blob);
        Ok(resp)
    }

    // Helper function that is common
    fn enclave_err_to_rpc_status(&self, context: &str, src: EnclaveError) -> RpcStatus {
        // Treat prost-decode error as an invalid arg,
        // treat attest error as permission denied,
        // everything else is an internal error
        match src {
            EnclaveError::ProstDecode => {
                rpc_invalid_arg_error(context, "Prost decode failed", &self.logger)
            }
            EnclaveError::Attest(err) => rpc_permissions_error(context, err, &self.logger),
            other => rpc_internal_error(context, format!("{}", &other), &self.logger),
        }
    }

    /// Handle MultiKeyImageStoreRequest contents sent by a router to this store.
    fn process_queries(&mut self, fog_ledger_store_uri: KeyImageStoreUri, 
        queries: Vec<attest::Message>) -> MultiKeyImageStoreResponse { 
        let mut response = MultiKeyImageStoreResponse::new();
        // The router needs our own URI, in case auth fails / hasn't been started yet.
        response.set_fog_ledger_store_uri(fog_ledger_store_uri.url().to_string());

        for query in queries.into_iter() {
            // Only one of the query messages in the multi-store query is intended for this store.
            // It's a bit of a broadcast model - all queries are sent to all stores, and then 
            // the stores evaluate which message is meant for them.
            if let Ok(attested_message) = self.check_key_images_auth(query) {
                response.set_query_response(attested_message);
                response.set_status(MultiKeyImageStoreResponseStatus::SUCCESS);

                return response;
            }
        }

        // TODO: different response code for "none found matching" from "authentication error," potentially?

        response.set_status(MultiKeyImageStoreResponseStatus::AUTHENTICATION_ERROR);
        response
    }
}

impl<L: Ledger + Clone, E: LedgerEnclaveProxy> FogKeyImageApi for KeyImageService<L, E> {
    fn check_key_images(&mut self, ctx: RpcContext, request: Message, sink: UnarySink<Message>) {
        let _timer = SVC_COUNTERS.req(&ctx);
        mc_common::logger::scoped_global_logger(&rpc_logger(&ctx, &self.logger), |logger| {
            if let Err(err) = self.authenticator.authenticate_rpc(&ctx) {
                return send_result(ctx, sink, err.into(), logger);
            }

            send_result(ctx, sink, self.check_key_images_auth(request), logger)
        })
    }

    fn auth(&mut self, ctx: RpcContext, request: AuthMessage, sink: UnarySink<AuthMessage>) {
        let _timer = SVC_COUNTERS.req(&ctx);
        mc_common::logger::scoped_global_logger(&rpc_logger(&ctx, &self.logger), |logger| {
            if let Err(err) = self.authenticator.authenticate_rpc(&ctx) {
                return send_result(ctx, sink, err.into(), logger);
            }

            match self.auth_impl(request.into(), &logger) {
                Ok(response) => {
                    send_result(ctx, sink, Ok(response.into()), logger);
                }
                Err(client_error) => {
                    // This is debug because there's no requirement on the remote party to trigger
                    // it.
                    log::info!(
                        logger,
                        "LedgerEnclave::client_accept failed: {}",
                        client_error
                    );
                    // TODO: increment failed inbound peering counter.
                    send_result(
                        ctx,
                        sink,
                        Err(client_error),
                        logger,
                    );
                }
            }
        });
    }
}

impl<L: Ledger + Clone, E: LedgerEnclaveProxy> KeyImageStoreApi for KeyImageService<L, E> {
    #[allow(unused_variables)] //FIXME
    fn auth(
        &mut self,
        ctx: grpcio::RpcContext,
        req: AuthMessage,
        sink: grpcio::UnarySink<AuthMessage>,
    ) {
        let _timer = SVC_COUNTERS.req(&ctx);
        mc_common::logger::scoped_global_logger(&rpc_logger(&ctx, &self.logger), |logger| {
            if let Err(err) = self.authenticator.authenticate_rpc(&ctx) {
                return send_result(ctx, sink, err.into(), logger);
            }

            match self.auth_impl(req.into(), &logger) {
                Ok(response) => {
                    send_result(ctx, sink, Ok(response.into()), logger);
                }
                Err(client_error) => {
                    // This is debug because there's no requirement on the remote party to trigger
                    // it.
                    log::info!(
                        logger,
                        "LedgerEnclave::client_accept failed: {}",
                        client_error
                    );
                    // TODO: increment failed inbound peering counter.
                    send_result(
                        ctx,
                        sink,
                        Err(client_error),
                        logger,
                    );
                }
            }
        });
    }

    #[allow(unused_variables)] //FIXME
    fn multi_key_image_store_query(
        &mut self,
        ctx: grpcio::RpcContext,
        req: MultiKeyImageStoreRequest,
        sink: grpcio::UnarySink<MultiKeyImageStoreResponse>,
    ) {
        let _timer = SVC_COUNTERS.req(&ctx);
        mc_common::logger::scoped_global_logger(&rpc_logger(&ctx, &self.logger), |logger| {
            if let Err(err) = self.authenticator.authenticate_rpc(&ctx) {
                return send_result(ctx, sink, err.into(), logger);
            }
            if let KeyImageClientListenUri::Store(store_uri) = self.client_listen_uri.clone() {
                let response = self.process_queries(store_uri, req.queries.into_vec());
                send_result(ctx, sink, Ok(response), logger)
            } else {
                let rpc_permissions_error = rpc_permissions_error(
                    "multi_key_image_store_query",
                    "Permission denied: the multi_key_image_store_query is not accessible to clients"
                        .to_string(),
                    logger,
                );
                send_result(ctx, sink, Err(rpc_permissions_error), logger)
            }
        });
    }
}
