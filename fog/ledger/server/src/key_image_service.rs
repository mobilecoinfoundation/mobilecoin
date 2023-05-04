// Copyright (c) 2018-2022 The MobileCoin Foundation
use crate::{DbPollSharedState, SVC_COUNTERS};
use grpcio::RpcStatus;
use mc_attest_api::{attest, attest::AuthMessage};
use mc_blockchain_types::MAX_BLOCK_VERSION;
use mc_common::logger::{log, Logger};
use mc_fog_api::{
    ledger::{
        MultiKeyImageStoreRequest, MultiKeyImageStoreResponse, MultiKeyImageStoreResponseStatus,
    },
    ledger_grpc::KeyImageStoreApi,
};
use mc_fog_ledger_enclave::LedgerEnclaveProxy;
use mc_fog_ledger_enclave_api::{Error as EnclaveError, UntrustedKeyImageQueryResponse};
use mc_fog_uri::{ConnectionUri, KeyImageStoreUri};
use mc_ledger_db::Ledger;
use mc_util_grpc::{rpc_logger, rpc_permissions_error, send_result, Authenticator};
use mc_watcher::watcher_db::WatcherDB;
use std::sync::{Arc, Mutex};

#[derive(Clone)]
pub struct KeyImageService<L: Ledger + Clone, E: LedgerEnclaveProxy> {
    /// The ClientListenUri for this Fog Ledger Service.
    client_listen_uri: KeyImageStoreUri,
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
        client_listen_uri: KeyImageStoreUri,
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

    pub fn auth_store(
        &mut self,
        mut req: AuthMessage,
        logger: &Logger,
    ) -> Result<attest::AuthMessage, RpcStatus> {
        // TODO: Use the prost message directly, once available
        match self.enclave.frontend_accept(req.take_data().into()) {
            Ok((response, _)) => {
                let mut result = attest::AuthMessage::new();
                result.set_data(response.into());
                Ok(result)
            }
            Err(client_error) => {
                // There's no requirement on the remote party to trigger this, so it's debug.
                log::debug!(
                    logger,
                    "KeyImageStoreApi::frontend_accept failed: {}",
                    client_error
                );
                let rpc_permissions_error = rpc_permissions_error(
                    "auth_store",
                    format!("Permission denied: {client_error}"),
                    logger,
                );
                Err(rpc_permissions_error)
            }
        }
    }

    /// Generate an UntrustedKeyImageQueryResponse
    /// for use in [KeyImageService::check_key_images_auth()]
    /// and [KeyImageService::check_key_image_store_auth()]
    fn prepare_untrusted_query(&mut self) -> UntrustedKeyImageQueryResponse {
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

        UntrustedKeyImageQueryResponse {
            highest_processed_block_count,
            last_known_block_cumulative_txo_count,
            latest_block_version,
            max_block_version: latest_block_version.max(*MAX_BLOCK_VERSION),
        }
    }

    /// Unwrap and forward to enclave
    // self.enclave.check_key_images should take both a NonceMessage and an
    // UntrustedKeyImageQueryResponse object that contains any data that is
    // needed that isn't in the ORAM. This might be like "num_blocks" and similar
    // stuff. self.enclave.check_key_images should return an AttestMessage that
    // we send back to the user.
    fn check_key_image_store_auth(
        &mut self,
        request: attest::NonceMessage,
    ) -> Result<attest::NonceMessage, EnclaveError> {
        log::trace!(self.logger, "Getting encrypted request");

        let untrusted_query_response = self.prepare_untrusted_query();

        let response = self
            .enclave
            .check_key_image_store(request.into(), untrusted_query_response)?;

        Ok(response.into())
    }

    /// Handle MultiKeyImageStoreRequest contents sent by a router to this
    /// store.
    fn process_queries(
        &mut self,
        fog_ledger_store_uri: KeyImageStoreUri,
        queries: Vec<attest::NonceMessage>,
    ) -> MultiKeyImageStoreResponse {
        let mut response = MultiKeyImageStoreResponse::new();
        // The router needs our own URI, in case auth fails / hasn't been started yet.
        response.set_store_uri(fog_ledger_store_uri.url().to_string());
        // Default status of AUTHENTICATION_ERROR in case of empty queries
        response.set_status(MultiKeyImageStoreResponseStatus::AUTHENTICATION_ERROR);

        for query in queries.into_iter() {
            // Only one of the query messages in the multi-store query is intended for this
            // store. It's a bit of a broadcast model - all queries are sent to
            // all stores, and then the stores evaluate which message is meant
            // for them.
            match self.check_key_image_store_auth(query) {
                Ok(attested_message) => {
                    response.set_query_response(attested_message);
                    response.set_status(MultiKeyImageStoreResponseStatus::SUCCESS);
                }
                Err(EnclaveError::ProstDecode) => {
                    response.set_status(MultiKeyImageStoreResponseStatus::INVALID_ARGUMENT);
                }
                Err(EnclaveError::Attest(_)) => {
                    response.set_status(MultiKeyImageStoreResponseStatus::AUTHENTICATION_ERROR);
                    // All other conditions are early exit but we expect several of these
                    continue;
                }
                Err(_) => {
                    response.set_status(MultiKeyImageStoreResponseStatus::UNKNOWN);
                }
            }

            // Early-exit for success or failure
            return response;
        }

        // Late exit for authentication errors
        response
    }
}

impl<L: Ledger + Clone, E: LedgerEnclaveProxy> KeyImageStoreApi for KeyImageService<L, E> {
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

            match self.auth_store(req, logger) {
                Ok(response) => {
                    send_result(ctx, sink, Ok(response), logger);
                }
                Err(client_error) => {
                    // This is debug because there's no requirement on the remote party to trigger
                    // it.
                    log::info!(
                        logger,
                        "LedgerEnclave::frontend_accept failed: {}",
                        client_error
                    );
                    // TODO: increment failed inbound peering counter.
                    send_result(ctx, sink, Err(client_error), logger);
                }
            }
        });
    }

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
            let response =
                self.process_queries(self.client_listen_uri.clone(), req.queries.into_vec());
            send_result(ctx, sink, Ok(response), logger)
        });
    }
}
