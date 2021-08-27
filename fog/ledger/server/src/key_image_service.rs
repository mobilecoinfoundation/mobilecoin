// Copyright (c) 2018-2021 The MobileCoin Foundation
use crate::server::DbPollSharedState;
use grpcio::{RpcContext, RpcStatus, UnarySink};
use mc_attest_api::{
    attest,
    attest::{AuthMessage, Message},
};
use mc_common::logger::{log, Logger};
use mc_fog_api::ledger_grpc::FogKeyImageApi;
use mc_fog_ledger_enclave::LedgerEnclaveProxy;
use mc_fog_ledger_enclave_api::{Error as EnclaveError, UntrustedKeyImageQueryResponse};
use mc_ledger_db::{self, Ledger};
use mc_util_grpc::{
    rpc_internal_error, rpc_invalid_arg_error, rpc_logger, rpc_permissions_error, send_result,
    Authenticator,
};
use mc_util_metrics::SVC_COUNTERS;
use mc_watcher::watcher_db::WatcherDB;
use std::sync::{Arc, Mutex};

#[derive(Clone)]
pub struct KeyImageService<L: Ledger + Clone, E: LedgerEnclaveProxy> {
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
        ledger: L,
        watcher: WatcherDB,
        enclave: E,
        db_poll_shared_state: Arc<Mutex<DbPollSharedState>>,
        authenticator: Arc<dyn Authenticator + Send + Sync>,
        logger: Logger,
    ) -> Self {
        Self {
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

        let (highest_processed_block_count, last_known_block_cumulative_txo_count) = {
            let shared_state = self.db_poll_shared_state.lock().expect("mutex poisoned");
            (
                shared_state.highest_processed_block_count,
                shared_state.last_known_block_cumulative_txo_count,
            )
        };

        let untrusted_query_response = UntrustedKeyImageQueryResponse {
            highest_processed_block_count,
            last_known_block_cumulative_txo_count,
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
        // Treat prost-decode error as an invalid arg, everything else is an internal
        // error
        match src {
            EnclaveError::ProstDecode => {
                rpc_invalid_arg_error(context, "Prost decode failed", &self.logger)
            }
            other => rpc_internal_error(context, format!("{}", &other), &self.logger),
        }
    }
}

impl<L: Ledger + Clone, E: LedgerEnclaveProxy> FogKeyImageApi for KeyImageService<L, E> {
    fn check_key_images(&mut self, ctx: RpcContext, request: Message, sink: UnarySink<Message>) {
        let _timer = SVC_COUNTERS.req(&ctx);
        mc_common::logger::scoped_global_logger(&rpc_logger(&ctx, &self.logger), |logger| {
            if let Err(err) = self.authenticator.authenticate_rpc(&ctx) {
                return send_result(ctx, sink, err.into(), &logger);
            }

            send_result(ctx, sink, self.check_key_images_auth(request), &logger)
        })
    }

    fn auth(&mut self, ctx: RpcContext, request: AuthMessage, sink: UnarySink<AuthMessage>) {
        let _timer = SVC_COUNTERS.req(&ctx);
        mc_common::logger::scoped_global_logger(&rpc_logger(&ctx, &self.logger), |logger| {
            if let Err(err) = self.authenticator.authenticate_rpc(&ctx) {
                return send_result(ctx, sink, err.into(), &logger);
            }

            // TODO: Use the prost message directly, once available
            match self.enclave.client_accept(request.into()) {
                Ok((response, _session_id)) => {
                    send_result(ctx, sink, Ok(response.into()), &logger);
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
                        Err(rpc_permissions_error(
                            "client_auth",
                            "Permission denied",
                            &logger,
                        )),
                        &logger,
                    );
                }
            }
        });
    }
}
